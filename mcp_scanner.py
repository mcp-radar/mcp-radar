#!/usr/bin/env python3
"""
Quick and dirty MCP scanner.

What it does
- Local mode:
  - Uses ss/netstat/lsof to find listening TCP ports on the current machine.
  - Probes those ports for likely MCP HTTP endpoints.
- Docker mode:
  - Scans host.docker.internal because netstat inside a container only shows the container's own sockets.
  - By default scans all TCP ports 1-65535 on the target host.
- Detection:
  - Tries modern Streamable HTTP MCP by POSTing initialize to likely endpoints.
  - Tries legacy HTTP+SSE MCP by GETting SSE endpoints and looking for an endpoint event.
  - Optionally does one follow-up request after initialize to confirm the session works.

Notes
- This only finds MCP servers exposed over TCP/HTTP(S).
- It will not find stdio-only MCP servers because those are subprocess/stdin/stdout based, not listening sockets.
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import http.client
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import time
from dataclasses import dataclass, asdict
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

PROTOCOL_VERSION = "2025-03-26"
DEFAULT_PATHS = ["/mcp", "/", "/sse", "/messages", "/message"]
DEFAULT_CONNECT_TIMEOUT = 0.35
DEFAULT_HTTP_TIMEOUT = 1.2
DEFAULT_WORKERS = 128
READ_LIMIT = 64 * 1024


@dataclass
class Finding:
    host: str
    port: int
    scheme: str
    path: str
    kind: str
    confidence: str
    score: int
    status: Optional[int]
    evidence: List[str]
    server_info: Optional[dict] = None
    protocol_version: Optional[str] = None
    session_id: Optional[str] = None

    def short(self) -> str:
        bits = [f"{self.scheme}://{self.host}:{self.port}{self.path}", self.kind, self.confidence]
        if self.server_info:
            name = self.server_info.get("name")
            version = self.server_info.get("version")
            if name or version:
                bits.append(f"server={name or '?'}:{version or '?'}")
        return " | ".join(bits)


@dataclass
class ProbeResponse:
    scheme: str
    host: str
    port: int
    path: str
    method: str
    status: Optional[int]
    headers: Dict[str, str]
    body: bytes
    error: Optional[str] = None

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "")

    @property
    def session_id(self) -> Optional[str]:
        return self.headers.get("mcp-session-id")


# -----------------------------
# Port discovery
# -----------------------------

def run_cmd(cmd: Sequence[str]) -> Tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", "not found"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"


def extract_port_from_endpoint(endpoint: str) -> Optional[int]:
    endpoint = endpoint.strip()
    if not endpoint:
        return None

    # [::]:8000, 127.0.0.1:8000, *:8000
    m = re.search(r":(\d+)(?:\s|$)", endpoint)
    if m:
        port = int(m.group(1))
        if 1 <= port <= 65535:
            return port

    # lsof NAME column sometimes looks like TCP *:8000 (LISTEN)
    m = re.search(r"\*:(\d+)", endpoint)
    if m:
        port = int(m.group(1))
        if 1 <= port <= 65535:
            return port

    return None


def discover_ports_via_ss() -> Set[int]:
    ports: Set[int] = set()
    rc, out, _ = run_cmd(["ss", "-ltnH"])
    if rc != 0:
        return ports
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        local = parts[3]
        port = extract_port_from_endpoint(local)
        if port:
            ports.add(port)
    return ports


def discover_ports_via_netstat() -> Set[int]:
    ports: Set[int] = set()
    rc, out, _ = run_cmd(["netstat", "-ltn"])
    if rc != 0:
        return ports
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("tcp"):
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        local = parts[3]
        port = extract_port_from_endpoint(local)
        if port:
            ports.add(port)
    return ports


def discover_ports_via_lsof() -> Set[int]:
    ports: Set[int] = set()
    rc, out, _ = run_cmd(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"])
    if rc != 0:
        return ports
    for line in out.splitlines()[1:]:
        port = extract_port_from_endpoint(line)
        if port:
            ports.add(port)
    return ports


def discover_local_listening_ports() -> List[int]:
    ports: Set[int] = set()
    ports |= discover_ports_via_ss()
    ports |= discover_ports_via_netstat()
    ports |= discover_ports_via_lsof()
    return sorted(ports)


# -----------------------------
# Port list helpers
# -----------------------------

def expand_ports(spec: str) -> List[int]:
    ports: Set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            left, right = chunk.split("-", 1)
            start, end = int(left), int(right)
            if start > end:
                start, end = end, start
            for p in range(start, end + 1):
                if 1 <= p <= 65535:
                    ports.add(p)
        else:
            p = int(chunk)
            if 1 <= p <= 65535:
                ports.add(p)
    return sorted(ports)


# -----------------------------
# TCP connect scan
# -----------------------------

def can_connect(host: str, port: int, timeout: float) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        return s.connect_ex((host, port)) == 0
    except socket.gaierror:
        return False
    except OSError:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass


def connect_scan(host: str, ports: Sequence[int], timeout: float, workers: int) -> List[int]:
    open_ports: List[int] = []
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        fut_map = {ex.submit(can_connect, host, p, timeout): p for p in ports}
        for fut in cf.as_completed(fut_map):
            p = fut_map[fut]
            try:
                if fut.result():
                    open_ports.append(p)
            except Exception:
                pass
    return sorted(open_ports)


# -----------------------------
# HTTP/S helpers
# -----------------------------

def make_conn(scheme: str, host: str, port: int, timeout: float):
    if scheme == "https":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
    return http.client.HTTPConnection(host, port, timeout=timeout)


def read_streaming_body(resp: http.client.HTTPResponse, max_bytes: int, max_seconds: float) -> bytes:
    deadline = time.time() + max_seconds
    chunks: List[bytes] = []
    total = 0
    while time.time() < deadline and total < max_bytes:
        line = resp.fp.readline(4096)
        if not line:
            break
        chunks.append(line)
        total += len(line)
        # Stop once we have seen at least one event boundary.
        if line in (b"\n", b"\r\n") and total > 0:
            break
    return b"".join(chunks)


def request(
    scheme: str,
    host: str,
    port: int,
    method: str,
    path: str,
    body: Optional[bytes],
    headers: Dict[str, str],
    timeout: float,
) -> ProbeResponse:
    conn = None
    try:
        conn = make_conn(scheme, host, port, timeout)
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        headers_out = {k.lower(): v for k, v in resp.getheaders()}
        ctype = headers_out.get("content-type", "")
        if "text/event-stream" in ctype.lower():
            data = read_streaming_body(resp, READ_LIMIT, timeout)
        else:
            data = resp.read(READ_LIMIT)
        return ProbeResponse(
            scheme=scheme,
            host=host,
            port=port,
            path=path,
            method=method,
            status=resp.status,
            headers=headers_out,
            body=data,
            error=None,
        )
    except Exception as e:
        return ProbeResponse(
            scheme=scheme,
            host=host,
            port=port,
            path=path,
            method=method,
            status=None,
            headers={},
            body=b"",
            error=f"{type(e).__name__}: {e}",
        )
    finally:
        try:
            if conn:
                conn.close()
        except Exception:
            pass


# -----------------------------
# Response parsing
# -----------------------------

def safe_decode(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def parse_json_body(data: bytes):
    try:
        return json.loads(safe_decode(data).strip())
    except Exception:
        return None


def parse_sse_events(data: bytes) -> List[dict]:
    text = safe_decode(data)
    events: List[dict] = []
    event_name = "message"
    data_lines: List[str] = []

    def flush():
        nonlocal event_name, data_lines
        if data_lines or event_name != "message":
            events.append({"event": event_name, "data": "\n".join(data_lines).strip()})
        event_name = "message"
        data_lines = []

    for raw in text.splitlines():
        line = raw.rstrip("\r")
        if not line:
            flush()
            continue
        if line.startswith(":"):
            continue
        if ":" in line:
            field, value = line.split(":", 1)
            value = value.lstrip(" ")
        else:
            field, value = line, ""
        if field == "event":
            event_name = value
        elif field == "data":
            data_lines.append(value)
    flush()
    return events


def is_bare_initialize_result(obj: dict) -> bool:
    return bool(
        isinstance(obj, dict)
        and (obj.get("serverInfo") or obj.get("capabilities") is not None or obj.get("protocolVersion"))
        and obj.get("jsonrpc") != "2.0"
    )


def extract_initialize_result(resp: ProbeResponse) -> Tuple[bool, Optional[dict], Optional[str], List[str]]:
    evidence: List[str] = []
    ctype = (resp.content_type or "").lower()

    if "application/json" in ctype or resp.body.startswith((b"{", b"[")):
        obj = parse_json_body(resp.body)
        if isinstance(obj, dict):
            if obj.get("jsonrpc") == "2.0" and isinstance(obj.get("result"), dict):
                result = obj["result"]
                server_info = result.get("serverInfo")
                protocol_version = result.get("protocolVersion")
                if server_info or result.get("capabilities") is not None or protocol_version:
                    evidence.append("initialize returned JSON-RPC result")
                    return True, result, resp.session_id, evidence
            if is_bare_initialize_result(obj):
                evidence.append("initialize returned bare result object")
                return True, obj, resp.session_id, evidence
            if obj.get("error"):
                evidence.append(f"JSON-RPC error: {obj['error']}")
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, dict) and item.get("jsonrpc") == "2.0" and isinstance(item.get("result"), dict):
                    evidence.append("initialize returned JSON-RPC batch result")
                    return True, item["result"], resp.session_id, evidence

    if "text/event-stream" in ctype:
        events = parse_sse_events(resp.body)
        if events:
            evidence.append("POST initialize upgraded to SSE stream")
        for ev in events:
            if ev["data"]:
                maybe = parse_json_body(ev["data"].encode())
                if isinstance(maybe, dict) and maybe.get("jsonrpc") == "2.0" and isinstance(maybe.get("result"), dict):
                    evidence.append(f"SSE event carried initialize result ({ev['event']})")
                    return True, maybe["result"], resp.session_id, evidence
                if isinstance(maybe, dict) and is_bare_initialize_result(maybe):
                    evidence.append(f"SSE event carried bare initialize result ({ev['event']})")
                    return True, maybe, resp.session_id, evidence

    return False, None, None, evidence


def extract_legacy_endpoint(resp: ProbeResponse) -> Tuple[Optional[str], List[str]]:
    evidence: List[str] = []
    ctype = (resp.content_type or "").lower()
    if "text/event-stream" not in ctype:
        return None, evidence

    events = parse_sse_events(resp.body)
    if events:
        evidence.append("GET returned text/event-stream")
    for ev in events:
        if ev["event"] == "endpoint" and ev["data"]:
            evidence.append("legacy SSE endpoint event observed")
            return ev["data"].strip(), evidence
    return None, evidence


def looks_mcpish_text(resp: ProbeResponse) -> List[str]:
    evidence: List[str] = []
    text = safe_decode(resp.body).lower()
    ctype = (resp.content_type or "").lower()
    if "model context protocol" in text:
        evidence.append("body mentions model context protocol")
    if '"method":"initialize"' in text or '"method": "initialize"' in text:
        evidence.append("body echoes initialize")
    if '"serverinfo"' in text:
        evidence.append("body mentions serverInfo")
    if '"protocolversion"' in text:
        evidence.append("body mentions protocolVersion")
    if "mcp" in text and "jsonrpc" in text:
        evidence.append("body mentions mcp and jsonrpc")
    if "mcp-session-id" in ctype or "mcp-session-id" in " ".join(resp.headers.keys()).lower():
        evidence.append("response references Mcp-Session-Id")
    return evidence


# -----------------------------
# MCP probes
# -----------------------------

def make_initialize_request() -> bytes:
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "quick-dirty-mcp-scanner", "version": "0.1"},
            },
        }
    ).encode("utf-8")


def make_initialized_notification() -> bytes:
    return json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}).encode("utf-8")


def make_ping_request() -> bytes:
    return json.dumps({"jsonrpc": "2.0", "id": 2, "method": "ping"}).encode("utf-8")


def probe_streamable_http(host: str, port: int, scheme: str, path: str, timeout: float) -> Optional[Finding]:
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "User-Agent": "quick-dirty-mcp-scanner/0.1",
        "Origin": "http://localhost",
    }
    init_resp = request(scheme, host, port, "POST", path, make_initialize_request(), headers, timeout)
    ok, result, session_id, evidence = extract_initialize_result(init_resp)

    if ok and result is not None:
        score = 95
        followup_ok = False
        follow_headers = headers.copy()
        if session_id:
            follow_headers["Mcp-Session-Id"] = session_id
            evidence.append("server returned Mcp-Session-Id")
            score += 2

        # Best-effort follow up. Some servers accept notifications with 202 and some support ping.
        notif_resp = request(scheme, host, port, "POST", path, make_initialized_notification(), follow_headers, timeout)
        if notif_resp.status in (200, 202, 204):
            evidence.append("initialized notification accepted")
            followup_ok = True
            score += 1

        ping_resp = request(scheme, host, port, "POST", path, make_ping_request(), follow_headers, timeout)
        ping_obj = parse_json_body(ping_resp.body)
        if ping_resp.status and isinstance(ping_obj, dict) and ping_obj.get("jsonrpc") == "2.0" and (
            "result" in ping_obj or "error" in ping_obj
        ):
            evidence.append("follow-up JSON-RPC exchange worked")
            followup_ok = True
            score += 1

        confidence = "high" if followup_ok else "high"
        return Finding(
            host=host,
            port=port,
            scheme=scheme,
            path=path,
            kind="mcp-streamable-http",
            confidence=confidence,
            score=min(score, 99),
            status=init_resp.status,
            evidence=evidence,
            server_info=result.get("serverInfo") if isinstance(result, dict) else None,
            protocol_version=result.get("protocolVersion") if isinstance(result, dict) else None,
            session_id=session_id,
        )

    text_hits = looks_mcpish_text(init_resp)
    if text_hits:
        return Finding(
            host=host,
            port=port,
            scheme=scheme,
            path=path,
            kind="possible-mcp-http",
            confidence="low",
            score=30,
            status=init_resp.status,
            evidence=evidence + text_hits,
            server_info=None,
            protocol_version=None,
            session_id=init_resp.session_id,
        )

    return None


def probe_legacy_sse(host: str, port: int, scheme: str, path: str, timeout: float) -> Optional[Finding]:
    headers = {
        "Accept": "text/event-stream",
        "User-Agent": "quick-dirty-mcp-scanner/0.1",
        "Origin": "http://localhost",
    }
    resp = request(scheme, host, port, "GET", path, None, headers, timeout)
    endpoint, evidence = extract_legacy_endpoint(resp)
    if endpoint:
        score = 85
        post_status = None
        # Best-effort initialize on the legacy message endpoint if the endpoint looks like a path.
        message_path = None
        if endpoint.startswith("http://") or endpoint.startswith("https://"):
            m = re.match(r"https?://[^/]+(?P<path>/.*)", endpoint)
            if m:
                message_path = m.group("path")
        elif endpoint.startswith("/"):
            message_path = endpoint

        if message_path:
            headers2 = {
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
                "User-Agent": "quick-dirty-mcp-scanner/0.1",
                "Origin": "http://localhost",
            }
            post_resp = request(scheme, host, port, "POST", message_path, make_initialize_request(), headers2, timeout)
            post_status = post_resp.status
            ok, result, session_id, ev2 = extract_initialize_result(post_resp)
            evidence.extend(ev2)
            if ok:
                evidence.append("initialize worked on legacy message endpoint")
                score = 92
                return Finding(
                    host=host,
                    port=port,
                    scheme=scheme,
                    path=path,
                    kind="mcp-legacy-sse",
                    confidence="high",
                    score=score,
                    status=post_status,
                    evidence=evidence + [f"message-endpoint={message_path}"],
                    server_info=result.get("serverInfo") if isinstance(result, dict) else None,
                    protocol_version=result.get("protocolVersion") if isinstance(result, dict) else None,
                    session_id=session_id,
                )
            evidence.append(f"message-endpoint={message_path}")

        return Finding(
            host=host,
            port=port,
            scheme=scheme,
            path=path,
            kind="possible-mcp-legacy-sse",
            confidence="medium",
            score=score,
            status=post_status or resp.status,
            evidence=evidence,
            server_info=None,
            protocol_version=None,
            session_id=None,
        )

    if "text/event-stream" in (resp.content_type or "").lower():
        return Finding(
            host=host,
            port=port,
            scheme=scheme,
            path=path,
            kind="possible-sse-service",
            confidence="low",
            score=20,
            status=resp.status,
            evidence=["GET returned SSE but no legacy endpoint event was captured"],
            server_info=None,
            protocol_version=None,
            session_id=None,
        )

    return None


def scan_one_endpoint(host: str, port: int, scheme: str, path: str, timeout: float) -> Optional[Finding]:
    finding = probe_streamable_http(host, port, scheme, path, timeout)
    if finding and finding.score >= 90:
        return finding
    legacy = probe_legacy_sse(host, port, scheme, path, timeout)
    if legacy and (not finding or legacy.score > finding.score):
        return legacy
    return finding or legacy


def scan_port(host: str, port: int, paths: Sequence[str], timeout: float) -> Optional[Finding]:
    best: Optional[Finding] = None
    for scheme in ("http", "https"):
        for path in paths:
            finding = scan_one_endpoint(host, port, scheme, path, timeout)
            if finding and (best is None or finding.score > best.score):
                best = finding
            if best and best.score >= 95:
                return best
    return best


# -----------------------------
# Output
# -----------------------------

def print_text(findings: List[Finding], scanned_host: str, candidate_ports: int, open_ports: int) -> None:
    print(f"[*] Host: {scanned_host}")
    print(f"[*] Candidate ports considered: {candidate_ports}")
    print(f"[*] Reachable TCP ports: {open_ports}")
    print()

    if not findings:
        print("No likely MCP-over-HTTP endpoints found.")
        return

    findings = sorted(findings, key=lambda x: (-x.score, x.port, x.scheme, x.path))
    for f in findings:
        print(f"[{f.score:02d}] {f.short()}")
        if f.server_info:
            name = f.server_info.get("name")
            version = f.server_info.get("version")
            if name or version:
                print(f"     server_info.name={name or '?'}")
                print(f"     server_info.version={version or '?'}")
        if f.protocol_version:
            print(f"     protocol={f.protocol_version}")
        if f.session_id:
            print(f"     session_id={f.session_id}")
        for ev in f.evidence:
            print(f"     - {ev}")
        print()


def print_json(findings: List[Finding], scanned_host: str, candidate_ports: int, open_ports: int) -> None:
    obj = {
        "host": scanned_host,
        "candidate_ports": candidate_ports,
        "reachable_tcp_ports": open_ports,
        "findings": [asdict(f) for f in sorted(findings, key=lambda x: (-x.score, x.port))],
    }
    print(json.dumps(obj, indent=2))


def print_jsonl(findings: List[Finding], scanned_host: str, candidate_ports: int, open_ports: int) -> None:
    summary = {
        "type": "summary",
        "host": scanned_host,
        "candidate_ports": candidate_ports,
        "reachable_tcp_ports": open_ports,
        "findings_count": len(findings),
    }
    print(json.dumps(summary, separators=(",", ":")))
    for f in sorted(findings, key=lambda x: (-x.score, x.port)):
        row = {"type": "finding", **asdict(f)}
        print(json.dumps(row, separators=(",", ":")))


# -----------------------------
# Main
# -----------------------------

def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Quick and dirty MCP scanner")
    p.add_argument("--docker", action="store_true", help="scan host.docker.internal instead of localhost")
    p.add_argument("--host", help="override target host")
    p.add_argument(
        "--ports",
        help="explicit ports or ranges, for example: 3000,6274,8000-8010",
    )
    p.add_argument(
        "--all-ports",
        action="store_true",
        help="scan all 1-65535 ports instead of discovered listening ports",
    )
    p.add_argument(
        "--paths",
        default=",".join(DEFAULT_PATHS),
        help="comma-separated candidate HTTP paths to probe",
    )
    p.add_argument("--connect-timeout", type=float, default=DEFAULT_CONNECT_TIMEOUT)
    p.add_argument("--http-timeout", type=float, default=DEFAULT_HTTP_TIMEOUT)
    p.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    p.add_argument("--json", action="store_true", help="output JSON")
    p.add_argument("--jsonl", action="store_true", help="output JSON Lines (NDJSON)")
    return p.parse_args(argv)


def main(argv: Sequence[str]) -> int:
    args = parse_args(argv)

    target_host = args.host or ("host.docker.internal" if args.docker else "127.0.0.1")
    paths = [x.strip() for x in args.paths.split(",") if x.strip()]

    # Decide candidate ports.
    if args.ports:
        candidates = expand_ports(args.ports)
    elif args.docker or args.all_ports:
        candidates = list(range(1, 65536))
    else:
        candidates = discover_local_listening_ports()
        if not candidates:
            print("[!] No listening ports discovered via ss/netstat/lsof. Falling back to full 1-65535 scan.", file=sys.stderr)
            candidates = list(range(1, 65536))

    # Resolve host early.
    try:
        socket.getaddrinfo(target_host, None)
    except socket.gaierror as e:
        print(f"[!] Could not resolve host '{target_host}': {e}", file=sys.stderr)
        return 2

    # TCP reachability scan.
    open_ports = connect_scan(target_host, candidates, timeout=args.connect_timeout, workers=args.workers)

    findings: List[Finding] = []
    with cf.ThreadPoolExecutor(max_workers=args.workers) as ex:
        fut_map = {
            ex.submit(scan_port, target_host, port, paths, args.http_timeout): port
            for port in open_ports
        }
        for fut in cf.as_completed(fut_map):
            try:
                res = fut.result()
                if res:
                    findings.append(res)
            except Exception:
                pass

    if args.jsonl:
        print_jsonl(findings, target_host, len(candidates), len(open_ports))
    elif args.json:
        print_json(findings, target_host, len(candidates), len(open_ports))
    else:
        print_text(findings, target_host, len(candidates), len(open_ports))

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
