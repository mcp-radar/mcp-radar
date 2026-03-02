# Quick and Dirty MCP Scanner

A small Python script to discover likely [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) servers exposed over TCP on localhost, remote hosts, or `host.docker.internal`.

It is intentionally pragmatic and a bit noisy. The goal is fast discovery and enrichment, not perfect protocol validation.

## What it does

- Finds listening TCP ports on the local machine using `ss`, `netstat`, and `lsof`
- Optionally brute-force scans all TCP ports
- Supports a Docker/container mode that targets `host.docker.internal`
- Probes likely MCP HTTP endpoints such as `/mcp`, `/`, `/sse`, `/messages`, and `/message`
- Tries modern MCP over Streamable HTTP by sending an `initialize` request
- Tries legacy HTTP + SSE MCP by opening an SSE stream and looking for a legacy `endpoint` event
- Extracts `serverInfo` when available
- Outputs either human-readable text or JSON

## What it does not do

- It does **not** detect stdio-only MCP servers
- It does **not** perform authentication
- It does **not** guarantee zero false positives
- It does **not** enumerate all tools/resources/prompts after discovery
- It does **not** currently support custom virtual-host overrides such as a separate `Host` header while connecting to an IP

This scanner is meant for reconnaissance, inventory enrichment, lab discovery, and quick MCP validation.

## Why this exists

MCP servers are easy to miss during local testing because they may hide behind arbitrary ports and paths. If you are building inventory or "smells like AI" style detection, a rough network-side detector is useful for:

- developer workstation discovery
- local lab enumeration
- container-to-host scanning
- quick enrichment of asset inventories
- identifying likely MCP endpoints before deeper inspection

## Requirements

- Python 3.9+
- No third-party Python dependencies
- Optional local port discovery helpers:
  - `ss`
  - `netstat`
  - `lsof`

If those tools are unavailable, the scanner falls back to a full TCP port scan.

## Installation

Clone the repo or download the script:

```bash
chmod +x mcp_scanner.py
```

Then run it with Python:

```bash
python3 mcp_scanner.py
```

## Basic usage

### Scan discovered local listening ports

```bash
python3 mcp_scanner.py
```

### Scan all local TCP ports

```bash
python3 mcp_scanner.py --all-ports
```

### Scan the host from inside a container

```bash
python3 mcp_scanner.py --docker
```

### Limit the scan to a range or list of ports

```bash
python3 mcp_scanner.py --ports 6274,8000-8100
```

### Scan a remote hostname

```bash
python3 mcp_scanner.py --host mcp.hacktolearn.org --ports 443,80
```

### Change candidate paths

```bash
python3 mcp_scanner.py --paths /mcp,/sse,/
```

### Machine-readable output

```bash
python3 mcp_scanner.py --json
```

## Options

```text
--docker             Scan host.docker.internal instead of localhost
--host HOST          Override the target host
--ports SPEC         Explicit ports or ranges, for example 3000,6274,8000-8010
--all-ports          Scan all ports 1-65535 instead of discovered listening ports
--paths PATHS        Comma-separated candidate HTTP paths to probe
--connect-timeout N  TCP connect timeout in seconds
--http-timeout N     HTTP probe timeout in seconds
--workers N          Number of worker threads
--json               Output one JSON document
```

## HTTPS and hostnames

The scanner tries **both** `http` and `https` for each reachable port.

That means this works fine for ordinary hostname-based TLS setups:

```bash
python3 mcp_scanner.py --host mcp.hacktolearn.org --ports 443 --paths /mcp
```

Because the script connects to the hostname directly, Python's HTTPS client will normally send the correct TLS SNI for that hostname.

If you are scanning a remote host, you should almost always provide `--ports` or `--all-ports`. Otherwise, in non-Docker mode, the scanner defaults to locally discovered listening ports.

## Timeout note

The default HTTP timeout is intentionally small so localhost scans stay quick:

- `--connect-timeout` defaults to `0.35`
- `--http-timeout` defaults to `1.2`

That is often fine for local dev servers, but it can be too aggressive for:

- reverse proxies
- TLS handshakes on slower systems
- remote hosts over the internet
- MCP servers that initialize slowly
- SSE endpoints that take a moment before emitting data

If you are missing servers that you know exist, increase the HTTP timeout first.

Examples:

```bash
python3 mcp_scanner.py --host mcp.hacktolearn.org --ports 443 --http-timeout 3.0
python3 mcp_scanner.py --docker --http-timeout 4.0
python3 mcp_scanner.py --all-ports --connect-timeout 1.0 --http-timeout 3.0 --workers 64
```

A good rule of thumb:

- **localhost**: keep the defaults or use `--http-timeout 2.0`
- **remote HTTPS**: try `--http-timeout 3.0` to `5.0`
- **slow lab environments / proxies**: try `--http-timeout 5.0+`

## Example text output

```text
[*] Host: 127.0.0.1
[*] Candidate ports considered: 42
[*] Reachable TCP ports: 5

[97] http://127.0.0.1:6274/mcp | mcp-streamable-http | high | server=desktop-commander:0.2.37
     protocol=2025-03-26
     session_id=abc123
     - initialize returned JSON-RPC result
     - server returned Mcp-Session-Id
     - initialized notification accepted
     - follow-up JSON-RPC exchange worked
```

## What the score means

The bracketed number is a heuristic confidence score.

Examples:

- `95+` = strong MCP signal
- `90s` = very likely MCP
- `80s` = plausible legacy MCP over SSE
- `20-30` = weak MCP-ish signal or generic SSE/HTTP behavior

This score is meant for ranking and triage, not as a formal guarantee.

## JSON output

Use `--json` for a single parseable JSON document:

```bash
python3 mcp_scanner.py --json
```

Example:

```json
{
  "host": "127.0.0.1",
  "candidate_ports": 42,
  "reachable_tcp_ports": 5,
  "findings": [
    {
      "host": "127.0.0.1",
      "port": 6274,
      "scheme": "http",
      "path": "/mcp",
      "kind": "mcp-streamable-http",
      "confidence": "high",
      "score": 97,
      "status": 200,
      "evidence": [
        "initialize returned JSON-RPC result",
        "server returned Mcp-Session-Id"
      ],
      "server_info": {
        "name": "desktop-commander",
        "version": "0.2.37"
      },
      "protocol_version": "2025-03-26",
      "session_id": "abc123"
    }
  ]
}
```

## Detection logic

The scanner uses a small set of practical heuristics.

### 1. Modern MCP over HTTP

For each candidate port and path, it tries:

- `POST` with JSON-RPC `initialize`
- optional `notifications/initialized`
- optional follow-up `ping`

If the endpoint behaves like MCP, the finding is marked as `mcp-streamable-http`.

### 2. Legacy HTTP + SSE MCP

It also tries:

- `GET` with `Accept: text/event-stream`
- parses SSE events
- looks for a legacy `endpoint` event
- optionally sends `initialize` to the returned message endpoint

If this succeeds, the finding is marked as `mcp-legacy-sse` or `possible-mcp-legacy-sse`.

### 3. Server info extraction

When available, the scanner captures:

- `server_info.name`
- `server_info.version`
- `protocol_version`
- `session_id`
- evidence strings explaining why a port was classified as MCP-like

This makes it suitable for feeding into inventory or enrichment pipelines.

## Examples for pipelines

### Print JSON into jq

```bash
python3 mcp_scanner.py --json | jq '.findings[] | {port, kind, server_info}'
```

### Scan from a container against the host

```bash
python3 mcp_scanner.py --docker --json
```

### Remote HTTPS probe with a longer timeout

```bash
python3 mcp_scanner.py --host mcp.hacktolearn.org --ports 443 --paths /mcp --http-timeout 4.0 --json
```

## Performance notes

- Full scans over `1-65535` can be noisy and slow depending on timeouts and worker count
- The defaults are tuned to be reasonably quick on localhost
- You can trade speed for reliability by adjusting:
  - `--connect-timeout`
  - `--http-timeout`
  - `--workers`

Examples:

```bash
python3 mcp_scanner.py --all-ports --connect-timeout 0.2 --http-timeout 0.8 --workers 256
python3 mcp_scanner.py --all-ports --connect-timeout 1.0 --http-timeout 3.0 --workers 64
```

## Caveats

- Some services may look MCP-ish without actually being MCP
- Some real MCP servers may require auth, custom paths, or longer timeouts
- HTTPS probing skips certificate validation by design because the goal is discovery, not trust validation
- `host.docker.internal` depends on your runtime/environment resolving that name
- The scanner focuses on TCP/HTTP(S) exposure only

## Exit codes

- `0` on success
- `2` if the target host cannot be resolved

## Security / responsible use

This tool is intended for:

- your own workstation
- your lab
- your containers
- systems you are authorized to inspect

Do not use it against systems you do not own or administer.

## Roadmap ideas

Some useful next steps if you want to extend it:

- auth headers / bearer token support
- tool/resource/prompt enumeration after initialization
- JSONL output
- CSV output
- endpoint fingerprint-only mode
- banner grabbing for non-MCP services
- richer path discovery
- authentication-aware fingerprinting
- explicit virtual-host overrides for more advanced reverse-proxy cases

## License

Add the license of your choice, for example MIT.
