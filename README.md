# Quick and Dirty MCP Scanner

A small Python script to discover likely [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) servers exposed over localhost or `host.docker.internal`.

It is intentionally pragmatic and noisy: the goal is fast local discovery, not perfect fingerprinting.

## What it does

- Finds listening TCP ports on the local machine using `ss`, `netstat`, and `lsof`
- Optionally brute-force scans all TCP ports
- Supports a Docker/container mode that targets `host.docker.internal`
- Probes likely MCP HTTP endpoints such as `/mcp`, `/`, `/sse`, `/messages`, and `/message`
- Tries modern MCP over Streamable HTTP by sending an `initialize` request
- Tries legacy HTTP + SSE MCP by opening an SSE stream and looking for a legacy `endpoint` event
- Extracts `serverInfo` when available, including servers that return a bare initialize result object
- Outputs human-readable text, JSON, or JSONL

## What it does **not** do

- It does **not** detect stdio-only MCP servers
- It does **not** perform authentication
- It does **not** guarantee zero false positives
- It does **not** try to enumerate all tools/resources/prompts after discovery

This scanner is for reconnaissance, inventory enrichment, and quick local discovery.

## Why this exists

MCP servers are often easy to miss during local testing because they may be hidden behind arbitrary ports and paths. If you are building inventory or "smells like AI" style detection, a rough network-side detector is useful for:

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

### Override the target host

```bash
python3 mcp_scanner.py --host 127.0.0.1 --ports 3000-9000
```

### Change candidate paths

```bash
python3 mcp_scanner.py --paths /mcp,/sse,/
```

### Machine-readable output

```bash
python3 mcp_scanner.py --json
python3 mcp_scanner.py --jsonl
```

## Options

```text
--docker             Scan host.docker.internal instead of localhost
--host HOST          Override the target host
--ports SPEC         Explicit ports or ranges, for example 3000,6274,8000-8010
--all-ports          Scan all ports 1-65535
--paths PATHS        Comma-separated candidate HTTP paths to probe
--connect-timeout N  TCP connect timeout in seconds
--http-timeout N     HTTP probe timeout in seconds
--workers N          Number of worker threads
--json               Output one JSON document
--jsonl              Output newline-delimited JSON
```

## Example text output

```text
[*] Host: 127.0.0.1
[*] Candidate ports considered: 42
[*] Reachable TCP ports: 5

[97] http://127.0.0.1:6274/mcp | mcp-streamable-http | high | server=desktop-commander:0.2.37
     server_info.name=desktop-commander
     server_info.version=0.2.37
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

## JSONL output

Use `--jsonl` when you want to stream results into `jq`, SIEM pipelines, or inventory tooling.

```bash
python3 mcp_scanner.py --jsonl
```

Example:

```json
{"type":"summary","host":"127.0.0.1","candidate_ports":42,"reachable_tcp_ports":5,"findings_count":1}
{"type":"finding","host":"127.0.0.1","port":6274,"scheme":"http","path":"/mcp","kind":"mcp-streamable-http","confidence":"high","score":97,"status":200,"evidence":["initialize returned JSON-RPC result","server returned Mcp-Session-Id"],"server_info":{"name":"desktop-commander","version":"0.2.37"},"protocol_version":"2025-03-26","session_id":"abc123"}
```

## Detection logic

The scanner currently uses a small set of heuristics:

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

### 3. Bare initialize result support

Some implementations return the inner initialize result directly instead of a full JSON-RPC envelope. This scanner accepts both:

- standard JSON-RPC initialize responses
- bare result objects containing fields such as `serverInfo`, `capabilities`, or `protocolVersion`

## Extracted fields

When available, the scanner captures:

- `server_info.name`
- `server_info.version`
- `protocol_version`
- `session_id`
- evidence strings explaining why a port was classified as MCP-like

This makes it suitable for feeding into inventory or enrichment pipelines.

## Examples for pipelines

### Filter only actual findings from JSONL

```bash
python3 mcp_scanner.py --jsonl | jq 'select(.type == "finding")'
```

### Extract a compact fingerprint

```bash
python3 mcp_scanner.py --jsonl \
  | jq 'select(.type == "finding") | {endpoint:(.scheme + "://" + .host + ":" + (.port|tostring) + .path), kind, name:.server_info.name, version:.server_info.version}'
```

### Scan from a container against the host

```bash
python3 mcp_scanner.py --docker --jsonl
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
python3 mcp_scanner.py --all-ports --connect-timeout 1.0 --http-timeout 2.0 --workers 64
```

## Caveats

- Some services may look MCP-ish without actually being MCP
- Some real MCP servers may require auth, custom paths, or longer timeouts
- HTTPS probing skips certificate validation by design because the goal is discovery, not trust validation
- `host.docker.internal` depends on your runtime/environment resolving that name
- The scanner currently focuses on TCP/HTTP(S) exposure only

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
- CSV output
- endpoint fingerprint-only mode
- banner grabbing for non-MCP services
- richer path discovery
- authentication-aware fingerprinting

## License

MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limited to the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

You are free to redistribute, share, and use this software as long as you include the license and attribution.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
