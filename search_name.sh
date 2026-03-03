#!/bin/bash

# Script to run mcp_scanner.py, extract the server name, and search via API
# Usage: ./search_name.sh --host HOSTNAME --ports PORTS [--http-timeout TIMEOUT] [mode] [limit] [offset]

set -e

# Show usage if no arguments
if [[ $# -lt 2 ]]; then
  echo "Usage: $0 --host HOSTNAME --ports PORTS [--http-timeout TIMEOUT] [mode] [limit] [offset]"
  echo ""
  echo "Examples:"
  echo "  $0 --host desktopcommander.hacktolearn.org --ports 443,80"
  echo "  $0 --host desktopcommander.hacktolearn.org --ports 443,80 --http-timeout 600"
  echo "  $0 --host desktopcommander.hacktolearn.org --ports 443,80 full 50 0"
  exit 1
fi

# Parse arguments for scanner and search parameters
SCANNER_ARGS=()
MODE="full"
LIMIT="50"
OFFSET="0"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host|--ports|--http-timeout)
      SCANNER_ARGS+=("$1" "$2")
      shift 2
      ;;
    *)
      # Remaining arguments are search parameters
      if [[ -z "$1" ]]; then
        shift
      else
        case "${#@}" in
          1) MODE="$1"; shift ;;
          2) MODE="$1"; LIMIT="$2"; shift 2 ;;
          3) MODE="$1"; LIMIT="$2"; OFFSET="$3"; shift 3 ;;
          *) shift ;;
        esac
      fi
      ;;
  esac
done

# Run mcp_scanner and capture JSON output
echo "Running mcp_scanner.py..."
SCANNER_OUTPUT=$(python3 mcp_scanner.py "${SCANNER_ARGS[@]}" --json)

# Extract all server names from the findings
NAMES=$(echo "$SCANNER_OUTPUT" | jq -r '.findings[].server_info.name // empty')

if [[ -z "$NAMES" ]]; then
  echo "No server names found in scanner output"
  echo "Raw output:"
  echo "$SCANNER_OUTPUT" | jq '.'
  exit 1
fi

# Search for each name
echo ""
while IFS= read -r NAME; do
  if [[ -n "$NAME" ]]; then
    # URL encode the name for the query parameter
    NAME_ENCODED=$(printf '%s\n' "$NAME" | jq -sRr @uri)

    echo "=========================================="
    echo "Searching for: $NAME"
    echo "API endpoint: http://127.0.0.1:8888/api/v1/search?q=$NAME_ENCODED&mode=$MODE&limit=$LIMIT&offset=$OFFSET"
    echo "=========================================="
    
    curl -s -X 'GET' \
      "http://127.0.0.1:8888/api/v1/search?q=$NAME_ENCODED&mode=$MODE&limit=$LIMIT&offset=$OFFSET" \
      -H 'accept: application/json' | jq '.'
    
    echo ""
  fi
done <<< "$NAMES"
