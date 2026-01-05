#!/bin/bash
# Development server for local testing
# Usage: ./scripts/dev-server.sh

PORT=${1:-8080}

echo "============================================"
echo "  MCP Audit - Local Development Server"
echo "============================================"
echo ""
echo "Starting server on http://localhost:$PORT"
echo ""
echo "Test URLs:"
echo "  - Main app:        http://localhost:$PORT/index.html"
echo "  - Getting started: http://localhost:$PORT/getting-started.html"
echo ""
echo "Press Ctrl+C to stop the server"
echo "============================================"
echo ""

cd "$(dirname "$0")/.."
python3 -m http.server $PORT
