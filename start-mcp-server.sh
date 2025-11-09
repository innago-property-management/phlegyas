#!/bin/bash
# Start the MCP permission approver server with venv activated

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Activate the virtual environment
source "$SCRIPT_DIR/venv/bin/activate"

# Run the MCP server
exec python "$SCRIPT_DIR/src/approver_mcp.py"
