#!/bin/bash
# MCP Audit Collector Script (macOS/Linux)
# 
# This script collects MCP configurations from developer machines.
# Deploy via MDM (Jamf, etc.) to gather org-wide MCP inventory.
#
# Output: JSON to stdout or file
# Usage: 
#   ./collector.sh                    # Output to stdout
#   ./collector.sh /path/to/output/   # Write to output directory
#
# The output JSON can be analyzed with: mcp-audit analyze /path/to/collected/

set -e

# Configuration
OUTPUT_DIR="${1:-}"
MACHINE_ID="${HOSTNAME:-$(hostname)}"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Initialize JSON structure
MCPS="[]"

# Function to add MCP to results
add_mcp() {
    local name="$1"
    local found_in="$2"
    local config_path="$3"
    local config="$4"
    
    # Create MCP entry
    local entry=$(cat <<EOF
{
    "name": "$name",
    "found_in": "$found_in",
    "config_path": "$config_path",
    "config": $config
}
EOF
)
    
    # Append to MCPS array
    if [ "$MCPS" = "[]" ]; then
        MCPS="[$entry]"
    else
        MCPS="${MCPS%]}, $entry]"
    fi
}

# Scan Claude Desktop
scan_claude_desktop() {
    local config_path=""
    
    if [[ "$OSTYPE" == "darwin"* ]]; then
        config_path="$HOME/Library/Application Support/Claude/claude_desktop_config.json"
    elif [[ "$OSTYPE" == "linux"* ]]; then
        config_path="$HOME/.config/Claude/claude_desktop_config.json"
    fi
    
    if [ -f "$config_path" ]; then
        # Parse mcpServers from config
        if command -v python3 &> /dev/null; then
            python3 << EOF
import json
import sys

try:
    with open("$config_path", 'r') as f:
        config = json.load(f)
    
    mcp_servers = config.get('mcpServers', {})
    for name, server_config in mcp_servers.items():
        entry = {
            "name": name,
            "found_in": "Claude Desktop",
            "config_path": "$config_path",
            "config": server_config
        }
        print(json.dumps(entry))
except Exception as e:
    sys.stderr.write(f"Error parsing Claude Desktop config: {e}\n")
EOF
        fi
    fi
}

# Scan Cursor
scan_cursor() {
    local config_paths=(
        "$HOME/.cursor/mcp.json"
    )
    
    if [[ "$OSTYPE" == "darwin"* ]]; then
        config_paths+=("$HOME/Library/Application Support/Cursor/mcp.json")
    elif [[ "$OSTYPE" == "linux"* ]]; then
        config_paths+=("$HOME/.config/Cursor/mcp.json")
    fi
    
    for config_path in "${config_paths[@]}"; do
        if [ -f "$config_path" ]; then
            if command -v python3 &> /dev/null; then
                python3 << EOF
import json
import sys

try:
    with open("$config_path", 'r') as f:
        config = json.load(f)
    
    mcp_servers = config.get('mcpServers', {})
    for name, server_config in mcp_servers.items():
        entry = {
            "name": name,
            "found_in": "Cursor",
            "config_path": "$config_path",
            "config": server_config
        }
        print(json.dumps(entry))
except Exception as e:
    sys.stderr.write(f"Error parsing Cursor config: {e}\n")
EOF
            fi
            break
        fi
    done
}

# Scan VS Code / Continue
scan_vscode() {
    local continue_config="$HOME/.continue/config.json"
    
    if [ -f "$continue_config" ]; then
        if command -v python3 &> /dev/null; then
            python3 << EOF
import json
import sys

try:
    with open("$continue_config", 'r') as f:
        config = json.load(f)
    
    experimental = config.get('experimental', {})
    mcp_servers = experimental.get('modelContextProtocolServers', [])
    
    for server in mcp_servers:
        if isinstance(server, dict):
            name = server.get('name', 'unknown')
            entry = {
                "name": name,
                "found_in": "Continue",
                "config_path": "$continue_config",
                "config": server
            }
            print(json.dumps(entry))
except Exception as e:
    sys.stderr.write(f"Error parsing Continue config: {e}\n")
EOF
        fi
    fi
}

# Main collection
collect() {
    local all_mcps="[]"
    
    # Collect from all sources using Python for JSON handling
    if command -v python3 &> /dev/null; then
        all_mcps=$(python3 << 'EOF'
import json
import os
import sys
from pathlib import Path

mcps = []

def parse_mcp_config(config_path, found_in):
    """Parse an MCP config file and extract servers"""
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
        
        mcp_servers = config.get('mcpServers', {})
        for name, server_config in mcp_servers.items():
            mcps.append({
                "name": name,
                "found_in": found_in,
                "config_path": str(config_path),
                "config": server_config
            })
    except Exception as e:
        sys.stderr.write(f"Error parsing {config_path}: {e}\n")

def parse_continue_config(config_path):
    """Parse Continue extension config"""
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
        
        experimental = config.get('experimental', {})
        mcp_servers = experimental.get('modelContextProtocolServers', [])
        
        for server in mcp_servers:
            if isinstance(server, dict):
                mcps.append({
                    "name": server.get('name', 'unknown'),
                    "found_in": "Continue",
                    "config_path": str(config_path),
                    "config": server
                })
    except Exception as e:
        sys.stderr.write(f"Error parsing {config_path}: {e}\n")

home = Path.home()
is_mac = sys.platform == 'darwin'
is_linux = sys.platform.startswith('linux')

# Claude Desktop
if is_mac:
    claude_path = home / "Library/Application Support/Claude/claude_desktop_config.json"
elif is_linux:
    claude_path = home / ".config/Claude/claude_desktop_config.json"
else:
    claude_path = None

if claude_path and claude_path.exists():
    parse_mcp_config(claude_path, "Claude Desktop")

# Cursor
cursor_paths = [home / ".cursor/mcp.json"]
if is_mac:
    cursor_paths.append(home / "Library/Application Support/Cursor/mcp.json")
elif is_linux:
    cursor_paths.append(home / ".config/Cursor/mcp.json")

for cursor_path in cursor_paths:
    if cursor_path.exists():
        parse_mcp_config(cursor_path, "Cursor")
        break

# Continue
continue_path = home / ".continue/config.json"
if continue_path.exists():
    parse_continue_config(continue_path)

print(json.dumps(mcps))
EOF
)
    else
        echo "Error: Python 3 is required for MCP collection" >&2
        exit 1
    fi
    
    # Build final output
    local output=$(cat <<EOF
{
    "machine_id": "$MACHINE_ID",
    "collected_at": "$TIMESTAMP",
    "mcps": $all_mcps
}
EOF
)
    
    # Output
    if [ -n "$OUTPUT_DIR" ]; then
        mkdir -p "$OUTPUT_DIR"
        local output_file="$OUTPUT_DIR/${MACHINE_ID}.json"
        echo "$output" > "$output_file"
        echo "Wrote results to: $output_file" >&2
    else
        echo "$output"
    fi
}

# Run collection
collect
