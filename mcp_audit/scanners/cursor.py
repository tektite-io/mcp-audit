"""
Cursor IDE MCP configuration scanner
"""

import json
import platform
from pathlib import Path
from typing import Optional

from mcp_audit.models import ScanResult


def get_config_paths() -> list[Path]:
    """Get possible Cursor config paths for current OS"""
    paths = []
    home = Path.home()
    
    # Primary location
    paths.append(home / ".cursor" / "mcp.json")
    
    # Alternative locations
    system = platform.system()
    
    if system == "Darwin":  # macOS
        paths.append(home / "Library" / "Application Support" / "Cursor" / "mcp.json")
    elif system == "Windows":
        import os
        appdata = os.environ.get("APPDATA", "")
        if appdata:
            paths.append(Path(appdata) / "Cursor" / "mcp.json")
    elif system == "Linux":
        paths.append(home / ".config" / "Cursor" / "mcp.json")
    
    return paths


def scan() -> list[ScanResult]:
    """Scan for Cursor MCP configurations"""
    results = []
    
    for config_path in get_config_paths():
        if not config_path.exists():
            continue
        
        try:
            config = json.loads(config_path.read_text())
        except (json.JSONDecodeError, IOError):
            continue
        
        # Cursor uses same format as Claude Desktop
        mcp_servers = config.get("mcpServers", {})
        
        for name, server_config in mcp_servers.items():
            result = ScanResult.from_dict(
                {"name": name, **server_config},
                found_in="Cursor",
                config_path=str(config_path),
            )
            results.append(result)
    
    return results
