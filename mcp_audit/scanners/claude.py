"""
Claude Desktop MCP configuration scanner
"""

import json
import platform
from pathlib import Path
from typing import Optional

from mcp_audit.models import ScanResult


def get_config_path() -> Optional[Path]:
    """Get Claude Desktop config path for current OS"""
    system = platform.system()
    
    if system == "Darwin":  # macOS
        return Path.home() / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
    elif system == "Windows":
        # Windows uses %APPDATA%
        import os
        appdata = os.environ.get("APPDATA", "")
        if appdata:
            return Path(appdata) / "Claude" / "claude_desktop_config.json"
    elif system == "Linux":
        # Linux follows XDG spec
        xdg_config = Path.home() / ".config"
        return xdg_config / "Claude" / "claude_desktop_config.json"
    
    return None


def scan() -> list[ScanResult]:
    """Scan for Claude Desktop MCP configurations"""
    results = []
    
    config_path = get_config_path()
    if not config_path or not config_path.exists():
        return results
    
    try:
        config = json.loads(config_path.read_text())
    except (json.JSONDecodeError, IOError):
        return results
    
    # MCP servers are under "mcpServers" key
    mcp_servers = config.get("mcpServers", {})
    
    for name, server_config in mcp_servers.items():
        result = ScanResult.from_dict(
            {"name": name, **server_config},
            found_in="Claude Desktop",
            config_path=str(config_path),
        )
        results.append(result)
    
    return results
