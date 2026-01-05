"""
Windsurf IDE MCP configuration scanner
"""

import json
import platform
from pathlib import Path
from typing import Optional

from mcp_audit.models import ScanResult


def get_config_paths() -> list[Path]:
    """Get possible Windsurf config paths for current OS"""
    paths = []
    home = Path.home()
    system = platform.system()

    if system == "Darwin":  # macOS
        # Windsurf uses Codeium's config structure
        paths.append(home / "Library" / "Application Support" / "Windsurf" / "mcp.json")
        paths.append(home / "Library" / "Application Support" / "Windsurf" / "User" / "settings.json")
        paths.append(home / ".windsurf" / "mcp.json")
    elif system == "Windows":
        import os
        appdata = os.environ.get("APPDATA", "")
        if appdata:
            paths.append(Path(appdata) / "Windsurf" / "mcp.json")
            paths.append(Path(appdata) / "Windsurf" / "User" / "settings.json")
        localappdata = os.environ.get("LOCALAPPDATA", "")
        if localappdata:
            paths.append(Path(localappdata) / "Windsurf" / "mcp.json")
    elif system == "Linux":
        paths.append(home / ".config" / "Windsurf" / "mcp.json")
        paths.append(home / ".config" / "Windsurf" / "User" / "settings.json")
        paths.append(home / ".windsurf" / "mcp.json")

    return paths


def scan() -> list[ScanResult]:
    """Scan for Windsurf MCP configurations"""
    results = []

    for config_path in get_config_paths():
        if not config_path.exists():
            continue

        try:
            config = json.loads(config_path.read_text())
        except (json.JSONDecodeError, IOError):
            continue

        # Check for mcpServers in settings.json format
        mcp_servers = config.get("mcpServers", {})
        if not mcp_servers:
            # Check for windsurf-specific settings
            mcp_servers = config.get("windsurf.mcpServers", {})
        if not mcp_servers:
            # Check for servers key
            mcp_servers = config.get("servers", {})

        for name, server_config in mcp_servers.items():
            result = ScanResult.from_dict(
                {"name": name, **server_config},
                found_in="Windsurf",
                config_path=str(config_path),
            )
            results.append(result)

    return results
