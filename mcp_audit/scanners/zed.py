"""
Zed Editor MCP configuration scanner
"""

import json
import platform
from pathlib import Path

from mcp_audit.models import ScanResult


def get_config_paths() -> list[Path]:
    """Get possible Zed config paths for current OS"""
    paths = []
    home = Path.home()
    system = platform.system()

    if system == "Darwin":  # macOS
        # Zed stores settings in ~/.config/zed/
        paths.append(home / ".config" / "zed" / "settings.json")
        paths.append(home / "Library" / "Application Support" / "Zed" / "settings.json")
    elif system == "Linux":
        paths.append(home / ".config" / "zed" / "settings.json")
    elif system == "Windows":
        import os
        appdata = os.environ.get("APPDATA", "")
        if appdata:
            paths.append(Path(appdata) / "Zed" / "settings.json")

    return paths


def scan() -> list[ScanResult]:
    """Scan for Zed Editor MCP configurations"""
    results = []

    for config_path in get_config_paths():
        if not config_path.exists():
            continue

        try:
            config = json.loads(config_path.read_text())
        except (json.JSONDecodeError, IOError):
            continue

        # Zed uses "language_models" or "assistant" sections
        # MCP support may be under various keys
        mcp_servers = config.get("mcpServers", {})
        if not mcp_servers:
            mcp_servers = config.get("mcp_servers", {})
        if not mcp_servers:
            # Check assistant settings
            assistant = config.get("assistant", {})
            mcp_servers = assistant.get("mcpServers", {})

        for name, server_config in mcp_servers.items():
            result = ScanResult.from_dict(
                {"name": name, **server_config},
                found_in="Zed",
                config_path=str(config_path),
            )
            results.append(result)

    return results
