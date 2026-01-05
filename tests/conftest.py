"""
Pytest configuration and fixtures
"""

import pytest
import json
from pathlib import Path
import tempfile
import shutil


@pytest.fixture
def fixtures_path():
    """Return path to fixtures directory"""
    return Path(__file__).parent / "fixtures"


@pytest.fixture
def claude_desktop_config(fixtures_path):
    """Load Claude Desktop config fixture"""
    config_path = fixtures_path / "claude_desktop_config.json"
    return json.loads(config_path.read_text())


@pytest.fixture
def cursor_config(fixtures_path):
    """Load Cursor config fixture"""
    config_path = fixtures_path / "cursor_mcp.json"
    return json.loads(config_path.read_text())


@pytest.fixture
def package_json(fixtures_path):
    """Load package.json fixture"""
    config_path = fixtures_path / "package.json"
    return json.loads(config_path.read_text())


@pytest.fixture
def collected_config(fixtures_path):
    """Load collected config fixture"""
    config_path = fixtures_path / "collected_config.json"
    return json.loads(config_path.read_text())


@pytest.fixture
def temp_dir():
    """Create a temporary directory for tests"""
    temp_path = Path(tempfile.mkdtemp())
    yield temp_path
    shutil.rmtree(temp_path, ignore_errors=True)


@pytest.fixture
def temp_project(temp_dir, fixtures_path):
    """Create a temporary project with test files"""
    # Copy fixtures
    shutil.copy(fixtures_path / "package.json", temp_dir / "package.json")

    # Create mcp.json
    mcp_config = {
        "mcpServers": {
            "test-server": {
                "command": "npx",
                "args": ["test-mcp-server"]
            }
        }
    }
    (temp_dir / "mcp.json").write_text(json.dumps(mcp_config))

    return temp_dir


@pytest.fixture
def sample_scan_results():
    """Return sample scan results for testing"""
    return {
        "scan_time": "2024-01-15T10:30:00Z",
        "total_mcps": 3,
        "mcps": [
            {
                "name": "filesystem",
                "source": "@anthropic/mcp-server-filesystem",
                "found_in": "Claude Desktop",
                "server_type": "npm",
                "config_path": "/home/user/.config/claude.json",
                "risk_flags": ["filesystem-access"]
            },
            {
                "name": "shell",
                "source": "mcp-shell-tools",
                "found_in": "Cursor",
                "server_type": "python",
                "config_path": "/home/user/.cursor/mcp.json",
                "risk_flags": ["shell-access", "unverified-source"]
            },
            {
                "name": "slack",
                "source": "@modelcontextprotocol/server-slack",
                "found_in": "Claude Desktop",
                "server_type": "npm",
                "config_path": "/home/user/.config/claude.json",
                "risk_flags": []
            }
        ]
    }


@pytest.fixture
def sample_policy():
    """Return sample policy for testing"""
    return {
        "allowed_sources": [
            "@anthropic/*",
            "@modelcontextprotocol/*"
        ],
        "denied_capabilities": [
            "shell-access"
        ],
        "require_review": [
            "unverified-source"
        ]
    }
