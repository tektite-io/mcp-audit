"""
Project-level MCP configuration scanner
Scans directories for MCP config files, .env files, and MCP dependencies
"""

import json
from pathlib import Path

from mcp_audit.models import ScanResult, DetectedSecret


# MCP config files to look for
MCP_CONFIG_FILES = [
    "mcp.json",
    "mcp.yaml",
    ".mcp/config.json",
    ".mcp/mcp.json",
    "mcp-manifest.json",
    "claude_desktop_config.json",
    "claude-desktop-config.json",
    "claude_desktop-config.json",
    "continue_config.json",
    "continue-config.json",
    ".continue/config.json",
]

# Environment files to scan for secrets
ENV_FILES = [
    ".env",
    ".env.local",
    ".env.development",
    ".env.production",
]

# Dependency files to check for MCP packages
DEPENDENCY_FILES = [
    "package.json",
    "requirements.txt",
    "pyproject.toml",
]

# Known MCP package patterns
MCP_NPM_PATTERNS = [
    "@modelcontextprotocol/",
    "@anthropic/mcp-",
    "mcp-server-",
]

MCP_PYTHON_PATTERNS = [
    "mcp",
    "fastmcp",
    "modelcontextprotocol",
]

# Directories to skip during recursive scanning
SKIP_DIRS = ["node_modules", "venv", ".venv", "__pycache__"]


def scan(path: Path, recursive: bool = True) -> list[ScanResult]:
    """Scan a directory for MCP configurations and dependencies"""
    results = []

    if not path.exists() or not path.is_dir():
        return results

    # Scan for config files
    results.extend(_scan_config_files(path, recursive))

    # Scan for .env files
    results.extend(_scan_env_files(path, recursive))

    # Scan for dependencies
    results.extend(_scan_dependencies(path, recursive))

    return results


def _should_skip(path: Path) -> bool:
    """Check if a path is inside a directory that should be skipped"""
    path_str = str(path)
    return any(skip_dir in path_str for skip_dir in SKIP_DIRS)


def _scan_config_files(path: Path, recursive: bool) -> list[ScanResult]:
    """Scan for MCP config files"""
    results = []

    if recursive:
        # Use glob for recursive search
        for pattern in MCP_CONFIG_FILES:
            for config_path in path.rglob(pattern):
                if _should_skip(config_path):
                    continue
                results.extend(_parse_config_file(config_path))
    else:
        # Just check immediate directory
        for pattern in MCP_CONFIG_FILES:
            config_path = path / pattern
            if config_path.exists():
                results.extend(_parse_config_file(config_path))

    return results


def _get_found_in(config_path: Path) -> str:
    """Determine a descriptive found_in label based on config filename"""
    name = config_path.name.lower()
    parent = config_path.parent.name
    if "claude" in name:
        return f"Claude Config ({parent})"
    if "continue" in name or config_path.parent.name == ".continue":
        return f"Continue Config ({parent})"
    return f"Project ({parent})"


def _parse_config_file(config_path: Path) -> list[ScanResult]:
    """Parse an MCP config file"""
    results = []

    try:
        if config_path.suffix == ".yaml":
            # Skip YAML for now
            return results

        config = json.loads(config_path.read_text())
    except (json.JSONDecodeError, IOError):
        return results

    # Handle different config formats
    mcp_servers = config.get("mcpServers", {})
    if not mcp_servers:
        mcp_servers = config.get("servers", {})
    # Also check Continue's old experimental key
    if not mcp_servers:
        experimental = config.get("experimental", {})
        if isinstance(experimental, dict):
            mcp_servers = experimental.get("modelContextProtocolServers", [])

    found_in = _get_found_in(config_path)

    # mcpServers can be a dict (keyed by name) or a list of dicts
    if isinstance(mcp_servers, dict):
        for name, server_config in mcp_servers.items():
            if isinstance(server_config, dict):
                result = ScanResult.from_dict(
                    {"name": name, **server_config},
                    found_in=found_in,
                    config_path=str(config_path),
                )
                results.append(result)
    elif isinstance(mcp_servers, list):
        for server in mcp_servers:
            if isinstance(server, dict):
                name = server.get("name", server.get("transport", {}).get("command", "unknown"))
                result = ScanResult.from_dict(
                    {"name": name, **server},
                    found_in=found_in,
                    config_path=str(config_path),
                )
                results.append(result)

    return results


def _scan_env_files(path: Path, recursive: bool) -> list[ScanResult]:
    """Scan .env files for secrets"""
    results = []

    if recursive:
        for pattern in ENV_FILES:
            for env_path in path.rglob(pattern):
                if _should_skip(env_path):
                    continue
                result = _parse_env_file(env_path)
                if result:
                    results.append(result)
    else:
        for pattern in ENV_FILES:
            env_path = path / pattern
            if env_path.exists():
                result = _parse_env_file(env_path)
                if result:
                    results.append(result)

    return results


def _parse_env_file(env_path: Path) -> ScanResult:
    """Parse a .env file and scan for secrets"""
    try:
        content = env_path.read_text()
    except IOError:
        return None

    # Parse KEY=VALUE pairs
    env_dict = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and value:
                env_dict[key] = value

    if not env_dict:
        return None

    # Reuse existing secret detection
    from mcp_audit.data.secret_patterns import detect_secrets

    raw_secrets = detect_secrets(env_dict, config_path=str(env_path), mcp_name=env_path.name)

    # Convert to DetectedSecret objects
    secrets = []
    for s in raw_secrets:
        secrets.append(DetectedSecret(
            type=s["type"],
            description=s["description"],
            severity=s["severity"],
            env_key=s["env_key"],
            value_masked=s["value_masked"],
            value_length=s["value_length"],
            confidence=s["confidence"],
            rotation_url=s.get("rotation_url"),
        ))

    if not secrets:
        return None

    risk_flags = ["secrets-detected"]

    return ScanResult(
        name=env_path.name,
        source=str(env_path),
        found_in=f"Project ({env_path.parent.name})",
        server_type="env-file",
        config_path=str(env_path),
        risk_flags=risk_flags,
        secrets=secrets,
    )


def _scan_dependencies(path: Path, recursive: bool) -> list[ScanResult]:
    """Scan dependency files for MCP packages"""
    results = []

    if recursive:
        for dep_file in DEPENDENCY_FILES:
            for dep_path in path.rglob(dep_file):
                if _should_skip(dep_path):
                    continue
                results.extend(_parse_dependency_file(dep_path))
    else:
        for dep_file in DEPENDENCY_FILES:
            dep_path = path / dep_file
            if dep_path.exists():
                results.extend(_parse_dependency_file(dep_path))

    return results


def _parse_dependency_file(dep_path: Path) -> list[ScanResult]:
    """Parse a dependency file for MCP packages"""
    results = []

    try:
        content = dep_path.read_text()
    except IOError:
        return results

    if dep_path.name == "package.json":
        results.extend(_parse_package_json(content, dep_path))
    elif dep_path.name == "requirements.txt":
        results.extend(_parse_requirements_txt(content, dep_path))
    elif dep_path.name == "pyproject.toml":
        results.extend(_parse_pyproject_toml(content, dep_path))

    return results


def _parse_package_json(content: str, dep_path: Path) -> list[ScanResult]:
    """Parse package.json for MCP dependencies"""
    results = []

    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return results

    all_deps = {}
    all_deps.update(data.get("dependencies", {}))
    all_deps.update(data.get("devDependencies", {}))

    for pkg, version in all_deps.items():
        if any(pattern in pkg for pattern in MCP_NPM_PATTERNS):
            result = ScanResult(
                name=pkg,
                source=f"{pkg}@{version}",
                found_in=f"Dependency ({dep_path.parent.name})",
                server_type="npm",
                config_path=str(dep_path),
                risk_flags=["dependency-only"],  # Not a running config, just a dependency
            )
            results.append(result)

    return results


def _parse_requirements_txt(content: str, dep_path: Path) -> list[ScanResult]:
    """Parse requirements.txt for MCP packages"""
    results = []

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # Extract package name (before any version specifier)
        pkg = line.split("==")[0].split(">=")[0].split("<=")[0].split("[")[0].strip()

        if any(pattern in pkg.lower() for pattern in MCP_PYTHON_PATTERNS):
            result = ScanResult(
                name=pkg,
                source=line,
                found_in=f"Dependency ({dep_path.parent.name})",
                server_type="python",
                config_path=str(dep_path),
                risk_flags=["dependency-only"],
            )
            results.append(result)

    return results


def _parse_pyproject_toml(content: str, dep_path: Path) -> list[ScanResult]:
    """Parse pyproject.toml for MCP dependencies (basic parsing)"""
    results = []

    # Basic TOML parsing without dependency
    # Look for dependencies section
    in_deps = False
    for line in content.splitlines():
        line = line.strip()

        if "[project.dependencies]" in line or "[tool.poetry.dependencies]" in line:
            in_deps = True
            continue

        if in_deps:
            if line.startswith("["):
                in_deps = False
                continue

            for pattern in MCP_PYTHON_PATTERNS:
                if pattern in line.lower():
                    # Extract package name
                    pkg = line.split("=")[0].strip().strip('"').strip("'")
                    result = ScanResult(
                        name=pkg,
                        source=line.strip(),
                        found_in=f"Dependency ({dep_path.parent.name})",
                        server_type="python",
                        config_path=str(dep_path),
                        risk_flags=["dependency-only"],
                    )
                    results.append(result)

    return results
