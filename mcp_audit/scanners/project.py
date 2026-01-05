"""
Project-level MCP configuration scanner
Scans directories for mcp.json, .mcp/ folders, and MCP dependencies
"""

import json
from pathlib import Path

from mcp_audit.models import ScanResult


# Files to look for
MCP_CONFIG_FILES = [
    "mcp.json",
    "mcp.yaml",
    ".mcp/config.json",
    ".mcp/mcp.json",
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


def scan(path: Path, recursive: bool = True) -> list[ScanResult]:
    """Scan a directory for MCP configurations and dependencies"""
    results = []
    
    if not path.exists() or not path.is_dir():
        return results
    
    # Scan for config files
    results.extend(_scan_config_files(path, recursive))
    
    # Scan for dependencies
    results.extend(_scan_dependencies(path, recursive))
    
    return results


def _scan_config_files(path: Path, recursive: bool) -> list[ScanResult]:
    """Scan for MCP config files"""
    results = []
    
    if recursive:
        # Use glob for recursive search
        for pattern in MCP_CONFIG_FILES:
            for config_path in path.rglob(pattern):
                results.extend(_parse_config_file(config_path))
    else:
        # Just check immediate directory
        for pattern in MCP_CONFIG_FILES:
            config_path = path / pattern
            if config_path.exists():
                results.extend(_parse_config_file(config_path))
    
    return results


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
    
    for name, server_config in mcp_servers.items():
        result = ScanResult.from_dict(
            {"name": name, **server_config},
            found_in=f"Project ({config_path.parent.name})",
            config_path=str(config_path),
        )
        results.append(result)
    
    return results


def _scan_dependencies(path: Path, recursive: bool) -> list[ScanResult]:
    """Scan dependency files for MCP packages"""
    results = []
    
    if recursive:
        for dep_file in DEPENDENCY_FILES:
            for dep_path in path.rglob(dep_file):
                # Skip node_modules and venv
                if "node_modules" in str(dep_path) or "venv" in str(dep_path):
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
