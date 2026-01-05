"""
Docker Compose and Kubernetes MCP configuration scanner
Scans for MCP servers in container orchestration configs
"""

import json
import re
from pathlib import Path
from typing import Optional

from mcp_audit.models import ScanResult


# Docker Compose files to look for
DOCKER_COMPOSE_FILES = [
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
]

# Kubernetes manifest patterns
K8S_PATTERNS = [
    "*.yaml",
    "*.yml",
]

# MCP-related image/service patterns
MCP_PATTERNS = [
    r"mcp-server",
    r"modelcontextprotocol",
    r"@anthropic/mcp",
    r"fastmcp",
]


def scan(path: Path, recursive: bool = True) -> list[ScanResult]:
    """Scan for MCP servers in Docker and Kubernetes configs"""
    results = []

    if not path.exists() or not path.is_dir():
        return results

    # Scan Docker Compose files
    results.extend(_scan_docker_compose(path, recursive))

    # Scan Kubernetes manifests
    results.extend(_scan_kubernetes(path, recursive))

    return results


def _scan_docker_compose(path: Path, recursive: bool) -> list[ScanResult]:
    """Scan Docker Compose files for MCP services"""
    results = []

    for compose_file in DOCKER_COMPOSE_FILES:
        if recursive:
            for config_path in path.rglob(compose_file):
                results.extend(_parse_docker_compose(config_path))
        else:
            config_path = path / compose_file
            if config_path.exists():
                results.extend(_parse_docker_compose(config_path))

    return results


def _parse_docker_compose(config_path: Path) -> list[ScanResult]:
    """Parse Docker Compose file for MCP services"""
    results = []

    try:
        content = config_path.read_text()
    except IOError:
        return results

    # Basic YAML parsing for services
    # Look for MCP-related patterns in the content
    for pattern in MCP_PATTERNS:
        if re.search(pattern, content, re.IGNORECASE):
            # Found MCP reference, parse more carefully
            services = _extract_docker_services(content)
            for service_name, service_config in services.items():
                if _is_mcp_service(service_name, service_config):
                    image = service_config.get("image", "unknown")
                    result = ScanResult(
                        name=service_name,
                        source=image,
                        found_in=f"Docker Compose ({config_path.parent.name})",
                        server_type="docker",
                        config_path=str(config_path),
                        command="docker",
                        args=["run", image],
                        risk_flags=_identify_docker_risks(service_config),
                    )
                    results.append(result)
            break

    return results


def _extract_docker_services(content: str) -> dict:
    """Extract services from Docker Compose YAML (basic parsing)"""
    services = {}
    current_service = None
    in_services = False
    indent_level = 0

    for line in content.splitlines():
        stripped = line.strip()

        if stripped.startswith("services:"):
            in_services = True
            continue

        if in_services:
            # Check if we're at a new top-level section
            if stripped and not line.startswith(" ") and not line.startswith("\t"):
                in_services = False
                continue

            # Count indentation
            spaces = len(line) - len(line.lstrip())

            # New service definition (typically 2 spaces)
            if spaces == 2 and stripped.endswith(":") and not stripped.startswith("-"):
                current_service = stripped.rstrip(":")
                services[current_service] = {}
                indent_level = spaces
                continue

            # Service property
            if current_service and spaces > indent_level:
                if ":" in stripped:
                    key, value = stripped.split(":", 1)
                    key = key.strip()
                    value = value.strip()
                    services[current_service][key] = value

    return services


def _is_mcp_service(name: str, config: dict) -> bool:
    """Check if a Docker service is MCP-related"""
    # Check service name
    for pattern in MCP_PATTERNS:
        if re.search(pattern, name, re.IGNORECASE):
            return True

    # Check image
    image = config.get("image", "")
    for pattern in MCP_PATTERNS:
        if re.search(pattern, image, re.IGNORECASE):
            return True

    return False


def _identify_docker_risks(config: dict) -> list[str]:
    """Identify risks from Docker service config"""
    risks = []

    # Check for volume mounts
    volumes = config.get("volumes", "")
    if volumes:
        risks.append("filesystem-access")

    # Check for privileged mode
    if config.get("privileged", "").lower() == "true":
        risks.append("shell-access")

    # Check for network mode
    network = config.get("network_mode", "")
    if network == "host":
        risks.append("network-access")

    return risks


def _scan_kubernetes(path: Path, recursive: bool) -> list[ScanResult]:
    """Scan Kubernetes manifests for MCP deployments"""
    results = []

    if recursive:
        for pattern in K8S_PATTERNS:
            for config_path in path.rglob(pattern):
                # Skip Docker Compose files
                if config_path.name in DOCKER_COMPOSE_FILES:
                    continue
                # Skip node_modules and similar
                if "node_modules" in str(config_path):
                    continue
                results.extend(_parse_kubernetes(config_path))

    return results


def _parse_kubernetes(config_path: Path) -> list[ScanResult]:
    """Parse Kubernetes manifest for MCP containers"""
    results = []

    try:
        content = config_path.read_text()
    except IOError:
        return results

    # Check if this looks like a Kubernetes manifest
    if "apiVersion:" not in content or "kind:" not in content:
        return results

    # Look for MCP patterns
    for pattern in MCP_PATTERNS:
        if re.search(pattern, content, re.IGNORECASE):
            # Extract container info (basic parsing)
            containers = _extract_k8s_containers(content)
            for container in containers:
                if _is_mcp_container(container):
                    name = container.get("name", "unknown")
                    image = container.get("image", "unknown")
                    result = ScanResult(
                        name=name,
                        source=image,
                        found_in=f"Kubernetes ({config_path.parent.name})",
                        server_type="docker",
                        config_path=str(config_path),
                        command="kubectl",
                        args=["run", name, f"--image={image}"],
                        risk_flags=["kubernetes-deployment"],
                    )
                    results.append(result)
            break

    return results


def _extract_k8s_containers(content: str) -> list[dict]:
    """Extract container specs from Kubernetes manifest (basic parsing)"""
    containers = []
    current_container = None
    in_containers = False

    for line in content.splitlines():
        stripped = line.strip()

        if "containers:" in stripped:
            in_containers = True
            continue

        if in_containers:
            if stripped.startswith("- name:"):
                if current_container:
                    containers.append(current_container)
                current_container = {"name": stripped.split(":", 1)[1].strip()}
                continue

            if current_container and ":" in stripped:
                key, value = stripped.split(":", 1)
                key = key.strip().lstrip("-").strip()
                value = value.strip()
                if key and value:
                    current_container[key] = value

            # End of containers section
            if stripped and not stripped.startswith("-") and not stripped.startswith(" "):
                if stripped.endswith(":") and not stripped.startswith("image"):
                    in_containers = False
                    if current_container:
                        containers.append(current_container)
                    current_container = None

    if current_container:
        containers.append(current_container)

    return containers


def _is_mcp_container(container: dict) -> bool:
    """Check if a Kubernetes container is MCP-related"""
    name = container.get("name", "")
    image = container.get("image", "")

    for pattern in MCP_PATTERNS:
        if re.search(pattern, name, re.IGNORECASE):
            return True
        if re.search(pattern, image, re.IGNORECASE):
            return True

    return False
