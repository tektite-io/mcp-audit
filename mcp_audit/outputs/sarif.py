"""
SARIF (Static Analysis Results Interchange Format) output for MCP Audit

SARIF 2.1.0 specification for GitHub Security integration.
"""

import json
from datetime import datetime
from typing import List, Dict

from mcp_audit.models import ScanResult
from mcp_audit.data.risk_definitions import get_risk_flag_info, get_severity_for_flag
from mcp_audit.data.owasp_llm import (
    get_owasp_llm_for_secret,
    get_owasp_llm_for_risk_flag,
    get_owasp_llm_for_finding,
    OWASP_LLM_TOP_10,
)


def generate_sarif(results: List[ScanResult]) -> str:
    """
    Generate SARIF 2.1.0 output for MCP audit results.

    Returns:
        JSON string in SARIF format
    """
    # Build rules from all unique findings
    rules = _build_rules(results)

    # Build results from all findings
    sarif_results = _build_sarif_results(results)

    sarif_doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mcp-audit",
                        "informationUri": "https://github.com/apisec-inc/mcp-audit",
                        "version": "1.0.0",
                        "organization": "APIsec",
                        "shortDescription": {
                            "text": "Security audit for Model Context Protocol (MCP) configurations"
                        },
                        "fullDescription": {
                            "text": "MCP Audit scans AI development tools (Claude Desktop, Cursor, VS Code) for security risks including exposed secrets, API endpoints, and excessive agency."
                        },
                        "rules": rules,
                    }
                },
                "results": sarif_results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": datetime.utcnow().isoformat() + "Z",
                    }
                ],
            }
        ],
    }

    return json.dumps(sarif_doc, indent=2)


def _build_rules(results: List[ScanResult]) -> List[Dict]:
    """Build SARIF rules from scan results"""
    rules = []
    seen_rule_ids = set()

    # Add rules for risk flags
    for r in results:
        for flag in r.risk_flags:
            rule_id = f"mcp-audit/{flag}"
            if rule_id in seen_rule_ids:
                continue
            seen_rule_ids.add(rule_id)

            info = get_risk_flag_info(flag)
            severity = get_severity_for_flag(flag)
            owasp_refs = get_owasp_llm_for_risk_flag(flag)

            rule = {
                "id": rule_id,
                "name": flag.replace("-", " ").title(),
                "shortDescription": {
                    "text": info.get("description", flag)
                },
                "fullDescription": {
                    "text": info.get("explanation", "")
                },
                "help": {
                    "text": info.get("remediation", "Review and fix"),
                    "markdown": f"**Remediation:** {info.get('remediation', 'Review and fix')}"
                },
                "defaultConfiguration": {
                    "level": _severity_to_sarif_level(severity)
                },
                "properties": {
                    "tags": _build_tags(flag, owasp_refs),
                    "security-severity": _severity_to_score(severity),
                }
            }
            rules.append(rule)

    # Add rules for secret types
    for r in results:
        for s in r.secrets:
            secret_type = s.type if hasattr(s, 'type') else s.get('type', 'unknown')
            rule_id = f"mcp-audit/secret/{secret_type}"
            if rule_id in seen_rule_ids:
                continue
            seen_rule_ids.add(rule_id)

            severity = s.severity if hasattr(s, 'severity') else s.get('severity', 'high')
            owasp_refs = get_owasp_llm_for_secret(secret_type)
            description = s.description if hasattr(s, 'description') else s.get('description', 'Secret detected')

            rule = {
                "id": rule_id,
                "name": f"Exposed Secret: {secret_type.replace('_', ' ').title()}",
                "shortDescription": {
                    "text": description
                },
                "fullDescription": {
                    "text": f"A {secret_type} was detected in MCP configuration. Exposed secrets can lead to unauthorized access and data breaches."
                },
                "help": {
                    "text": "Rotate the credential immediately and remove from configuration.",
                    "markdown": "**Remediation:**\n1. Rotate the credential immediately\n2. Remove from configuration\n3. Use environment variables or secrets manager"
                },
                "defaultConfiguration": {
                    "level": _severity_to_sarif_level(severity)
                },
                "properties": {
                    "tags": _build_tags(f"secret-{secret_type}", owasp_refs),
                    "security-severity": _severity_to_score(severity),
                }
            }
            rules.append(rule)

    return rules


def _build_sarif_results(results: List[ScanResult]) -> List[Dict]:
    """Build SARIF results from scan results"""
    sarif_results = []

    for r in results:
        # Add results for risk flags
        for flag in r.risk_flags:
            info = get_risk_flag_info(flag)
            severity = get_severity_for_flag(flag)

            result = {
                "ruleId": f"mcp-audit/{flag}",
                "level": _severity_to_sarif_level(severity),
                "message": {
                    "text": f"{flag}: {info.get('explanation', 'Risk detected')} in MCP '{r.name}'"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": r.config_path,
                                "uriBaseId": "%SRCROOT%"
                            }
                        },
                        "logicalLocations": [
                            {
                                "name": r.name,
                                "kind": "mcp",
                                "fullyQualifiedName": f"{r.found_in}/{r.name}"
                            }
                        ]
                    }
                ],
                "fixes": [
                    {
                        "description": {
                            "text": info.get("remediation", "Review and fix")
                        }
                    }
                ],
            }
            sarif_results.append(result)

        # Add results for secrets
        for s in r.secrets:
            secret_type = s.type if hasattr(s, 'type') else s.get('type', 'unknown')
            severity = s.severity if hasattr(s, 'severity') else s.get('severity', 'high')
            env_key = s.env_key if hasattr(s, 'env_key') else s.get('env_key', 'unknown')
            description = s.description if hasattr(s, 'description') else s.get('description', 'Secret detected')
            rotation_url = s.rotation_url if hasattr(s, 'rotation_url') else s.get('rotation_url', '')

            result = {
                "ruleId": f"mcp-audit/secret/{secret_type}",
                "level": _severity_to_sarif_level(severity),
                "message": {
                    "text": f"{description} in MCP '{r.name}' at env.{env_key}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": r.config_path,
                                "uriBaseId": "%SRCROOT%"
                            }
                        },
                        "logicalLocations": [
                            {
                                "name": f"{r.name}/env/{env_key}",
                                "kind": "environment-variable",
                                "fullyQualifiedName": f"{r.found_in}/{r.name}/env/{env_key}"
                            }
                        ]
                    }
                ],
                "fixes": [
                    {
                        "description": {
                            "text": f"Rotate credential at {rotation_url}" if rotation_url else "Rotate this credential immediately"
                        }
                    }
                ],
            }
            sarif_results.append(result)

    return sarif_results


def _build_tags(finding_type: str, owasp_refs: List[Dict]) -> List[str]:
    """Build SARIF tags including OWASP LLM references"""
    tags = ["security", "mcp", "ai-security"]

    # Add finding-specific tags
    if "secret" in finding_type.lower():
        tags.append("secrets")
        tags.append("credential-exposure")
    if "shell" in finding_type.lower():
        tags.append("shell-access")
        tags.append("code-execution")
    if "database" in finding_type.lower():
        tags.append("database-access")
    if "filesystem" in finding_type.lower():
        tags.append("filesystem-access")

    # Add OWASP LLM Top 10 tags
    for ref in owasp_refs:
        tags.append(f"OWASP-LLM-{ref['id']}")
        # Also add CWE-like tag for better integration
        tags.append(f"external/owasp-llm/{ref['id'].lower()}")

    return list(set(tags))  # Remove duplicates


def _severity_to_sarif_level(severity: str) -> str:
    """Convert severity to SARIF level"""
    mapping = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
    }
    return mapping.get(severity.lower(), "warning")


def _severity_to_score(severity: str) -> str:
    """Convert severity to CVSS-like score for security-severity"""
    mapping = {
        "critical": "9.0",
        "high": "7.5",
        "medium": "5.0",
        "low": "2.5",
    }
    return mapping.get(severity.lower(), "5.0")
