"""
Output formatters for MCP Audit results
"""

import json
from datetime import datetime
from typing import Optional

from mcp_audit.models import ScanResult, CollectedConfig


def format_results(results: list[ScanResult], format: str) -> str:
    """Format scan results in requested format"""
    if format == "json":
        return _to_json(results)
    elif format == "markdown":
        return _to_markdown(results)
    elif format == "csv":
        return _to_csv(results)
    else:
        # Table format is handled separately with rich
        return _to_json(results)


def format_aggregated(
    mcps: dict, 
    configs: list[CollectedConfig], 
    format: str
) -> str:
    """Format aggregated results from collected configs"""
    if format == "json":
        return _aggregated_to_json(mcps, configs)
    elif format == "markdown":
        return _aggregated_to_markdown(mcps, configs)
    elif format == "csv":
        return _aggregated_to_csv(mcps, configs)
    else:
        return _aggregated_to_json(mcps, configs)


def _to_json(results: list[ScanResult]) -> str:
    """Convert results to JSON"""
    data = {
        "scan_time": datetime.now().isoformat(),
        "total_mcps": len(results),
        "mcps": [r.to_dict() for r in results],
    }
    return json.dumps(data, indent=2)


def _to_markdown(results: list[ScanResult]) -> str:
    """Convert results to Markdown"""
    lines = [
        "# MCP Audit Report",
        "",
        f"**Scan Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"**Total MCPs Found:** {len(results)}",
        "",
        "## MCP Inventory",
        "",
        "| MCP Name | Source | Found In | Type | Risk Flags |",
        "|----------|--------|----------|------|------------|",
    ]
    
    for r in results:
        risk_flags = ", ".join(r.risk_flags) if r.risk_flags else "-"
        lines.append(f"| {r.name} | {r.source} | {r.found_in} | {r.server_type} | {risk_flags} |")
    
    # Risk summary
    with_risks = [r for r in results if r.risk_flags]
    if with_risks:
        lines.extend([
            "",
            "## Risk Summary",
            "",
        ])
        for r in with_risks:
            lines.append(f"- **{r.name}**: {', '.join(r.risk_flags)}")
    
    return "\n".join(lines)


def _to_csv(results: list[ScanResult]) -> str:
    """Convert results to CSV"""
    lines = ["name,source,found_in,server_type,risk_flags,config_path"]
    
    for r in results:
        risk_flags = "|".join(r.risk_flags)
        # Escape commas in fields
        source = f'"{r.source}"' if "," in r.source else r.source
        config_path = f'"{r.config_path}"' if "," in r.config_path else r.config_path
        lines.append(f"{r.name},{source},{r.found_in},{r.server_type},{risk_flags},{config_path}")
    
    return "\n".join(lines)


def _aggregated_to_json(mcps: dict, configs: list[CollectedConfig]) -> str:
    """Convert aggregated results to JSON"""
    data = {
        "scan_time": datetime.now().isoformat(),
        "machines_reporting": len(configs),
        "unique_mcps": len(mcps),
        "mcps": [
            {
                "name": name,
                "source": info["source"],
                "server_type": info["server_type"],
                "machine_count": len(info["machines"]),
                "machines": info["machines"],
                "risk_flags": list(info["risk_flags"]),
            }
            for name, info in mcps.items()
        ],
        "by_machine": [c.to_dict() for c in configs],
    }
    return json.dumps(data, indent=2)


def _aggregated_to_markdown(mcps: dict, configs: list[CollectedConfig]) -> str:
    """Convert aggregated results to Markdown"""
    lines = [
        "# MCP Audit Report - Aggregated",
        "",
        f"**Scan Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"**Machines Reporting:** {len(configs)}",
        f"**Unique MCPs:** {len(mcps)}",
        "",
        "## MCP Inventory",
        "",
        "| MCP Name | Source | Machines | Type | Risk Flags |",
        "|----------|--------|----------|------|------------|",
    ]
    
    for name, info in sorted(mcps.items(), key=lambda x: len(x[1]["machines"]), reverse=True):
        risk_flags = ", ".join(info["risk_flags"]) if info["risk_flags"] else "-"
        lines.append(
            f"| {name} | {info['source'][:40]} | {len(info['machines'])} | "
            f"{info['server_type']} | {risk_flags} |"
        )
    
    # Machine summary
    lines.extend([
        "",
        "## By Machine",
        "",
    ])
    
    for config in configs:
        mcp_names = ", ".join([m.name for m in config.mcps[:5]])
        if len(config.mcps) > 5:
            mcp_names += f" (+{len(config.mcps) - 5} more)"
        lines.append(f"- **{config.machine_id}**: {len(config.mcps)} MCPs - {mcp_names}")
    
    return "\n".join(lines)


def _aggregated_to_csv(mcps: dict, configs: list[CollectedConfig]) -> str:
    """Convert aggregated results to CSV"""
    lines = ["name,source,server_type,machine_count,risk_flags"]
    
    for name, info in mcps.items():
        risk_flags = "|".join(info["risk_flags"])
        source = f'"{info["source"]}"' if "," in info["source"] else info["source"]
        lines.append(f"{name},{source},{info['server_type']},{len(info['machines'])},{risk_flags}")
    
    return "\n".join(lines)
