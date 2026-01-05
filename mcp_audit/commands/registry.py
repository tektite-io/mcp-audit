"""
Registry command - View and export known MCP registry
"""

import typer
from rich.console import Console
from rich.table import Table
from pathlib import Path
from typing import Optional
import json

from mcp_audit.data import (
    get_registry,
    get_mcps_by_risk,
    get_verified_mcps,
    get_all_endpoints,
    get_risk_definition,
    get_type_definition,
)

app = typer.Typer(help="View and export known MCP registry")
console = Console()


@app.callback(invoke_without_command=True)
def registry(
    ctx: typer.Context,
    risk: Optional[str] = typer.Option(
        None, "--risk", "-r", help="Filter by risk level: critical, high, medium, low"
    ),
    provider: Optional[str] = typer.Option(
        None, "--provider", "-p", help="Filter by provider name"
    ),
    mcp_type: Optional[str] = typer.Option(
        None, "--type", "-t", help="Filter by type: official, vendor, community"
    ),
    verified_only: bool = typer.Option(
        False, "--verified", help="Show only verified MCPs"
    ),
    format: str = typer.Option(
        "table", "--format", "-f", help="Output format: table, json, endpoints"
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Write output to file"
    ),
):
    """
    View the known MCP registry.

    Examples:
        mcp-audit registry                           # Show all known MCPs
        mcp-audit registry --risk critical           # Show critical risk MCPs
        mcp-audit registry --provider Anthropic      # Show Anthropic MCPs
        mcp-audit registry --type official           # Show official MCPs only
        mcp-audit registry --format endpoints        # Export for firewall/proxy
        mcp-audit registry --format json -o mcps.json
    """
    if ctx.invoked_subcommand is not None:
        return

    console.print("\n[bold blue]MCP Audit - Known MCP Registry[/bold blue]\n")

    registry_data = get_registry()
    mcps = registry_data["mcps"]

    # Apply filters
    if risk:
        mcps = [m for m in mcps if m["risk_level"] == risk.lower()]

    if provider:
        mcps = [m for m in mcps if provider.lower() in m["provider"].lower()]

    if mcp_type:
        mcps = [m for m in mcps if m["type"] == mcp_type.lower()]

    if verified_only:
        mcps = [m for m in mcps if m.get("verified", False)]

    if not mcps:
        console.print("[yellow]No MCPs match the specified filters.[/yellow]")
        return

    # Output
    if format == "json":
        output_data = json.dumps({"mcps": mcps}, indent=2)
        if output:
            output.write_text(output_data)
            console.print(f"[green]Written to {output}[/green]")
        else:
            console.print(output_data)

    elif format == "endpoints":
        endpoints = [m for m in mcps if m.get("endpoint")]
        if not endpoints:
            console.print("[yellow]No MCPs with known endpoints in the filtered set.[/yellow]")
            return

        output_data = json.dumps({
            "description": "Known MCP endpoints for network monitoring",
            "endpoints": [
                {
                    "name": m["name"],
                    "provider": m["provider"],
                    "endpoint": m["endpoint"],
                    "risk_level": m["risk_level"]
                }
                for m in endpoints
            ]
        }, indent=2)

        if output:
            output.write_text(output_data)
            console.print(f"[green]Written to {output}[/green]")
        else:
            console.print(output_data)

    else:  # table
        _print_table(mcps)

    # Summary
    console.print(f"\n[dim]Total: {len(mcps)} MCPs[/dim]")


def _print_table(mcps: list[dict]):
    """Print MCPs as a rich table"""
    table = Table(title="Known MCP Registry", show_header=True, header_style="bold cyan")

    table.add_column("Name", style="white")
    table.add_column("Provider", style="blue")
    table.add_column("Package", style="dim")
    table.add_column("Type", style="magenta")
    table.add_column("Risk", style="yellow")
    table.add_column("Verified", style="green")

    for m in mcps:
        risk_style = {
            "critical": "[red]CRITICAL[/red]",
            "high": "[yellow]HIGH[/yellow]",
            "medium": "[blue]MEDIUM[/blue]",
            "low": "[green]LOW[/green]"
        }.get(m["risk_level"], m["risk_level"])

        verified = "[green]Yes[/green]" if m.get("verified") else "[red]No[/red]"

        table.add_row(
            m["name"],
            m["provider"],
            _truncate(m["package"], 35),
            m["type"],
            risk_style,
            verified
        )

    console.print(table)


@app.command()
def stats():
    """Show registry statistics"""
    registry_data = get_registry()
    mcps = registry_data["mcps"]

    console.print("\n[bold blue]MCP Registry Statistics[/bold blue]\n")

    # By risk
    console.print("[cyan]By Risk Level:[/cyan]")
    for risk in ["critical", "high", "medium", "low"]:
        count = len([m for m in mcps if m["risk_level"] == risk])
        risk_def = get_risk_definition(risk)
        console.print(f"  [bold]{risk.upper()}[/bold]: {count}")
        console.print(f"    [dim]{risk_def}[/dim]")

    # By type
    console.print("\n[cyan]By Type:[/cyan]")
    for mcp_type in ["official", "vendor", "community"]:
        count = len([m for m in mcps if m["type"] == mcp_type])
        type_def = get_type_definition(mcp_type)
        console.print(f"  [bold]{mcp_type.capitalize()}[/bold]: {count}")
        console.print(f"    [dim]{type_def}[/dim]")

    # Verified vs unverified
    verified = len([m for m in mcps if m.get("verified", False)])
    unverified = len(mcps) - verified
    console.print(f"\n[cyan]Verification:[/cyan]")
    console.print(f"  [green]Verified[/green]: {verified}")
    console.print(f"  [red]Unverified[/red]: {unverified}")

    # By provider
    console.print("\n[cyan]Top Providers:[/cyan]")
    providers = {}
    for m in mcps:
        providers[m["provider"]] = providers.get(m["provider"], 0) + 1

    for provider, count in sorted(providers.items(), key=lambda x: x[1], reverse=True)[:10]:
        console.print(f"  {provider}: {count}")

    # Endpoints
    with_endpoints = len([m for m in mcps if m.get("endpoint")])
    console.print(f"\n[cyan]With Known Endpoints:[/cyan] {with_endpoints}")

    console.print(f"\n[bold]Total MCPs in Registry: {len(mcps)}[/bold]")
    console.print(f"[dim]Registry Version: {registry_data.get('version', 'unknown')}[/dim]")
    console.print(f"[dim]Last Updated: {registry_data.get('last_updated', 'unknown')}[/dim]")


@app.command()
def lookup(
    source: str = typer.Argument(..., help="Package name or source to look up"),
):
    """Look up a specific MCP in the registry"""
    from mcp_audit.data import lookup_mcp

    console.print(f"\n[bold]Looking up: {source}[/bold]\n")

    match = lookup_mcp(source)

    if match:
        console.print("[green]Found in registry![/green]\n")

        table = Table(show_header=False, box=None)
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="white")

        table.add_row("Name", match["name"])
        table.add_row("Provider", match["provider"])
        table.add_row("Package", match["package"])
        table.add_row("Type", match["type"])

        risk_style = {
            "critical": "[red]CRITICAL[/red]",
            "high": "[yellow]HIGH[/yellow]",
            "medium": "[blue]MEDIUM[/blue]",
            "low": "[green]LOW[/green]"
        }.get(match["risk_level"], match["risk_level"])
        table.add_row("Risk Level", risk_style)

        verified = "[green]Yes[/green]" if match.get("verified") else "[red]No[/red]"
        table.add_row("Verified", verified)

        if match.get("endpoint"):
            table.add_row("Endpoint", match["endpoint"])

        table.add_row("Capabilities", ", ".join(match.get("capabilities", [])))
        table.add_row("Documentation", match.get("documentation", "N/A"))

        console.print(table)
    else:
        console.print("[yellow]Not found in registry.[/yellow]")
        console.print("\nThis MCP is not in the known registry. It may be:")
        console.print("  - A community/third-party MCP")
        console.print("  - A custom/internal MCP")
        console.print("  - A newer MCP not yet added to the registry")


@app.command()
def capabilities(
    capability: Optional[str] = typer.Argument(None, help="Filter by capability name"),
):
    """List MCPs by their capabilities"""
    registry_data = get_registry()
    mcps = registry_data["mcps"]

    # Collect all capabilities
    all_caps = {}
    for m in mcps:
        for cap in m.get("capabilities", []):
            if cap not in all_caps:
                all_caps[cap] = []
            all_caps[cap].append(m)

    if capability:
        # Filter to specific capability
        if capability.lower() not in [c.lower() for c in all_caps.keys()]:
            console.print(f"[yellow]No MCPs with capability: {capability}[/yellow]")
            console.print("\nAvailable capabilities:")
            for cap in sorted(all_caps.keys()):
                console.print(f"  - {cap}")
            return

        matching = [c for c in all_caps.keys() if c.lower() == capability.lower()][0]
        mcps_with_cap = all_caps[matching]

        console.print(f"\n[bold]MCPs with '{matching}' capability:[/bold]\n")

        for m in mcps_with_cap:
            risk_style = {
                "critical": "[red]CRITICAL[/red]",
                "high": "[yellow]HIGH[/yellow]",
                "medium": "[blue]MEDIUM[/blue]",
                "low": "[green]LOW[/green]"
            }.get(m["risk_level"], m["risk_level"])

            console.print(f"  - {m['name']} ({m['provider']}) - {risk_style}")
    else:
        # Show all capabilities
        console.print("\n[bold]All Capabilities in Registry:[/bold]\n")

        for cap in sorted(all_caps.keys()):
            count = len(all_caps[cap])
            console.print(f"  [cyan]{cap}[/cyan]: {count} MCP(s)")


def _truncate(s: str, length: int) -> str:
    """Truncate string with ellipsis"""
    if len(s) <= length:
        return s
    return s[:length-3] + "..."
