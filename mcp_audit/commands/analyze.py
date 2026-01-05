"""
Analyze command - Process collected MCP configurations from MDM
"""

import typer
from rich.console import Console
from rich.table import Table
from pathlib import Path
from typing import Optional
import json

from mcp_audit.models import ScanResult, CollectedConfig
from mcp_audit.outputs import formatter

app = typer.Typer(help="Analyze collected MCP configurations")
console = Console()


@app.callback(invoke_without_command=True)
def analyze(
    ctx: typer.Context,
    path: Path = typer.Argument(
        ..., help="Path to directory containing collected config files"
    ),
    format: str = typer.Option(
        "table", "--format", "-f", help="Output format: table, json, markdown, csv"
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Write output to file"
    ),
    group_by: str = typer.Option(
        "mcp", "--group-by", "-g", help="Group results by: mcp, machine, source"
    ),
):
    """
    Analyze MCP configurations collected from developer machines via MDM.
    
    The collector script outputs JSON files to a shared location.
    This command aggregates and analyzes all collected configs.
    
    Examples:
        mcp-audit analyze /path/to/collected-configs/
        mcp-audit analyze ./configs --format markdown --output report.md
        mcp-audit analyze ./configs --group-by machine
    """
    if ctx.invoked_subcommand is not None:
        return

    console.print("\n[bold blue]MCP Audit - Analyze Collected Configs[/bold blue]\n")
    
    # Validate path
    if not path.exists():
        console.print(f"[red]Error: Path does not exist: {path}[/red]")
        raise typer.Exit(1)
    
    if not path.is_dir():
        console.print(f"[red]Error: Path is not a directory: {path}[/red]")
        raise typer.Exit(1)
    
    # Find all JSON files
    json_files = list(path.glob("*.json"))
    
    if not json_files:
        console.print(f"[yellow]No JSON files found in {path}[/yellow]")
        raise typer.Exit(0)
    
    console.print(f"Found {len(json_files)} config file(s)\n")
    
    # Parse all configs
    all_configs: list[CollectedConfig] = []
    errors = []
    
    with console.status("[bold green]Parsing collected configs..."):
        for f in json_files:
            try:
                data = json.loads(f.read_text())
                config = CollectedConfig.from_dict(data, source_file=f.name)
                all_configs.append(config)
            except json.JSONDecodeError as e:
                errors.append(f"{f.name}: Invalid JSON - {e}")
            except Exception as e:
                errors.append(f"{f.name}: {e}")
    
    if errors:
        console.print("[yellow]Warnings:[/yellow]")
        for err in errors:
            console.print(f"  • {err}")
        console.print()
    
    if not all_configs:
        console.print("[red]No valid configs found[/red]")
        raise typer.Exit(1)
    
    # Aggregate results
    results = _aggregate_configs(all_configs)
    
    # Output
    if format == "table":
        if group_by == "mcp":
            _print_by_mcp(results, all_configs)
        elif group_by == "machine":
            _print_by_machine(all_configs)
        else:
            _print_by_source(results)
    else:
        formatted = formatter.format_aggregated(results, all_configs, format)
        if output:
            output.write_text(formatted)
            console.print(f"[green]Results written to {output}[/green]")
        else:
            console.print(formatted)
    
    # Summary
    _print_aggregate_summary(results, all_configs)


def _aggregate_configs(configs: list[CollectedConfig]) -> dict:
    """Aggregate configs to get unique MCPs and counts"""
    mcps = {}
    
    for config in configs:
        for mcp in config.mcps:
            key = mcp.name
            if key not in mcps:
                mcps[key] = {
                    "name": mcp.name,
                    "source": mcp.source,
                    "server_type": mcp.server_type,
                    "machines": [],
                    "risk_flags": set(),
                }
            mcps[key]["machines"].append(config.machine_id)
            mcps[key]["risk_flags"].update(mcp.risk_flags)
    
    return mcps


def _print_by_mcp(mcps: dict, configs: list[CollectedConfig]):
    """Print table grouped by MCP"""
    table = Table(title="MCP Inventory (by MCP)", show_header=True, header_style="bold cyan")
    
    table.add_column("MCP Name", style="white")
    table.add_column("Source", style="dim")
    table.add_column("Machines", style="blue", justify="right")
    table.add_column("Type", style="magenta")
    table.add_column("Risk Flags", style="yellow")
    
    for name, data in sorted(mcps.items(), key=lambda x: len(x[1]["machines"]), reverse=True):
        risk_flags = ", ".join(data["risk_flags"]) if data["risk_flags"] else "-"
        table.add_row(
            name,
            _truncate(data["source"], 35),
            str(len(data["machines"])),
            data["server_type"],
            risk_flags
        )
    
    console.print(table)


def _print_by_machine(configs: list[CollectedConfig]):
    """Print table grouped by machine"""
    table = Table(title="MCP Inventory (by Machine)", show_header=True, header_style="bold cyan")
    
    table.add_column("Machine", style="white")
    table.add_column("MCPs", style="blue", justify="right")
    table.add_column("MCP Names", style="dim")
    table.add_column("Risk Flags", style="yellow")
    
    for config in sorted(configs, key=lambda x: len(x.mcps), reverse=True):
        mcp_names = ", ".join([m.name for m in config.mcps[:3]])
        if len(config.mcps) > 3:
            mcp_names += f" (+{len(config.mcps) - 3} more)"
        
        all_risks = set()
        for mcp in config.mcps:
            all_risks.update(mcp.risk_flags)
        
        risk_flags = ", ".join(all_risks) if all_risks else "-"
        
        table.add_row(
            config.machine_id,
            str(len(config.mcps)),
            mcp_names,
            risk_flags
        )
    
    console.print(table)


def _print_by_source(mcps: dict):
    """Print table grouped by source/publisher"""
    # Group by source prefix
    by_source = {}
    for name, data in mcps.items():
        source = data["source"]
        # Extract publisher from source
        if source.startswith("@"):
            publisher = source.split("/")[0]
        elif "github.com" in source:
            parts = source.replace("https://", "").replace("github.com/", "").split("/")
            publisher = f"github:{parts[0]}" if parts else "github:unknown"
        else:
            publisher = "local/unknown"
        
        if publisher not in by_source:
            by_source[publisher] = []
        by_source[publisher].append(data)
    
    table = Table(title="MCP Inventory (by Source)", show_header=True, header_style="bold cyan")
    
    table.add_column("Publisher", style="white")
    table.add_column("MCPs", style="blue", justify="right")
    table.add_column("Total Installs", style="magenta", justify="right")
    table.add_column("MCP Names", style="dim")
    
    for publisher, mcps_list in sorted(by_source.items()):
        mcp_names = ", ".join([m["name"] for m in mcps_list[:3]])
        if len(mcps_list) > 3:
            mcp_names += f" (+{len(mcps_list) - 3} more)"
        
        total_installs = sum(len(m["machines"]) for m in mcps_list)
        
        table.add_row(
            publisher,
            str(len(mcps_list)),
            str(total_installs),
            mcp_names
        )
    
    console.print(table)


def _print_aggregate_summary(mcps: dict, configs: list[CollectedConfig]):
    """Print aggregate summary"""
    console.print("\n[bold]Summary[/bold]")
    console.print(f"  Machines reporting: {len(configs)}")
    console.print(f"  Unique MCPs: {len(mcps)}")
    
    total_installs = sum(len(m["machines"]) for m in mcps.values())
    console.print(f"  Total MCP installs: {total_installs}")
    
    # Risk summary
    all_risks = set()
    for data in mcps.values():
        all_risks.update(data["risk_flags"])
    
    if all_risks:
        console.print(f"\n  [yellow]Risk flags found: {', '.join(all_risks)}[/yellow]")
    
    # Unknown sources
    unknown = [name for name, data in mcps.items() 
               if not data["source"].startswith("@") and "github.com" not in data["source"]]
    if unknown:
        console.print(f"\n  [yellow]⚠ {len(unknown)} MCP(s) from unknown sources[/yellow]")


def _truncate(s: str, length: int) -> str:
    """Truncate string with ellipsis"""
    if len(s) <= length:
        return s
    return s[:length-3] + "..."
