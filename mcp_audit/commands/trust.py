"""
Trust command - Check trustworthiness of MCP sources
"""

import typer
from rich.console import Console
from rich.table import Table
from pathlib import Path
from typing import Optional
import json
import urllib.request
import urllib.error
from datetime import datetime

from mcp_audit.models import ScanResult

app = typer.Typer(help="Check trustworthiness of MCP sources")
console = Console()


# Verified publishers (high trust by default)
VERIFIED_PUBLISHERS = [
    "@anthropic/",
    "@modelcontextprotocol/",
    "@openai/",
]

# Known safe packages
KNOWN_SAFE = [
    "@anthropic/mcp-server-filesystem",
    "@anthropic/mcp-server-fetch",
    "@modelcontextprotocol/server-slack",
    "@modelcontextprotocol/server-github",
    "@modelcontextprotocol/server-postgres",
]


@app.callback(invoke_without_command=True)
def trust(
    ctx: typer.Context,
    input_file: Path = typer.Option(
        None, "--input", "-i", help="JSON file from scan results"
    ),
    source: Optional[str] = typer.Option(
        None, "--source", "-s", help="Check a specific MCP source (npm package or GitHub URL)"
    ),
    format: str = typer.Option(
        "table", "--format", "-f", help="Output format: table, json, markdown"
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Write output to file"
    ),
):
    """
    Check trustworthiness of MCP sources.

    Examples:
        mcp-audit trust --input inventory.json
        mcp-audit trust --source @anthropic/mcp-server-filesystem
        mcp-audit trust --source https://github.com/anthropics/mcp-server
    """
    if ctx.invoked_subcommand is not None:
        return

    console.print("\n[bold blue]MCP Audit - Trust Check[/bold blue]\n")

    results = []

    if source:
        # Check single source
        trust_info = check_source_trust(source)
        results.append(trust_info)
    elif input_file:
        # Check all sources from inventory
        if not input_file.exists():
            console.print(f"[red]Error: File not found: {input_file}[/red]")
            raise typer.Exit(1)

        try:
            data = json.loads(input_file.read_text())
            mcps = data.get("mcps", [])
        except (json.JSONDecodeError, IOError) as e:
            console.print(f"[red]Error reading file: {e}[/red]")
            raise typer.Exit(1)

        console.print(f"Checking trust for {len(mcps)} MCP(s)...\n")

        with console.status("[bold green]Checking trust scores..."):
            for mcp in mcps:
                source_name = mcp.get("source", mcp.get("name", "unknown"))
                trust_info = check_source_trust(source_name)
                trust_info["name"] = mcp.get("name", source_name)
                results.append(trust_info)
    else:
        console.print("[yellow]Please provide --input or --source[/yellow]")
        console.print("\nExamples:")
        console.print("  mcp-audit trust --input inventory.json")
        console.print("  mcp-audit trust --source @anthropic/mcp-server-filesystem")
        raise typer.Exit(1)

    # Output results
    if format == "table":
        _print_trust_table(results)
    elif format == "json":
        output_data = {
            "check_time": datetime.now().isoformat(),
            "results": results,
        }
        formatted = json.dumps(output_data, indent=2)
        if output:
            output.write_text(formatted)
            console.print(f"\n[green]Results written to {output}[/green]")
        else:
            console.print(formatted)
    elif format == "markdown":
        formatted = _to_markdown(results)
        if output:
            output.write_text(formatted)
            console.print(f"\n[green]Results written to {output}[/green]")
        else:
            console.print(formatted)

    # Summary
    _print_trust_summary(results)


def check_source_trust(source: str) -> dict:
    """Check trust score for a source"""
    result = {
        "source": source,
        "score": "UNKNOWN",
        "reasons": [],
        "npm_info": None,
        "github_info": None,
    }

    # Check verified publishers first
    for publisher in VERIFIED_PUBLISHERS:
        if source.startswith(publisher):
            result["score"] = "HIGH"
            result["reasons"].append(f"Verified publisher: {publisher.rstrip('/')}")
            break

    # Check known safe packages
    if source in KNOWN_SAFE:
        result["score"] = "HIGH"
        result["reasons"].append("Known safe package")

    # Check npm registry for npm packages
    if source.startswith("@") or (not source.startswith("http") and not source.startswith("/")):
        npm_info = _check_npm(source)
        if npm_info:
            result["npm_info"] = npm_info
            _evaluate_npm_trust(result, npm_info)

    # Check GitHub for GitHub URLs
    if "github.com" in source:
        github_info = _check_github(source)
        if github_info:
            result["github_info"] = github_info
            _evaluate_github_trust(result, github_info)

    # If still unknown, mark as low trust
    if result["score"] == "UNKNOWN":
        result["score"] = "LOW"
        result["reasons"].append("Unable to verify source")

    return result


def _check_npm(package: str) -> Optional[dict]:
    """Check npm registry for package info"""
    try:
        # Clean package name
        pkg_name = package.split("@")
        if package.startswith("@"):
            pkg_name = "@" + pkg_name[1]
        else:
            pkg_name = pkg_name[0]

        url = f"https://registry.npmjs.org/{pkg_name}"
        req = urllib.request.Request(url, headers={"Accept": "application/json"})

        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode())

        # Extract relevant info
        latest = data.get("dist-tags", {}).get("latest", "")
        latest_info = data.get("versions", {}).get(latest, {})
        time_info = data.get("time", {})

        return {
            "name": data.get("name"),
            "description": data.get("description", ""),
            "latest_version": latest,
            "last_published": time_info.get(latest, ""),
            "created": time_info.get("created", ""),
            "maintainers": [m.get("name", "") for m in data.get("maintainers", [])],
            "repository": data.get("repository", {}).get("url", ""),
            "homepage": data.get("homepage", ""),
            "license": latest_info.get("license", data.get("license", "")),
            "weekly_downloads": _get_npm_downloads(pkg_name),
        }
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, KeyError):
        return None


def _get_npm_downloads(package: str) -> Optional[int]:
    """Get weekly download count from npm"""
    try:
        url = f"https://api.npmjs.org/downloads/point/last-week/{package}"
        req = urllib.request.Request(url)

        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode())

        return data.get("downloads", 0)
    except:
        return None


def _check_github(url: str) -> Optional[dict]:
    """Check GitHub for repository info"""
    try:
        # Extract owner/repo from URL
        parts = url.replace("https://", "").replace("http://", "").replace("github.com/", "").split("/")
        if len(parts) < 2:
            return None

        owner = parts[0]
        repo = parts[1].replace(".git", "")

        api_url = f"https://api.github.com/repos/{owner}/{repo}"
        req = urllib.request.Request(api_url, headers={
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "mcp-audit",
        })

        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode())

        return {
            "full_name": data.get("full_name"),
            "description": data.get("description", ""),
            "stars": data.get("stargazers_count", 0),
            "forks": data.get("forks_count", 0),
            "open_issues": data.get("open_issues_count", 0),
            "created_at": data.get("created_at", ""),
            "updated_at": data.get("updated_at", ""),
            "pushed_at": data.get("pushed_at", ""),
            "license": data.get("license", {}).get("spdx_id", "") if data.get("license") else "",
            "owner_type": data.get("owner", {}).get("type", ""),
            "archived": data.get("archived", False),
        }
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, KeyError):
        return None


def _evaluate_npm_trust(result: dict, npm_info: dict):
    """Evaluate trust based on npm info"""
    score_factors = []

    # Check download count
    downloads = npm_info.get("weekly_downloads", 0)
    if downloads:
        if downloads > 100000:
            score_factors.append(("HIGH", f"High download count: {downloads:,}/week"))
        elif downloads > 10000:
            score_factors.append(("MEDIUM", f"Moderate downloads: {downloads:,}/week"))
        elif downloads > 1000:
            score_factors.append(("MEDIUM", f"Some downloads: {downloads:,}/week"))
        else:
            score_factors.append(("LOW", f"Low downloads: {downloads:,}/week"))

    # Check last published date
    last_published = npm_info.get("last_published", "")
    if last_published:
        try:
            pub_date = datetime.fromisoformat(last_published.replace("Z", "+00:00"))
            days_ago = (datetime.now(pub_date.tzinfo) - pub_date).days
            if days_ago < 90:
                score_factors.append(("HIGH", f"Recently updated ({days_ago} days ago)"))
            elif days_ago < 365:
                score_factors.append(("MEDIUM", f"Updated within a year"))
            else:
                score_factors.append(("LOW", f"Not updated in {days_ago} days"))
        except:
            pass

    # Check license
    license_val = npm_info.get("license", "")
    if license_val:
        if license_val in ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC"]:
            score_factors.append(("HIGH", f"Standard license: {license_val}"))
        else:
            score_factors.append(("MEDIUM", f"License: {license_val}"))

    # Determine overall score
    if result["score"] != "HIGH":  # Don't downgrade verified publishers
        if all(f[0] == "HIGH" for f in score_factors):
            result["score"] = "HIGH"
        elif any(f[0] == "LOW" for f in score_factors):
            result["score"] = "LOW"
        else:
            result["score"] = "MEDIUM"

    for factor in score_factors:
        result["reasons"].append(factor[1])


def _evaluate_github_trust(result: dict, github_info: dict):
    """Evaluate trust based on GitHub info"""
    score_factors = []

    # Check if archived
    if github_info.get("archived"):
        score_factors.append(("LOW", "Repository is archived"))

    # Check stars
    stars = github_info.get("stars", 0)
    if stars > 1000:
        score_factors.append(("HIGH", f"High stars: {stars:,}"))
    elif stars > 100:
        score_factors.append(("MEDIUM", f"Moderate stars: {stars:,}"))
    else:
        score_factors.append(("LOW", f"Low stars: {stars}"))

    # Check last push
    pushed_at = github_info.get("pushed_at", "")
    if pushed_at:
        try:
            push_date = datetime.fromisoformat(pushed_at.replace("Z", "+00:00"))
            days_ago = (datetime.now(push_date.tzinfo) - push_date).days
            if days_ago < 90:
                score_factors.append(("HIGH", f"Active development ({days_ago} days ago)"))
            elif days_ago < 365:
                score_factors.append(("MEDIUM", f"Some activity within a year"))
            else:
                score_factors.append(("LOW", f"Inactive for {days_ago} days"))
        except:
            pass

    # Check owner type (Organization vs User)
    if github_info.get("owner_type") == "Organization":
        score_factors.append(("MEDIUM", "Owned by organization"))

    # Determine overall score
    if result["score"] not in ["HIGH"]:
        if all(f[0] == "HIGH" for f in score_factors):
            result["score"] = "HIGH"
        elif any(f[0] == "LOW" for f in score_factors):
            result["score"] = "LOW"
        else:
            result["score"] = "MEDIUM"

    for factor in score_factors:
        result["reasons"].append(factor[1])


def _print_trust_table(results: list):
    """Print trust results as a table"""
    table = Table(title="MCP Trust Check Results", show_header=True, header_style="bold cyan")

    table.add_column("MCP", style="white")
    table.add_column("Source", style="dim")
    table.add_column("Trust Score", style="bold")
    table.add_column("Reasons", style="dim")

    for r in results:
        name = r.get("name", r.get("source", ""))
        source = r.get("source", "")
        score = r.get("score", "UNKNOWN")
        reasons = r.get("reasons", [])

        # Color code score
        if score == "HIGH":
            score_display = f"[green]{score}[/green]"
        elif score == "MEDIUM":
            score_display = f"[yellow]{score}[/yellow]"
        else:
            score_display = f"[red]{score}[/red]"

        reasons_display = "\n".join(reasons[:3])  # Show first 3 reasons
        if len(reasons) > 3:
            reasons_display += f"\n(+{len(reasons) - 3} more)"

        table.add_row(name, _truncate(source, 35), score_display, reasons_display)

    console.print(table)


def _print_trust_summary(results: list):
    """Print summary of trust scores"""
    console.print("\n[bold]Summary[/bold]")

    high = sum(1 for r in results if r.get("score") == "HIGH")
    medium = sum(1 for r in results if r.get("score") == "MEDIUM")
    low = sum(1 for r in results if r.get("score") == "LOW")
    unknown = sum(1 for r in results if r.get("score") == "UNKNOWN")

    console.print(f"  [green]HIGH[/green]: {high}")
    console.print(f"  [yellow]MEDIUM[/yellow]: {medium}")
    console.print(f"  [red]LOW[/red]: {low}")
    if unknown:
        console.print(f"  [dim]UNKNOWN[/dim]: {unknown}")

    if low > 0:
        console.print(f"\n[yellow]Warning: {low} MCP(s) have LOW trust scores[/yellow]")


def _to_markdown(results: list) -> str:
    """Convert results to markdown"""
    lines = [
        "# MCP Trust Check Report",
        "",
        f"**Check Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"**Total MCPs Checked:** {len(results)}",
        "",
        "## Trust Scores",
        "",
        "| MCP | Source | Trust Score | Reasons |",
        "|-----|--------|-------------|---------|",
    ]

    for r in results:
        name = r.get("name", r.get("source", ""))
        source = r.get("source", "")
        score = r.get("score", "UNKNOWN")
        reasons = "; ".join(r.get("reasons", [])[:3])
        lines.append(f"| {name} | {source[:40]} | **{score}** | {reasons} |")

    return "\n".join(lines)


def _truncate(s: str, length: int) -> str:
    """Truncate string with ellipsis"""
    if len(s) <= length:
        return s
    return s[:length-3] + "..."
