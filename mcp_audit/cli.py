"""
MCP Audit - Discover and audit MCP configurations
"""

import typer
from rich.console import Console

from mcp_audit.commands import scan, analyze, trust, policy, registry

app = typer.Typer(
    name="mcp-audit",
    help="Discover and audit MCP (Model Context Protocol) configurations across your organization",
    add_completion=False,
)

console = Console()

# Register commands
app.add_typer(scan.app, name="scan")
app.add_typer(analyze.app, name="analyze")
app.add_typer(trust.app, name="trust")
app.add_typer(policy.app, name="policy")
app.add_typer(registry.app, name="registry")


@app.callback()
def main():
    """
    MCP Audit - Security visibility for Model Context Protocol

    Discover what MCPs exist in your environment, assess their risk,
    and validate against security policies.
    """
    pass


@app.command()
def version():
    """Show version information"""
    from mcp_audit import __version__
    console.print(f"mcp-audit version {__version__}")


if __name__ == "__main__":
    app()
