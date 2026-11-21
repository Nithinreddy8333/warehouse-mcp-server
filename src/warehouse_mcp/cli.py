"""Command line interface: `warehouse-mcp --help`."""

from __future__ import annotations

import json
import sys

import typer
from rich.console import Console
from rich.table import Table

from .config import Settings
from .guard import QueryDenied
from .policy import load_policy
from .sample import build_sample
from .workspace import Workspace

app = typer.Typer(add_completion=False, help="Governed MCP server for data warehouse access by AI agents.")
# Everything human-readable goes to stderr: on the stdio transport, stdout belongs to the protocol.
console = Console(stderr=True)


@app.command("build-sample")
def build_sample_cmd() -> None:
    """Create the sample DuckDB warehouse (raw tables, SQL models, and a restricted hr schema)."""
    settings = Settings()
    for table, rows in build_sample(settings.warehouse_path, settings.models_dir).items():
        console.print(f"{table}: {rows} rows")


@app.command()
def serve(
    role: str = typer.Option(None, help="Role from the policy file (default: MCP_ROLE or 'analyst')"),
    transport: str = typer.Option("stdio", help="stdio or streamable-http"),
) -> None:
    """Start the MCP server for one role."""
    from .server import build_server

    settings = Settings()
    if role:
        settings.role = role
    build_server(settings).run(transport=transport)  # type: ignore[arg-type]


@app.command()
def roles() -> None:
    """Show what each role can see: tables, row counts and masked columns."""
    settings = Settings()
    policy = load_policy(settings.policy_path)
    for name, role in policy.roles.items():
        workspace = Workspace(settings, role)
        table = Table(title=f"{name}: {role.description}")
        for heading in ("table", "rows", "masked columns"):
            table.add_column(heading)
        for info in sorted(workspace.tables.values(), key=lambda t: t.name):
            masked = ", ".join(f"{c.name} ({c.mask})" for c in info.columns if c.mask)
            table.add_row(info.name + (" (row filter)" if info.row_filtered else ""), str(info.rows), masked)
        console.print(table)
        workspace.close()


@app.command()
def query(sql: str, role: str = typer.Option(None), max_rows: int = 20) -> None:
    """Run one query as a role, exactly as the MCP tool would (for debugging policies)."""
    settings = Settings()
    workspace = Workspace(settings, load_policy(settings.policy_path).role(role or settings.role))
    try:
        result = workspace.execute(sql, max_rows=max_rows)
    except QueryDenied as err:
        console.print(f"[red]Denied ({err.code}):[/red] {err}")
        raise typer.Exit(code=1) from err
    finally:
        workspace.close()
    json.dump({"columns": result.columns, "rows": result.rows, "truncated": result.truncated}, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    app()
