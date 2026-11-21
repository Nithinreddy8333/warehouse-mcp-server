"""The MCP server: six read-only tools and two resources over the role's workspace.

Every tool call, allowed or denied, is written to the audit log. Denials are returned to the
agent as tool errors with a plain reason, so it can correct itself instead of guessing.
"""

from __future__ import annotations

import functools
import json
import time
from collections.abc import Callable

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

from .audit import AuditLog
from .checks import load_checks, run_checks
from .config import Settings
from .guard import QueryDenied
from .lineage import lineage, load_models
from .models_util import TABLE_NAME
from .policy import load_policy
from .workspace import Workspace, q

READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False)

INSTRUCTIONS = """\
Read-only access to a data warehouse under an access policy.
Start with `whoami` to see your role, limits and which columns are masked, then `list_tables` \
and `describe_table` before writing SQL. Use `run_query` with DuckDB SQL: one SELECT per call, \
tables written as schema.table. Results are capped; aggregate in SQL instead of fetching rows. \
Masked columns contain placeholders or hashes, never real values: do not present them as real \
data. A denied call explains why; do not retry it in a different form."""


def build_server(settings: Settings | None = None) -> MCPServer:
    settings = settings or Settings()
    role = load_policy(settings.policy_path).role(settings.role)
    workspace = Workspace(settings, role)
    models = load_models(settings.models_dir)
    checks = load_checks(settings.checks_path)
    audit = AuditLog(settings.audit_log, role.name)
    server = MCPServer("warehouse", instructions=INSTRUCTIONS, version="0.1.0", log_level="WARNING")
    # Exposed for tests and the red-team suite.
    server.workspace, server.audit = workspace, audit  # type: ignore[attr-defined]

    def audited(fn: Callable) -> Callable:
        """Refresh the snapshot if needed, record the call, and turn denials into tool errors."""

        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            started = time.perf_counter()
            details = {k: (v if len(str(v)) <= 2000 else str(v)[:2000] + "…") for k, v in kwargs.items()}
            try:
                workspace.refresh_if_stale()
                result, extra = fn(*args, **kwargs)
            except QueryDenied as err:
                audit.record(fn.__name__, "denied", reason=err.code, message=str(err), **details)
                raise ToolError(f"Denied ({err.code}): {err}") from err
            except Exception as err:
                audit.record(fn.__name__, "error", message=str(err)[:300], **details)
                raise
            audit.record(fn.__name__, "allowed", ms=int((time.perf_counter() - started) * 1000), **details, **extra)
            return result

        return wrapper

    def require_table(table: str) -> str:
        table = table.strip().lower()
        if not TABLE_NAME.match(table) or table not in workspace.tables:
            raise QueryDenied("table_not_available", f"The table '{table[:80]}' is not available to this role.")
        return table

    @server.tool(annotations=READ_ONLY)
    @audited
    def whoami() -> dict:
        """Show the role this connection runs as: its purpose, limits, readable tables and masked columns."""
        masked = sorted(f"{t.name}.{c.name} ({c.mask})" for t in workspace.tables.values()
                        for c in t.columns if c.mask)
        return {
            "role": role.name,
            "description": role.description,
            "limits": role.limits.model_dump(),
            "readable_tables": sorted(workspace.tables),
            "masked_columns": masked,
            "row_filtered_tables": sorted(t.name for t in workspace.tables.values() if t.row_filtered),
        }, {}

    @server.tool(annotations=READ_ONLY)
    @audited
    def list_tables() -> dict:
        """List the tables this role can read, with row counts and a one-line description."""
        return {"tables": [
            {"table": t.name, "rows": t.rows, "columns": len(t.columns),
             "description": models[t.name].description if t.name in models else "Source table."}
            for t in sorted(workspace.tables.values(), key=lambda t: t.name)
        ]}, {}

    @server.tool(annotations=READ_ONLY)
    @audited
    def describe_table(table: str, sample_rows: int = 3) -> dict:
        """Show a table's columns, types and masking, with a few sample rows. `table` is schema.table."""
        name = require_table(table)
        info = workspace.tables[name]
        schema, rel = name.split(".", 1)
        sample = workspace.execute(f"select * from {q(schema)}.{q(rel)} limit {max(0, min(int(sample_rows), 10))}",
                                   checked=True)
        return {
            "table": name,
            "rows": info.rows,
            "description": models[name].description if name in models else "Source table.",
            "columns": [{"name": c.name, "type": c.type, "masked": c.mask} for c in info.columns],
            "row_filtered": info.row_filtered,
            "sample": sample.rows,
        }, {"tables": [name]}

    @server.tool(annotations=READ_ONLY)
    @audited
    def run_query(sql: str, max_rows: int = 50) -> dict:
        """Run one read-only DuckDB SELECT and return rows as JSON. Results are capped at the role's row limit."""
        result = workspace.execute(sql, max_rows=max(1, int(max_rows)))
        return {
            "columns": result.columns,
            "rows": result.rows,
            "row_count": len(result.rows),
            "truncated": result.truncated,
            "elapsed_ms": result.elapsed_ms,
        }, {"tables": result.tables, "rows": len(result.rows), "truncated": result.truncated}

    @server.tool(annotations=READ_ONLY)
    @audited
    def get_lineage(table: str) -> dict:
        """Show which tables a table is built from (upstream) and which tables depend on it (downstream)."""
        name = require_table(table)
        return lineage(name, models, set(workspace.tables)), {"tables": [name]}

    @server.tool(annotations=READ_ONLY)
    @audited
    def run_quality_checks(table: str | None = None) -> dict:
        """Run the declared data quality checks, for one table or for every table this role can read."""
        name = require_table(table) if table else None
        results = run_checks(workspace, checks, name)
        return {
            "passed": sum(r["status"] == "pass" for r in results),
            "failed": sum(r["status"] == "fail" for r in results),
            "results": results,
        }, {"tables": [name] if name else []}

    @server.resource("warehouse://catalog", mime_type="application/json",
                     description="Every table and column this role can read, as JSON.")
    def catalog() -> str:
        return json.dumps({
            t.name: {"rows": t.rows, "columns": {c.name: {"type": c.type, "masked": c.mask} for c in t.columns}}
            for t in workspace.tables.values()
        }, indent=2)

    @server.resource("warehouse://policy", mime_type="application/json",
                     description="The access policy in effect for this connection.")
    def policy() -> str:
        return json.dumps({"role": role.name, "description": role.description,
                           "limits": role.limits.model_dump(), "tables": role.tables, "masks": role.masks,
                           "row_filtered_tables": sorted(role.row_filters)}, indent=2)

    return server
