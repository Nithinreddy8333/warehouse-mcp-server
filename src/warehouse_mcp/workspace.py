"""The role's private view of the warehouse, and the only place queries are executed.

When the server starts, a throwaway in-memory database is built for the configured role:

  * each table the role may read is copied in, with masked columns already replaced and
    row filters already applied
  * the warehouse file is then detached
  * file, network and extension access are switched off and the configuration is locked

After that, data the role is not allowed to see is simply not there. A query cannot leak
what the session does not contain, no matter how it is written, so masking does not depend
on parsing or rewriting the user's SQL correctly.

Trade-off: the copy is a snapshot. It is rebuilt when the warehouse file changes, which is
fine for a file-based warehouse of modest size. On Snowflake, BigQuery or Postgres the same
idea is expressed with the platform's own roles, masking policies and row access policies,
with one service account per MCP role, and no copy.
"""

from __future__ import annotations

import datetime as dt
import decimal
import threading
import time
from dataclasses import dataclass, field

import duckdb

from .config import Settings
from .guard import CheckedQuery, QueryDenied, check_query
from .policy import MaskKind, Role


def q(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


def lit(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def mask_expression(column: str, kind: MaskKind, salt: str) -> str:
    c = q(column)
    if kind == "null":
        return "cast(null as varchar)"
    if kind == "redact":
        return f"case when {c} is null then null else '***' end"
    if kind == "hash":
        # Salted, so common values cannot be recovered by hashing a dictionary of guesses.
        return f"'h_' || substr(sha256({lit(salt)} || cast({c} as varchar)), 1, 12)"
    if kind == "email_domain":
        return f"regexp_replace(cast({c} as varchar), '^[^@]*', '***')"
    raise ValueError(f"unknown mask '{kind}'")


@dataclass
class ColumnInfo:
    name: str
    type: str
    mask: str | None = None


@dataclass
class TableInfo:
    name: str  # schema.table
    rows: int
    columns: list[ColumnInfo] = field(default_factory=list)
    row_filtered: bool = False


@dataclass
class QueryResult:
    columns: list[str]
    rows: list[dict]
    truncated: bool
    elapsed_ms: int
    tables: list[str]


def _json_safe(value, max_chars: int):
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, decimal.Decimal):
        return float(value)
    if isinstance(value, dt.datetime | dt.date | dt.time):
        return value.isoformat()
    if isinstance(value, bytes | bytearray):
        return f"<{len(value)} bytes>"
    text = str(value)
    return text if len(text) <= max_chars else text[:max_chars] + "…"


class Workspace:
    def __init__(self, settings: Settings, role: Role):
        self.settings, self.role = settings, role
        self._lock = threading.Lock()
        self._con: duckdb.DuckDBPyConnection | None = None
        self._built_from_mtime = 0.0
        self.tables: dict[str, TableInfo] = {}
        self.build()

    # ---- building the snapshot ---------------------------------------------------------
    def build(self) -> None:
        path = self.settings.warehouse_path
        if not path.exists():
            raise FileNotFoundError(f"Warehouse not found at {path}. Run `warehouse-mcp build-sample` first.")
        con = duckdb.connect(":memory:")
        con.execute(f"attach {lit(str(path))} as src (read_only)")
        found = con.execute(
            "select table_schema, table_name from information_schema.tables "
            "where table_catalog = 'src' and table_type = 'BASE TABLE' order by 1, 2"
        ).fetchall()
        tables: dict[str, TableInfo] = {}
        for schema, table in found:
            name = f"{schema}.{table}"
            if not self.role.can_read(name):
                continue
            columns = con.execute(
                "select column_name, data_type from information_schema.columns "
                "where table_catalog = 'src' and table_schema = ? and table_name = ? order by ordinal_position",
                [schema, table],
            ).fetchall()
            selects, infos = [], []
            for column, data_type in columns:
                kind = self.role.mask_for(name, column)
                if kind:
                    selects.append(f"{mask_expression(column, kind, self.settings.mask_salt)} as {q(column)}")
                    infos.append(ColumnInfo(column, "VARCHAR", kind))
                else:
                    selects.append(q(column))
                    infos.append(ColumnInfo(column, data_type))
            row_filter = self.role.row_filters.get(name)
            where = f" where {row_filter}" if row_filter else ""
            con.execute(f"create schema if not exists {q(schema)}")
            con.execute(
                f"create table {q(schema)}.{q(table)} as "
                f"select {', '.join(selects)} from src.{q(schema)}.{q(table)}{where}"
            )
            rows = con.execute(f"select count(*) from {q(schema)}.{q(table)}").fetchone()[0]
            tables[name] = TableInfo(name, rows, infos, bool(row_filter))
        con.execute("detach src")
        # From here on the session cannot reach anything outside itself, and cannot undo that.
        con.execute("set enable_external_access = false")
        con.execute("set autoinstall_known_extensions = false")
        con.execute("set autoload_known_extensions = false")
        con.execute("set lock_configuration = true")
        with self._lock:
            old, self._con = self._con, con
            self.tables = tables
            self._built_from_mtime = path.stat().st_mtime
        if old is not None:
            old.close()

    def refresh_if_stale(self) -> bool:
        if self.settings.warehouse_path.stat().st_mtime != self._built_from_mtime:
            self.build()
            return True
        return False

    def close(self) -> None:
        if self._con is not None:
            self._con.close()
            self._con = None

    # ---- running queries ---------------------------------------------------------------
    def check(self, sql: str) -> CheckedQuery:
        return check_query(sql, set(self.tables), self.role.limits.max_query_chars)

    def execute(self, sql: str, max_rows: int | None = None, checked: bool = False) -> QueryResult:
        """Run one read-only query under the role's limits.

        `checked=True` is for SQL built by this server itself (never for client input).
        """
        limits = self.role.limits
        tables: list[str] = []
        if not checked:
            verdict = self.check(sql)
            sql, tables = verdict.sql, verdict.tables
        cap = min(max_rows or limits.max_rows, limits.max_rows)
        # The execution path itself accepts exactly one statement, whether or not the static
        # guard ran. Otherwise "commit; delete ..." would end the read-only transaction and
        # then write outside it.
        try:
            statements = duckdb.extract_statements(sql)
        except duckdb.Error as err:
            raise QueryDenied("syntax", f"The query does not parse: {str(err)[:300]}") from err
        if len(statements) != 1:
            raise QueryDenied("multiple_statements", "Exactly one statement is allowed per call.")
        cursor = self._con.cursor()
        timed_out = threading.Event()

        def stop() -> None:
            timed_out.set()
            cursor.interrupt()

        timer = threading.Timer(limits.timeout_seconds, stop)
        started = time.perf_counter()
        try:
            # Enforced by the engine: nothing in this transaction can write.
            cursor.execute("begin transaction read only")
            timer.start()
            cursor.execute(statements[0])
            columns = [d[0] for d in cursor.description or []]
            fetched = cursor.fetchmany(cap + 1)
        except duckdb.InterruptException as err:
            raise QueryDenied("timeout", f"The query ran longer than {limits.timeout_seconds:g} seconds.") from err
        except duckdb.Error as err:
            if timed_out.is_set():
                raise QueryDenied("timeout", f"The query ran longer than {limits.timeout_seconds:g} seconds.") from err
            code = "read_only" if "read-only" in str(err) or "read only" in str(err) else "sql_error"
            raise QueryDenied(code, str(err).split("\n")[0][:400]) from err
        finally:
            timer.cancel()
            try:
                cursor.execute("rollback")
            except duckdb.Error:
                pass
            cursor.close()
        rows = [
            {c: _json_safe(v, limits.max_cell_chars) for c, v in zip(columns, row, strict=True)}
            for row in fetched[:cap]
        ]
        return QueryResult(columns, rows, len(fetched) > cap, int((time.perf_counter() - started) * 1000), tables)
