"""Static checks on a query before it is allowed to run.

These checks are one layer of three. They exist to reject bad queries early with a clear
reason and to record which tables a query touches. They are NOT what the security of the
server rests on. That is done by the engine itself (see workspace.py):

  1. the session only contains data the role may see, already masked
  2. file, network and configuration access are switched off and locked
  3. every query runs inside a READ ONLY transaction

A static check can be wrong; the three properties above hold even when it is.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import duckdb
import sqlglot
from sqlglot import exp

WRITE_NODES = (
    exp.Insert, exp.Update, exp.Delete, exp.Merge, exp.Create, exp.Drop, exp.Alter, exp.TruncateTable,
    exp.Command, exp.Copy, exp.Attach, exp.Detach, exp.Pragma, exp.Set, exp.Use, exp.Transaction,
    exp.Commit, exp.Rollback, exp.Describe, exp.Show, exp.Summarize,
)
# Table functions that only generate values. Everything else that appears in FROM as a
# function call (file readers, query(), query_table(), metadata functions ...) is refused.
SAFE_TABLE_FUNCTIONS = (exp.GenerateSeries, exp.Unnest, exp.Explode)


class QueryDenied(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass
class CheckedQuery:
    sql: str
    tables: list[str] = field(default_factory=list)


def check_query(sql: str, visible_tables: set[str], max_chars: int = 10_000) -> CheckedQuery:
    """Return the query and the tables it reads, or raise QueryDenied."""
    sql = sql.strip().rstrip(";").strip()
    if not sql:
        raise QueryDenied("empty", "The query is empty.")
    if len(sql) > max_chars:
        raise QueryDenied("too_long", f"The query is longer than {max_chars} characters.")

    # 1. The engine's own parser decides how many statements there are and what kind.
    try:
        statements = duckdb.extract_statements(sql)
    except duckdb.Error as err:
        raise QueryDenied("syntax", f"The query does not parse: {str(err)[:300]}") from err
    if len(statements) != 1:
        raise QueryDenied("multiple_statements", "Exactly one statement is allowed per call.")
    if statements[0].type != duckdb.StatementType.SELECT:
        kind = str(statements[0].type).split(".")[-1]
        raise QueryDenied("not_select", f"Only SELECT queries are allowed; this is a {kind} statement.")

    # 2. A second parser looks inside the statement. If it cannot read the query, fail closed.
    try:
        tree = sqlglot.parse_one(sql, read="duckdb")
    except sqlglot.errors.SqlglotError as err:
        raise QueryDenied("unanalysable", "The query could not be analysed, so it was not run.") from err
    for node in tree.walk():
        if isinstance(node, WRITE_NODES):
            raise QueryDenied(
                "write_operation",
                f"{type(node).__name__.upper()} is not allowed. This connection is read-only.",
            )

    # 3. Every table must be one the role can see. Table functions must be on the short safe list.
    cte_names = {cte.alias_or_name.lower() for cte in tree.find_all(exp.CTE)}
    tables: set[str] = set()
    for table in tree.find_all(exp.Table):
        if not isinstance(table.this, exp.Identifier):
            if isinstance(table.this, SAFE_TABLE_FUNCTIONS):
                continue
            name = table.this.name if isinstance(table.this, exp.Anonymous) else table.this.sql_name()
            raise QueryDenied("table_function", f"The table function {name.lower()}() is not allowed.")
        name = table.name.lower()
        if not table.db and name in cte_names:
            continue
        if table.catalog:
            raise QueryDenied("catalog_qualifier", "Refer to tables as schema.table, without a database name.")
        qualified = f"{table.db.lower()}.{name}" if table.db else name
        if qualified not in visible_tables:
            # Deliberately the same message for "does not exist" and "exists but is forbidden".
            raise QueryDenied("table_not_available", f"The table '{qualified}' is not available to this role.")
        tables.add(qualified)
    return CheckedQuery(sql=sql, tables=sorted(tables))
