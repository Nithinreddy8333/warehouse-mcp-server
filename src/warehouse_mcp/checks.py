"""Data quality checks an agent can run before trusting a table.

Checks are declared in config/checks.yaml. They run inside the role's workspace, so a role
can only check tables it can read, and a check on a masked column sees the masked values.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field

from .guard import QueryDenied
from .models_util import IDENTIFIER
from .workspace import Workspace, lit, q


class Check(BaseModel):
    table: str
    kind: Literal["not_null", "unique", "min_rows", "accepted_values", "max_age_days", "non_negative"]
    column: str | None = None
    value: float | None = None
    values: list[str] = Field(default_factory=list)

    @property
    def label(self) -> str:
        target = f"{self.table}.{self.column}" if self.column else self.table
        return f"{self.kind}({target})"


def load_checks(path: Path) -> list[Check]:
    if not path.exists():
        return []
    return [Check.model_validate(item) for item in yaml.safe_load(path.read_text(encoding="utf-8")) or []]


def _failing_rows_sql(check: Check) -> str:
    schema, table = check.table.split(".", 1)
    rel = f"{q(schema)}.{q(table)}"
    col = q(check.column) if check.column else None
    if check.kind == "not_null":
        return f"select count(*) from {rel} where {col} is null"
    if check.kind == "unique":
        return f"select count(*) - count(distinct {col}) from {rel} where {col} is not null"
    if check.kind == "non_negative":
        return f"select count(*) from {rel} where {col} < 0"
    if check.kind == "accepted_values":
        allowed = ", ".join(lit(v) for v in check.values)
        return f"select count(*) from {rel} where {col} is not null and cast({col} as varchar) not in ({allowed})"
    if check.kind == "min_rows":
        return f"select case when count(*) >= {int(check.value or 1)} then 0 else 1 end from {rel}"
    if check.kind == "max_age_days":
        return (f"select case when date_diff('day', max(cast({col} as date)), current_date) <= "
                f"{int(check.value or 1)} then 0 else 1 end from {rel}")
    raise ValueError(check.kind)


def run_checks(workspace: Workspace, checks: list[Check], table: str | None = None) -> list[dict]:
    results = []
    for check in checks:
        if check.table not in workspace.tables or (table and check.table != table):
            continue
        info = workspace.tables[check.table]
        if check.column and (not IDENTIFIER.match(check.column) or check.column not in {c.name for c in info.columns}):
            results.append({"check": check.label, "status": "error", "detail": "unknown column"})
            continue
        try:
            failing = workspace.execute(_failing_rows_sql(check), checked=True).rows[0]
            count = next(iter(failing.values())) or 0
            results.append({"check": check.label, "status": "pass" if count == 0 else "fail",
                            "failing": int(count)})
        except QueryDenied as err:
            results.append({"check": check.label, "status": "error", "detail": str(err)})
    return results
