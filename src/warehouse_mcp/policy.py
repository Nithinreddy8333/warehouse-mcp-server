"""Access policy: which tables a role may read, which columns are masked, and its limits.

Deny by default. A role sees a table only if a pattern in its `tables` list matches it.
Patterns are shell-style globs on `schema.table` (tables) and `schema.table.column` (masks).
"""

from __future__ import annotations

from fnmatch import fnmatchcase
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, model_validator

MaskKind = Literal["redact", "hash", "null", "email_domain"]


class Limits(BaseModel):
    max_rows: int = Field(default=200, ge=1, le=10_000)
    timeout_seconds: float = Field(default=5.0, gt=0, le=120)
    max_cell_chars: int = Field(default=500, ge=10)
    max_query_chars: int = Field(default=10_000, ge=100)


class Role(BaseModel):
    name: str = ""
    description: str = ""
    tables: list[str] = Field(default_factory=list)
    masks: dict[str, MaskKind] = Field(default_factory=dict)
    row_filters: dict[str, str] = Field(default_factory=dict)
    limits: Limits = Field(default_factory=Limits)

    def can_read(self, table: str) -> bool:
        return any(fnmatchcase(table, pattern) for pattern in self.tables)

    def mask_for(self, table: str, column: str) -> MaskKind | None:
        """The first matching mask wins, so list specific patterns before general ones."""
        full = f"{table}.{column}"
        for pattern, kind in self.masks.items():
            if fnmatchcase(full, pattern):
                return kind
        return None


class Policy(BaseModel):
    defaults: Limits = Field(default_factory=Limits)
    roles: dict[str, Role]

    @model_validator(mode="before")
    @classmethod
    def _apply_defaults(cls, data: dict) -> dict:
        defaults = data.get("defaults") or {}
        for name, role in (data.get("roles") or {}).items():
            role["name"] = name
            role["limits"] = {**defaults, **(role.get("limits") or {})}
        return data

    def role(self, name: str) -> Role:
        if name not in self.roles:
            raise KeyError(f"Unknown role '{name}'. Defined roles: {sorted(self.roles)}")
        return self.roles[name]


def load_policy(path: Path) -> Policy:
    return Policy.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))
