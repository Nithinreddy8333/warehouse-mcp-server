"""Table-level lineage, read from the SQL that builds the warehouse.

Each file in the models folder is named `<schema>.<table>.sql` and holds one SELECT. The
tables that SELECT reads are the model's direct upstreams. Nothing is declared by hand, so
the lineage cannot drift from the code.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from pathlib import Path

import sqlglot
from sqlglot import exp


@dataclass
class Model:
    name: str
    sql: str
    description: str
    upstream: list[str]


def load_models(models_dir: Path) -> dict[str, Model]:
    models: dict[str, Model] = {}
    for path in sorted(models_dir.glob("*.sql")):
        text = path.read_text(encoding="utf-8")
        description = " ".join(
            line[2:].strip() for line in text.splitlines() if line.startswith("--")
        )
        tree = sqlglot.parse_one(text, read="duckdb")
        ctes = {cte.alias_or_name.lower() for cte in tree.find_all(exp.CTE)}
        upstream = sorted({
            f"{t.db.lower()}.{t.name.lower()}"
            for t in tree.find_all(exp.Table)
            if isinstance(t.this, exp.Identifier) and t.db and t.name.lower() not in ctes
        })
        models[path.stem] = Model(path.stem, text, description, upstream)
    return models


def build_order(models: dict[str, Model]) -> list[str]:
    """Topological order, so every model is built after the models it reads."""
    remaining = {name: {u for u in m.upstream if u in models} for name, m in models.items()}
    order: list[str] = []
    while remaining:
        ready = sorted(name for name, deps in remaining.items() if not deps)
        if not ready:
            raise ValueError(f"Circular dependency between models: {sorted(remaining)}")
        for name in ready:
            order.append(name)
            del remaining[name]
        for deps in remaining.values():
            deps.difference_update(ready)
    return order


def _walk(start: str, edges: dict[str, set[str]]) -> list[tuple[str, int]]:
    seen, out, queue = {start}, [], deque([(start, 0)])
    while queue:
        node, depth = queue.popleft()
        for nxt in sorted(edges.get(node, ())):
            if nxt not in seen:
                seen.add(nxt)
                out.append((nxt, depth + 1))
                queue.append((nxt, depth + 1))
    return out


def lineage(table: str, models: dict[str, Model], visible: set[str]) -> dict:
    """Upstream and downstream tables of `table`, limited to what the role may see.

    Tables outside the role's access are counted but not named.
    """
    up = {name: set(m.upstream) for name, m in models.items()}
    down: dict[str, set[str]] = {}
    for name, sources in up.items():
        for source in sources:
            down.setdefault(source, set()).add(name)

    def shape(found: list[tuple[str, int]]) -> dict:
        shown = [{"table": t, "distance": d} for t, d in found if t in visible]
        return {"tables": shown, "restricted": len(found) - len(shown)}

    return {
        "table": table,
        "built_by": "sql model" if table in models else "source table (loaded, not derived)",
        "upstream": shape(_walk(table, up)),
        "downstream": shape(_walk(table, down)),
    }
