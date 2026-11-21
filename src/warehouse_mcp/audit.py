"""Append-only audit trail: one JSON line per tool call, allowed or denied."""

from __future__ import annotations

import json
import threading
from datetime import UTC, datetime
from pathlib import Path


class AuditLog:
    def __init__(self, path: Path | None, role: str):
        self.path, self.role = path, role
        self.events: list[dict] = []
        self._lock = threading.Lock()

    def record(self, tool: str, decision: str, **details) -> None:
        event = {
            "ts": datetime.now(UTC).isoformat(timespec="milliseconds"),
            "role": self.role,
            "tool": tool,
            "decision": decision,  # allowed | denied | error
            **details,
        }
        with self._lock:
            self.events.append(event)
            if self.path is not None:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(event, default=str) + "\n")
