"""Runtime settings, read from environment variables with local defaults."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _path(name: str, default: str) -> Path:
    return Path(os.environ.get(name, default))


@dataclass
class Settings:
    warehouse_path: Path = field(default_factory=lambda: _path("WAREHOUSE_PATH", "warehouse/warehouse.duckdb"))
    models_dir: Path = field(default_factory=lambda: _path("MODELS_DIR", "warehouse/models"))
    policy_path: Path = field(default_factory=lambda: _path("POLICY_PATH", "config/policy.yaml"))
    checks_path: Path = field(default_factory=lambda: _path("CHECKS_PATH", "config/checks.yaml"))
    audit_log: Path = field(default_factory=lambda: _path("AUDIT_LOG", "logs/audit.jsonl"))
    # The role is fixed when the server starts. The client cannot choose or change it.
    role: str = field(default_factory=lambda: os.environ.get("MCP_ROLE", "analyst"))
    # Salt for the 'hash' mask. Set MASK_SALT to keep hashed values stable across restarts.
    mask_salt: str = field(default_factory=lambda: os.environ.get("MASK_SALT") or os.urandom(16).hex())
