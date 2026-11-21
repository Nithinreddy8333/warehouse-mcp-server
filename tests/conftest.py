import asyncio
import json
from pathlib import Path

import pytest
from mcp import Client

from warehouse_mcp.config import Settings
from warehouse_mcp.policy import load_policy
from warehouse_mcp.sample import build_sample
from warehouse_mcp.server import build_server
from warehouse_mcp.workspace import Workspace

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="session")
def warehouse(tmp_path_factory) -> Path:
    path = tmp_path_factory.mktemp("wh") / "warehouse.duckdb"
    build_sample(path, ROOT / "warehouse/models")
    return path


@pytest.fixture()
def make_settings(warehouse, tmp_path):
    def factory(role: str = "analyst", **overrides) -> Settings:
        settings = Settings()
        settings.warehouse_path = warehouse
        settings.models_dir = ROOT / "warehouse/models"
        settings.policy_path = ROOT / "config/policy.yaml"
        settings.checks_path = ROOT / "config/checks.yaml"
        settings.audit_log = tmp_path / "audit.jsonl"
        settings.role = role
        settings.mask_salt = "test-salt"
        for key, value in overrides.items():
            setattr(settings, key, value)
        return settings

    return factory


@pytest.fixture()
def make_workspace(make_settings):
    opened = []

    def factory(role: str = "analyst", **overrides) -> Workspace:
        settings = make_settings(role, **overrides)
        ws = Workspace(settings, load_policy(settings.policy_path).role(role))
        opened.append(ws)
        return ws

    yield factory
    for ws in opened:
        ws.close()


@pytest.fixture()
def call(make_settings):
    """call(tool, args, role='analyst') -> (is_error, parsed JSON or error text), via a real MCP client."""
    servers = {}

    def invoke(tool: str, args: dict | None = None, role: str = "analyst"):
        if role not in servers:
            servers[role] = build_server(make_settings(role))

        async def go():
            async with Client(servers[role]) as client:
                return await client.call_tool(tool, args or {})

        reply = asyncio.run(go())
        text = "\n".join(getattr(block, "text", "") for block in reply.content)
        return reply.is_error, (text if reply.is_error else json.loads(text))

    invoke.servers = servers
    yield invoke
    for server in servers.values():
        server.workspace.close()
