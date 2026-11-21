import asyncio
import json
import os
import sys

from mcp import Client, StdioServerParameters

from warehouse_mcp.lineage import build_order, load_models


def test_tools_are_listed_as_read_only(call):
    call("whoami")
    server = call.servers["analyst"]

    async def go():
        async with Client(server) as client:
            return (await client.list_tools()).tools, (await client.list_resources()).resources

    tools, resources = asyncio.run(go())
    assert {t.name for t in tools} == {"whoami", "list_tables", "describe_table", "run_query", "get_lineage",
                                      "run_quality_checks"}
    assert all(t.annotations.read_only_hint and t.description for t in tools)
    assert {str(r.uri) for r in resources} == {"warehouse://catalog", "warehouse://policy"}


def test_whoami_tells_the_agent_its_limits_and_masks(call):
    error, me = call("whoami")
    assert not error and me["role"] == "analyst" and me["limits"]["max_rows"] == 200
    assert "marts.dim_customers.email (email_domain)" in me["masked_columns"]
    assert "hr.salaries" not in me["readable_tables"]


def test_run_query_returns_rows_and_denials_explain_themselves(call):
    error, result = call("run_query", {"sql": "select status, count(*) as n from marts.fct_orders group by 1"})
    assert not error and result["columns"] == ["status", "n"] and result["row_count"] == 5
    error, message = call("run_query", {"sql": "select * from hr.salaries"})
    assert error and "Denied (table_not_available)" in message
    error, message = call("run_query", {"sql": "delete from marts.fct_orders"})
    assert error and "Denied (not_select)" in message


def test_describe_table_shows_masking_and_masked_samples(call):
    error, info = call("describe_table", {"table": "marts.dim_customers", "sample_rows": 2})
    assert not error and info["rows"] == 300 and len(info["sample"]) == 2
    masked = {c["name"]: c["masked"] for c in info["columns"]}
    assert masked["email"] == "email_domain" and masked["country"] is None
    assert info["sample"][0]["phone"] == "***"
    assert call("describe_table", {"table": "hr.salaries"})[0]


def test_lineage_comes_from_the_model_sql_and_hides_restricted_tables(call):
    _, analyst = call("get_lineage", {"table": "marts.dim_customers"})
    assert [t["table"] for t in analyst["upstream"]["tables"]] == [
        "marts.fct_orders", "staging.stg_customers", "staging.stg_orders"]
    assert analyst["upstream"]["restricted"] == 3  # raw.customers, raw.orders, raw.products
    _, engineer = call("get_lineage", {"table": "raw.orders"}, role="engineer")
    assert engineer["built_by"].startswith("source table")
    assert {t["table"] for t in engineer["downstream"]["tables"]} == {
        "staging.stg_orders", "marts.fct_orders", "marts.dim_customers", "marts.daily_revenue"}
    models = load_models(call.servers["analyst"].workspace.settings.models_dir)
    order = build_order(models)
    assert order.index("staging.stg_orders") < order.index("marts.fct_orders") < order.index("marts.dim_customers")


def test_quality_checks_only_cover_tables_the_role_can_read(call):
    error, report = call("run_quality_checks")
    names = [r["check"] for r in report["results"]]
    assert not error and report["failed"] == 0 and report["passed"] == len(names) == 8
    assert not any("hr." in n or "raw." in n for n in names)
    _, one = call("run_quality_checks", {"table": "marts.dim_customers"})
    assert [r["check"] for r in one["results"]] == ["unique(marts.dim_customers.customer_id)",
                                                    "min_rows(marts.dim_customers)"]


def test_every_call_is_audited_including_denials(call):
    call("run_query", {"sql": "select count(*) from marts.fct_orders"})
    call("run_query", {"sql": "select * from hr.salaries"})
    call("describe_table", {"table": "marts.fct_orders"})
    log = call.servers["analyst"].workspace.settings.audit_log
    events = [json.loads(line) for line in log.read_text().splitlines()]
    assert [(e["tool"], e["decision"]) for e in events] == [
        ("run_query", "allowed"), ("run_query", "denied"), ("describe_table", "allowed")]
    assert events[0]["role"] == "analyst" and events[0]["tables"] == ["marts.fct_orders"] and events[0]["rows"] == 1
    assert events[1]["reason"] == "table_not_available" and "hr.salaries" in events[1]["sql"]


def test_resources_describe_catalog_and_policy(call):
    call("whoami")

    async def go():
        async with Client(call.servers["analyst"]) as client:
            catalog = await client.read_resource("warehouse://catalog")
            policy = await client.read_resource("warehouse://policy")
            return json.loads(catalog.contents[0].text), json.loads(policy.contents[0].text)

    catalog, policy = asyncio.run(go())
    assert catalog["marts.dim_customers"]["columns"]["phone"]["masked"] == "redact"
    assert "hr.salaries" not in catalog and policy["role"] == "analyst"


def test_server_works_over_real_stdio_transport(make_settings):
    settings = make_settings("support_de")
    env = {**os.environ, "WAREHOUSE_PATH": str(settings.warehouse_path), "MODELS_DIR": str(settings.models_dir),
           "POLICY_PATH": str(settings.policy_path), "CHECKS_PATH": str(settings.checks_path),
           "AUDIT_LOG": str(settings.audit_log), "MCP_ROLE": "support_de"}
    params = StdioServerParameters(command=sys.executable, args=["-m", "warehouse_mcp.cli", "serve"], env=env)

    async def go():
        async with Client(params) as client:
            me = await client.call_tool("whoami", {})
            denied = await client.call_tool("run_query", {"sql": "select * from marts.daily_revenue"})
            return json.loads(me.content[0].text), denied.is_error

    me, denied = asyncio.run(go())
    assert me["role"] == "support_de" and me["limits"]["max_rows"] == 50 and denied
