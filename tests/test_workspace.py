import shutil

import duckdb
import pytest

from warehouse_mcp.guard import QueryDenied
from warehouse_mcp.sample import EMAIL_LOCAL_CANARY, PHONE_CANARY


def test_only_permitted_tables_exist_in_the_session(make_workspace):
    ws = make_workspace("analyst")
    assert set(ws.tables) == {"marts.daily_revenue", "marts.dim_customers", "marts.fct_orders",
                              "staging.stg_customers", "staging.stg_orders"}
    # Even with the static guard bypassed, forbidden data is simply not there.
    for sql in ("select * from hr.salaries", "select * from raw.customers", "select * from src.hr.salaries"):
        with pytest.raises(QueryDenied) as err:
            ws.execute(sql, checked=True)
        assert err.value.code == "sql_error"
    names = ws.execute("select table_schema, table_name from information_schema.tables", checked=True).rows
    assert all(r["table_schema"] != "hr" for r in names)


def test_masks_are_applied_before_any_query_runs(make_workspace):
    ws = make_workspace("analyst")
    rows = ws.execute("select email, phone, full_name from marts.dim_customers", max_rows=200).rows
    assert all(r["email"].startswith("***@") and r["phone"] == "***" and r["full_name"].startswith("h_") for r in rows)
    dump = str(ws.execute("select * from staging.stg_customers", max_rows=200).rows)
    assert EMAIL_LOCAL_CANARY not in dump and PHONE_CANARY not in dump
    columns = {c.name: c for c in ws.tables["marts.dim_customers"].columns}
    assert columns["email"].mask == "email_domain" and columns["country"].mask is None


def test_hash_mask_is_stable_joinable_and_depends_on_the_salt(make_workspace):
    a = make_workspace("analyst")
    b = make_workspace("analyst", mask_salt="another-salt")
    sql = "select full_name from marts.dim_customers order by customer_id limit 5"
    first, again, other = a.execute(sql).rows, a.execute(sql).rows, b.execute(sql).rows
    assert first == again and first != other
    joined = a.execute(
        "select count(*) as n from marts.dim_customers m join staging.stg_customers s "
        "on m.full_name = s.full_name and m.customer_id = s.customer_id").rows[0]["n"]
    assert joined == 300


def test_row_filter_limits_both_tables_for_the_support_role(make_workspace):
    ws = make_workspace("support_de")
    assert ws.execute("select distinct country from marts.dim_customers").rows == [{"country": "DE"}]
    orphans = ws.execute("select count(*) as n from marts.fct_orders where customer_id not in "
                         "(select customer_id from marts.dim_customers)").rows[0]["n"]
    assert orphans == 0 and ws.tables["marts.dim_customers"].row_filtered


@pytest.mark.parametrize("sql", [
    "with d as (delete from marts.fct_orders returning *) select count(*) from d",
    "delete from marts.fct_orders",
    "drop table marts.fct_orders",
    "create table marts.x as select 1",
    "commit; delete from marts.fct_orders",
    "rollback; begin; delete from marts.fct_orders; commit",
])
def test_engine_refuses_writes_even_with_the_guard_bypassed(make_workspace, sql):
    ws = make_workspace("analyst")
    with pytest.raises(QueryDenied):
        ws.execute(sql, checked=True)
    assert ws.execute("select count(*) as n from marts.fct_orders", checked=True).rows == [{"n": 2000}]
    assert "marts.x" not in str(ws.execute("select table_name from information_schema.tables", checked=True).rows)


@pytest.mark.parametrize("sql", [
    "select * from read_csv('/etc/passwd')",
    "select * from read_text('/etc/hostname')",
    "select * from glob('/etc/*')",
    "copy marts.fct_orders to '/tmp/should_not_exist.csv'",
    "attach '/tmp/other.duckdb' as o",
    "set enable_external_access = true",
    "install httpfs",
])
def test_engine_refuses_file_network_and_config_access_with_the_guard_bypassed(make_workspace, sql):
    with pytest.raises(QueryDenied):
        make_workspace("analyst").execute(sql, checked=True)


def test_row_cap_truncation_and_json_safe_values(make_workspace):
    ws = make_workspace("analyst")
    result = ws.execute("select * from marts.fct_orders", max_rows=100_000)
    assert len(result.rows) == 200 and result.truncated
    small = ws.execute("select order_date, amount, is_cancelled_or_returned from marts.fct_orders limit 1")
    row = small.rows[0]
    assert not small.truncated
    assert isinstance(row["order_date"], str) and isinstance(row["amount"], float)
    assert isinstance(row["is_cancelled_or_returned"], bool)
    long = ws.execute("select repeat('x', 5000) as big").rows[0]["big"]
    assert len(long) == 501 and long.endswith("…")


def test_runaway_query_is_interrupted(make_workspace):
    ws = make_workspace("analyst")
    ws.role.limits.timeout_seconds = 0.3
    with pytest.raises(QueryDenied) as err:
        ws.execute("select count(*) from range(100000000000) a, range(1000) b")
    assert err.value.code == "timeout"
    assert ws.execute("select 1 as ok").rows == [{"ok": 1}]


def test_the_warehouse_file_is_never_modified(make_workspace, warehouse):
    before = warehouse.read_bytes()
    ws = make_workspace("engineer")
    for sql in ("delete from raw.orders", "with d as (delete from raw.orders returning *) select * from d"):
        with pytest.raises(QueryDenied):
            ws.execute(sql, checked=True)
    assert warehouse.read_bytes() == before


def test_snapshot_is_rebuilt_when_the_warehouse_changes(make_workspace, warehouse, tmp_path):
    copy = tmp_path / "copy.duckdb"
    shutil.copy(warehouse, copy)
    ws = make_workspace("analyst", warehouse_path=copy)
    assert not ws.refresh_if_stale()
    con = duckdb.connect(str(copy))
    con.execute("delete from marts.fct_orders where order_id < 10011")
    con.close()
    assert ws.refresh_if_stale()
    assert ws.execute("select count(*) as n from marts.fct_orders").rows == [{"n": 1990}]
