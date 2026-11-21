from pathlib import Path

import pytest

from warehouse_mcp.guard import QueryDenied, check_query
from warehouse_mcp.policy import Policy, load_policy

VISIBLE = {"marts.fct_orders", "marts.dim_customers"}


def test_roles_are_deny_by_default_and_nobody_can_read_hr():
    policy = load_policy(Path(__file__).resolve().parent.parent / "config/policy.yaml")
    for role in policy.roles.values():
        assert not role.can_read("hr.salaries")
        assert not role.can_read("secret.anything")
    assert policy.role("analyst").can_read("marts.fct_orders")
    assert not policy.role("analyst").can_read("raw.customers")
    assert policy.role("engineer").can_read("raw.customers")


def test_first_matching_mask_wins_and_limits_inherit_defaults():
    policy = Policy.model_validate({
        "defaults": {"max_rows": 10, "timeout_seconds": 2},
        "roles": {"r": {"tables": ["a.*"], "masks": {"a.t.email": "null", "*.email": "hash"},
                        "limits": {"max_rows": 3}}},
    })
    role = policy.role("r")
    assert role.mask_for("a.t", "email") == "null"
    assert role.mask_for("a.other", "email") == "hash"
    assert role.mask_for("a.t", "name") is None
    assert (role.limits.max_rows, role.limits.timeout_seconds) == (3, 2)
    with pytest.raises(KeyError):
        policy.role("nobody")


@pytest.mark.parametrize("sql", [
    "select count(*) from marts.fct_orders",
    "with x as (select * from marts.fct_orders) select * from x join marts.dim_customers using (customer_id)",
    "select * from range(10)",
    "select 'drop table x' as harmless_text",
    "from marts.fct_orders select status",
    "select 1;",
])
def test_guard_allows_ordinary_selects(sql):
    assert check_query(sql, VISIBLE).sql


@pytest.mark.parametrize(("sql", "code"), [
    ("", "empty"),
    ("select 1; select 2", "multiple_statements"),
    ("drop table marts.fct_orders", "not_select"),
    ("pragma database_list", "not_select"),
    ("copy marts.fct_orders to 'x.csv'", "not_select"),
    ("with d as (delete from marts.fct_orders returning *) select * from d", "write_operation"),
    ("describe marts.fct_orders", "write_operation"),
    ("select * from hr.salaries", "table_not_available"),
    ("select * from src.marts.fct_orders", "catalog_qualifier"),
    ("select * from read_csv('/etc/passwd')", "table_function"),
    ("select * from query_table('hr.salaries')", "table_function"),
    ("select * from duckdb_tables()", "table_function"),
    ("select (select max(salary) from hr.salaries)", "table_not_available"),
    ("selec oops", "syntax"),
    ("select " + "1, " * 6000 + "1", "too_long"),
])
def test_guard_denies_with_a_specific_reason(sql, code):
    with pytest.raises(QueryDenied) as err:
        check_query(sql, VISIBLE)
    assert err.value.code == code


def test_guard_reports_the_tables_a_query_reads():
    checked = check_query("select * from marts.fct_orders o join marts.dim_customers c using (customer_id)", VISIBLE)
    assert checked.tables == ["marts.dim_customers", "marts.fct_orders"]


def test_forbidden_and_missing_tables_get_the_same_message():
    messages = set()
    for table in ("hr.salaries", "does.not_exist"):
        with pytest.raises(QueryDenied) as err:
            check_query(f"select * from {table}", VISIBLE)
        messages.add(str(err.value).replace(table, "X"))
    assert len(messages) == 1
