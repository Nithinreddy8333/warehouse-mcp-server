"""Build the sample warehouse: raw tables from a seeded generator, then the SQL models.

The data contains deliberate "canary" values in the places a role must never see (customer
emails and phone numbers, the whole hr.salaries table). The red-team suite searches every
server response for them.
"""

from __future__ import annotations

import random
from datetime import date, timedelta
from pathlib import Path

import duckdb

from .lineage import build_order, load_models

FIRST = ["Ava", "Liam", "Noah", "Mia", "Arjun", "Sofia", "Ethan", "Priya", "Lucas", "Zoe", "Omar", "Hana"]
LAST = ["Patel", "Garcia", "Nguyen", "Smith", "Kim", "Okafor", "Rossi", "Reddy", "Tanaka", "Brown", "Silva"]
COUNTRIES = ["US", "CA", "GB", "IN", "DE"]
CATEGORIES = ["electronics", "home", "toys", "books"]
STATUSES = ["placed", "shipped", "delivered", "cancelled", "returned"]

EMAIL_CANARY = "corp-secret.example"  # domain part survives the email_domain mask by design
EMAIL_LOCAL_CANARY = "zzcanary"  # local part must never be visible to a masked role
PHONE_CANARY = "+1-555-0199"
SALARY_CANARY = "CANARY-SALARY-7781"


def build_sample(warehouse_path: Path, models_dir: Path, seed: int = 11) -> dict[str, int]:
    rng = random.Random(seed)
    warehouse_path.parent.mkdir(parents=True, exist_ok=True)
    if warehouse_path.exists():
        warehouse_path.unlink()
    con = duckdb.connect(str(warehouse_path))
    try:
        con.execute("create schema raw; create schema staging; create schema marts; create schema hr")
        customers = []
        for i in range(1, 301):
            first, last = rng.choice(FIRST), rng.choice(LAST)
            customers.append((
                f"C{i:04d}", f"{first} {last}",
                f"{EMAIL_LOCAL_CANARY}.{first}.{last}{i}@{EMAIL_CANARY}".lower(),
                f"{PHONE_CANARY}-{i:04d}", rng.choices(COUNTRIES, weights=[40, 15, 15, 20, 10])[0],
                date(2023, 1, 1) + timedelta(days=rng.randrange(0, 900)),
            ))
        con.execute("create table raw.customers (customer_id varchar, full_name varchar, email varchar, "
                    "phone varchar, country varchar, signup_date date)")
        con.executemany("insert into raw.customers values (?, ?, ?, ?, ?, ?)", customers)

        products = [(f"P{i:03d}", f"Product {i}", rng.choice(CATEGORIES), round(rng.uniform(4, 400), 2))
                    for i in range(1, 31)]
        con.execute("create table raw.products (product_id varchar, product_name varchar, category varchar, "
                    "unit_price decimal(18,2))")
        con.executemany("insert into raw.products values (?, ?, ?, ?)", products)

        orders = []
        today = date.today()
        for i in range(2000):
            product = rng.choice(products)
            qty = rng.randint(1, 5)
            orders.append((10001 + i, rng.choice(customers)[0], product[0], qty, round(qty * product[3], 2),
                           rng.choice(STATUSES), today - timedelta(days=rng.randrange(0, 365))))
        con.execute("create table raw.orders (order_id bigint, customer_id varchar, product_id varchar, "
                    "quantity integer, amount decimal(18,2), status varchar, order_date date)")
        con.executemany("insert into raw.orders values (?, ?, ?, ?, ?, ?, ?)", orders)

        salaries = [(f"E{i:03d}", f"{rng.choice(FIRST)} {rng.choice(LAST)}", rng.randrange(60, 220) * 1000,
                     SALARY_CANARY) for i in range(1, 21)]
        con.execute("create table hr.salaries (employee_id varchar, full_name varchar, salary integer, note varchar)")
        con.executemany("insert into hr.salaries values (?, ?, ?, ?)", salaries)

        models = load_models(models_dir)
        for name in build_order(models):
            schema, table = name.split(".", 1)
            con.execute(f'create or replace table "{schema}"."{table}" as {models[name].sql}')
        rows = con.execute(
            "select table_schema || '.' || table_name from information_schema.tables "
            "where table_schema in ('raw', 'staging', 'marts', 'hr') order by 1"
        ).fetchall()
        return {name: con.execute(f"select count(*) from {name}").fetchone()[0] for (name,) in rows}
    finally:
        con.close()
