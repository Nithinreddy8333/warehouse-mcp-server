"""Attack the server and prove that nothing leaks.

Each case in red_team.yaml is sent through a real MCP client to a server running as the
case's role. Three things are measured:

  1. verdicts    every attack is denied, every probe and legitimate call is allowed
  2. leaks       no response (results or error text) contains a value the role may not see.
                 The forbidden values are read straight from the warehouse: every real
                 email local part, phone number and salary note, plus rows hidden by a
                 row filter
  3. depth       each SQL attack is run again with the static guard switched OFF. The
                 engine layer alone (snapshot, lockdown, read-only transaction) must still
                 prevent every leak and every write

Usage:  python evals/run_red_team.py        (exit code 1 on any failure)
"""

from __future__ import annotations

import asyncio
import json
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

import duckdb
import yaml
from mcp import Client

from warehouse_mcp.config import Settings
from warehouse_mcp.guard import QueryDenied
from warehouse_mcp.sample import SALARY_CANARY, build_sample
from warehouse_mcp.server import build_server

HERE = Path(__file__).parent
ROOT = HERE.parent


def forbidden_values(warehouse: Path, role: str) -> set[str]:
    """Strings that must never appear in any response to this role."""
    con = duckdb.connect(str(warehouse), read_only=True)
    try:
        phones = {r[0] for r in con.execute("select phone from raw.customers").fetchall()}
        emails = dict(con.execute("select email, country from raw.customers").fetchall())
        name_rows = con.execute("select full_name, country from raw.customers").fetchall()
        hr_names = {r[0] for r in con.execute("select full_name from hr.salaries").fetchall()}
    finally:
        con.close()
    names = {n for n, _ in name_rows}
    forbidden = {SALARY_CANARY} | phones
    if role == "support_de":  # sees real emails and names, but only for German customers
        forbidden |= {e for e, country in emails.items() if country != "DE"}
        german_names = {n for n, country in name_rows if country == "DE"}
        forbidden |= {n for n in names | hr_names if n not in german_names}
    else:
        forbidden |= {e.split("@")[0] for e in emails}
        if role == "analyst":
            forbidden |= names | hr_names
    return forbidden


def leaks(text: str, forbidden: set[str]) -> list[str]:
    return sorted(v for v in forbidden if v in text)[:3]


def case_sql(case: dict) -> str | None:
    if "sql_repeat" in case:
        spec = case["sql_repeat"]
        return spec["text"] * spec["times"] + spec["tail"]
    return case.get("sql")


def table_fingerprint(workspace) -> dict:
    return {name: workspace.execute(f"select count(*) as n from {name}", checked=True).rows[0]["n"]
            for name in sorted(workspace.tables)}


async def run() -> dict:
    suite = yaml.safe_load((HERE / "red_team.yaml").read_text())
    with tempfile.TemporaryDirectory() as tmp:
        base = Settings()
        base.warehouse_path = Path(tmp) / "warehouse.duckdb"
        base.models_dir, base.policy_path, base.checks_path = (
            ROOT / "warehouse/models", ROOT / "config/policy.yaml", ROOT / "config/checks.yaml")
        base.audit_log = Path(tmp) / "audit.jsonl"
        build_sample(base.warehouse_path, base.models_dir)

        servers: dict[str, object] = {}

        def server_for(role: str):
            if role not in servers:
                settings = Settings()
                settings.__dict__.update(base.__dict__)
                settings.role = role
                servers[role] = build_server(settings)
            return servers[role]

        results = []
        for group, expected in (("attacks", "denied"), ("probes", "allowed"), ("legitimate", "allowed")):
            for case in suite[group]:
                role = case.get("role", "analyst")
                server = server_for(role)
                forbidden = forbidden_values(base.warehouse_path, role)
                sql = case_sql(case)
                tool = case.get("tool", "run_query")
                args = dict(case.get("args", {}))
                if tool == "run_query":
                    args["sql"] = sql
                before = table_fingerprint(server.workspace)
                async with Client(server) as client:
                    reply = await client.call_tool(tool, args)
                text = "\n".join(getattr(block, "text", "") for block in reply.content)
                verdict = "denied" if reply.is_error else "allowed"
                problems = []
                if verdict != expected:
                    problems.append(f"expected {expected}, got {verdict}: {text[:120]}")
                if case.get("expect_code") and f"({case['expect_code']})" not in text:
                    problems.append(f"expected reason {case['expect_code']}: {text[:120]}")
                if found := leaks(text, forbidden):
                    problems.append(f"LEAK {found}")
                if verdict == "allowed" and tool == "run_query":
                    payload = json.loads(text)
                    if "rows" in case and payload["rows"] != case["rows"]:
                        problems.append(f"rows {payload['rows'][:2]} != {case['rows']}")
                    if "max_rows" in case and len(payload["rows"]) > case["max_rows"]:
                        problems.append(f"{len(payload['rows'])} rows exceed the cap {case['max_rows']}")

                # Depth: the same SQL with the static guard bypassed.
                engine = "n/a"
                if group == "attacks" and tool == "run_query":
                    try:
                        raw = server.workspace.execute(sql, checked=True)
                        engine_text = json.dumps(raw.rows, default=str)
                        engine = "ran, harmless"
                    except QueryDenied as err:
                        engine_text, engine = str(err), f"stopped ({err.code})"
                    except Exception as err:  # noqa: BLE001 - any engine refusal counts as stopped
                        engine_text, engine = str(err), f"stopped ({type(err).__name__})"
                    if found := leaks(engine_text, forbidden):
                        problems.append(f"ENGINE-LAYER LEAK {found}")
                        engine = "LEAK"
                if table_fingerprint(server.workspace) != before:
                    problems.append("DATA WAS MODIFIED")
                results.append({"group": group, "name": case["name"], "role": role, "verdict": verdict,
                                "engine_without_guard": engine, "ok": not problems, "problems": problems})

        for server in servers.values():
            server.workspace.close()
        exfil_files = [p for p in ("/tmp/exfil.csv", "/tmp/exfil") if Path(p).exists()]
    return {"results": results, "exfil_files": exfil_files}


def main() -> int:
    outcome = asyncio.run(run())
    results = outcome["results"]

    def count(group: str, **where) -> int:
        return sum(1 for r in results if r["group"] == group and all(r[k] == v for k, v in where.items()))

    attacks = [r for r in results if r["group"] == "attacks"]
    sql_attacks = [r for r in attacks if r["engine_without_guard"] != "n/a"]
    leaks_found = sum(1 for r in results if any("LEAK" in p for p in r["problems"]))
    modified = sum(1 for r in results if "DATA WAS MODIFIED" in r["problems"])
    summary = {
        "attacks": len(attacks),
        "attacks_denied": count("attacks", verdict="denied"),
        "sql_attacks_rerun_without_guard": len(sql_attacks),
        "stopped_by_engine_without_guard": sum(r["engine_without_guard"].startswith("stopped") for r in sql_attacks),
        "ran_without_guard_but_harmless": sum(r["engine_without_guard"] == "ran, harmless" for r in sql_attacks),
        "probes": count("probes"), "probes_passed": count("probes", ok=True),
        "legitimate": count("legitimate"), "legitimate_allowed": count("legitimate", ok=True),
        "responses_with_leaked_values": leaks_found,
        "cases_that_modified_data": modified,
        "files_written_outside": len(outcome["exfil_files"]),
    }
    report = {"run_at": datetime.now(UTC).isoformat(timespec="seconds"), "summary": summary, "results": results}
    out = HERE / "results"
    out.mkdir(exist_ok=True)
    (out / "red_team.json").write_text(json.dumps(report, indent=2) + "\n")
    lines = ["| measure | result |", "|---|---|"] + [f"| {k.replace('_', ' ')} | {v} |" for k, v in summary.items()]
    (out / "red_team.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))

    failed = [r for r in results if not r["ok"]]
    for r in failed:
        print(f"FAIL [{r['group']}] {r['name']} ({r['role']}): {'; '.join(r['problems'])}")
    harmless = [r["name"] for r in sql_attacks if r["engine_without_guard"] == "ran, harmless"]
    if harmless:
        print("\nRan with the guard off, without leaking or writing:\n  " + "\n  ".join(harmless))
    if failed or leaks_found or modified or outcome["exfil_files"]:
        return 1
    print("\nAll red-team checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
