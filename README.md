# Warehouse MCP Server

A [Model Context Protocol](https://modelcontextprotocol.io) server that lets AI agents explore
and query a data warehouse **without being able to see or change anything their role does not
allow**, however the query is written.

```
 AI agent ──MCP──> warehouse-mcp (one role per process)
                     │  tools: whoami, list_tables, describe_table,
                     │         run_query, get_lineage, run_quality_checks
                     │
                     ├─ 1. static guard       one SELECT, known tables, no table functions
                     ├─ 2. private snapshot   only the role's tables, already masked and filtered
                     ├─ 3. engine lockdown    no files, no network, no config changes
                     ├─ 4. read-only txn      the engine refuses every write
                     ├─ 5. limits             row cap, timeout, cell and query size
                     └─ 6. audit log          every call, allowed or denied
```

It runs locally on DuckDB with a sample warehouse, so anyone can clone it, run the red-team
suite and connect an MCP client.

## Why this exists

Giving an agent a `run_sql` tool is easy. Doing it safely is the actual work, and the common
shortcut ("check that the query starts with SELECT") does not hold. While building this, the
red-team suite found two ways past that kind of check on DuckDB:

- **A write disguised as a SELECT.** DuckDB runs
  `with d as (delete from t returning *) select count(*) from d`, and its own statement
  classifier reports that statement as a `SELECT`. A filter on statement type lets it through,
  and it deletes the rows.
- **Leaving the read-only transaction.** Wrapping queries in a read-only transaction is not
  enough if the input may hold several statements: `commit; delete from t` ends the
  transaction and then writes outside it.

So the design does not depend on any single check being right:

| Layer | What it guarantees | If this layer is bypassed |
|---|---|---|
| Static guard (`guard.py`) | One statement, a SELECT, no write nodes anywhere in the tree, only tables the role can see, no table functions except value generators | The next three layers still hold |
| Private snapshot (`workspace.py`) | The session contains only the role's tables, with masked columns already replaced and row filters already applied. The warehouse is detached afterwards | There is nothing forbidden left to read |
| Engine lockdown | `enable_external_access = false`, extension loading off, then `lock_configuration = true` | No file, network, `ATTACH` or `COPY`, and the settings cannot be changed back |
| Execution path | Exactly one statement, run inside `BEGIN TRANSACTION READ ONLY`, always rolled back | The engine itself rejects writes |

Masking is the clearest example of why. Rewriting a user's SQL to mask columns has to get
`select *`, aliases, expressions, subqueries and joins all right. Here the data is masked
**before** the query exists, so there is nothing to get wrong at query time.

## Quick start

```bash
git clone https://github.com/Nithinreddy8333/warehouse-mcp-server
cd warehouse-mcp-server
python -m venv .venv && source .venv/bin/activate
make install
make roles      # what each role can see
make demo       # scripted agent session over stdio: answers and refusals
make redteam    # attack the server
make test       # 55 tests
```

Connect a real MCP client by registering the server as a stdio command. Most clients take a
command, arguments and environment variables, for example:

```json
{
  "mcpServers": {
    "warehouse": {
      "command": "/absolute/path/to/.venv/bin/warehouse-mcp",
      "args": ["serve", "--role", "analyst"],
      "env": {
        "WAREHOUSE_PATH": "/absolute/path/to/warehouse/warehouse.duckdb",
        "POLICY_PATH": "/absolute/path/to/config/policy.yaml",
        "CHECKS_PATH": "/absolute/path/to/config/checks.yaml",
        "MODELS_DIR": "/absolute/path/to/warehouse/models",
        "AUDIT_LOG": "/absolute/path/to/logs/audit.jsonl"
      }
    }
  }
}
```

Check your client's documentation for where this configuration lives.

## Tools

| Tool | Purpose |
|---|---|
| `whoami` | The role, its limits, readable tables, masked columns and row-filtered tables. Agents are told to call this first |
| `list_tables` | Readable tables with row counts and descriptions |
| `describe_table` | Columns, types, which are masked, and sample rows |
| `run_query` | One read-only DuckDB `SELECT`; rows as JSON with a `truncated` flag |
| `get_lineage` | Upstream and downstream tables, parsed from the SQL that builds the warehouse |
| `run_quality_checks` | Declared checks (unique, not null, accepted values, freshness, row counts) |

Resources: `warehouse://catalog` and `warehouse://policy`. All tools are annotated read-only.
A refused call returns a tool error with a reason code, such as
`Denied (table_not_available): The table 'hr.salaries' is not available to this role.`
A forbidden table and a table that does not exist produce the same message.

## Access policy

`config/policy.yaml` is deny-by-default:

```yaml
roles:
  analyst:
    tables: ["marts.*", "staging.*"]
    masks:
      "*.email": email_domain     # ***@domain
      "*.phone": redact           # ***
      "*.full_name": hash         # salted, stable, still joinable
  support_de:
    tables: ["marts.dim_customers", "marts.fct_orders"]
    masks: {"*.phone": redact}
    row_filters:
      "marts.dim_customers": "country = 'DE'"
    limits: {max_rows: 50}
```

Nobody is granted `hr.*`, so no role can read salaries. The role is fixed when the server
process starts (`--role` or `MCP_ROLE`); a client cannot choose or change it.

What an analyst gets back from `select email, phone, full_name, country from marts.dim_customers`:

```json
{"email": "***@corp-secret.example", "phone": "***", "full_name": "h_3b8d5fcf2231", "country": "CA"}
```

(The hash depends on the salt, so yours will differ.)

## Red-team results

`make redteam` sends every case in `evals/red_team.yaml` through a real MCP client and checks
three things. The sample data plants known values where no role should see them, and the
forbidden values for each role are read straight from the warehouse, so a leak is detected by
content, not by trusting the verdict.

| Measure | Result |
|---|---|
| Attacks sent | 71 |
| Attacks denied | 71 |
| SQL attacks re-run with the static guard switched off | 66 |
| ... stopped by the engine layers alone | 55 |
| ... ran, but leaked nothing and wrote nothing | 11 |
| Masking and row-filter probes passed | 11 of 11 |
| Legitimate calls allowed | 21 of 21 |
| Responses containing a forbidden value | 0 |
| Cases that modified data | 0 |
| Files written outside the session | 0 |

The attacks cover forbidden tables (plain, quoted, in unions, subqueries, CTEs and joins),
catalog qualifiers, `query()` and `query_table()`, metadata functions, file and network
readers, `COPY`, `ATTACH`, extensions, every kind of write including the CTE forms above,
multiple statements with comment tricks, `COMMIT`/`ROLLBACK` escapes, configuration changes,
a runaway cross join, an oversized query, and injection through tool arguments.

The 11 that ran with the guard off are reads of the session's own metadata
(`information_schema`, `duckdb_tables()`, `show tables` and similar), which lists only the
role's snapshot, plus an `explain` of a permitted table, a very long but harmless query, and
no-ops such as `checkpoint`.

As a control, removing the analyst's masks from the policy makes the suite fail with leaks
reported, so the detector does detect.

## Limits and honest caveats

- **Passing 71 attacks I wrote is not proof of security.** It is a regression suite. It
  covers what I thought of, on DuckDB, at one version.
- **Not tested with an LLM client.** Everything was exercised with the MCP Python SDK's
  client, in memory and over stdio. I did not connect Claude Desktop or another agent.
- **stdio only in practice.** `--transport streamable-http` is passed through to the SDK but
  is untested, and there is **no authentication**: identity is "whoever started the process".
  Serving many users from one endpoint needs OAuth and a token-to-role mapping, which is not
  built.
- **The snapshot is a copy.** It is rebuilt when the warehouse file changes. That suits a
  local or modest warehouse, not a large one. On Snowflake, BigQuery or Postgres the same
  design maps to native roles, masking policies and row access policies with one service
  account per MCP role, and no copy. That port is not written.
- **Hashed columns** are salted, but anyone who can read the salt can test guesses. Set
  `MASK_SALT` from a secret store; without it, hashes change on every restart.
- **Lineage reveals a count.** A role sees how many upstream tables are hidden from it, not
  their names.
- **Row filters are trusted SQL** written by the policy author and run against the source
  while the snapshot is built.
- **Built on MCP Python SDK 2.x** (`mcp>=2,<3`). The 1.x API differs.
- The Dockerfile is included but was not built in the environment this was developed in.

## Project layout

```
src/warehouse_mcp/
  server.py      MCP tools and resources, audit wrapper
  workspace.py   per-role snapshot, masking, lockdown, read-only execution, limits
  guard.py       static query checks with reason codes
  policy.py      roles, table patterns, masks, row filters, limits
  lineage.py     lineage parsed from the model SQL
  checks.py      data quality checks
  audit.py       JSONL audit log
  sample.py      sample warehouse with planted canary values
  cli.py         warehouse-mcp command (serve, roles, query, build-sample)
config/          policy.yaml, checks.yaml
warehouse/models SQL that builds staging and marts
evals/           red-team cases, runner, results
examples/        scripted agent session over stdio
tests/           55 tests, including a real stdio client-server round trip
```

## What I would do next

- Streamable HTTP with OAuth, mapping token claims to roles.
- A Snowflake backend using native roles and masking policies instead of a snapshot.
- Query cost limits (scan size estimates) in addition to time and row limits.
- Run an LLM agent against the server with adversarial prompts, and add what it finds to the
  red-team suite.

## License

MIT
