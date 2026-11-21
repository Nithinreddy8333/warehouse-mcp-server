"""A scripted agent session against the server, over the real stdio transport.

    python examples/client_demo.py            # as the analyst role
    python examples/client_demo.py support_de

It does what an LLM agent would do (orient, explore, query), then tries things the policy
forbids, so you can see both the answers and the refusals.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys

from mcp import Client, StdioServerParameters

STEPS = [
    ("whoami", {}),
    ("list_tables", {}),
    ("describe_table", {"table": "marts.dim_customers", "sample_rows": 2}),
    ("run_query", {"sql": "select category, round(sum(amount)) as revenue from marts.fct_orders "
                          "where not is_cancelled_or_returned group by 1 order by 2 desc"}),
    ("get_lineage", {"table": "marts.dim_customers"}),
    ("run_quality_checks", {"table": "marts.fct_orders"}),
    # Things the policy forbids:
    ("run_query", {"sql": "select * from hr.salaries"}),
    ("run_query", {"sql": "with d as (delete from marts.fct_orders returning *) select count(*) from d"}),
    ("run_query", {"sql": "select * from read_csv('/etc/passwd')"}),
]


def shorten(value, limit: int = 600) -> str:
    text = json.dumps(value, indent=2) if not isinstance(value, str) else value
    return text if len(text) <= limit else text[:limit] + "\n  …"


async def main(role: str) -> None:
    params = StdioServerParameters(command=sys.executable, args=["-m", "warehouse_mcp.cli", "serve", "--role", role],
                                   env=dict(os.environ))
    async with Client(params) as client:
        for tool, args in STEPS:
            reply = await client.call_tool(tool, args)
            text = "\n".join(getattr(block, "text", "") for block in reply.content)
            print(f"\n>>> {tool}({json.dumps(args) if args else ''})")
            print("REFUSED: " + text if reply.is_error else shorten(json.loads(text)))


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1] if len(sys.argv) > 1 else "analyst"))
