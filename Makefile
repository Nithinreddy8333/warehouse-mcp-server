.PHONY: install sample roles demo serve test lint redteam clean

ROLE ?= analyst

install:
	pip install -e ".[dev]"

sample:  ## Build the sample DuckDB warehouse
	warehouse-mcp build-sample

roles: sample  ## Show what each role can see
	warehouse-mcp roles

demo: sample  ## Scripted agent session over stdio: answers and refusals
	python examples/client_demo.py $(ROLE)

serve: sample  ## Start the MCP server on stdio for one role
	warehouse-mcp serve --role $(ROLE)

test:
	pytest

lint:
	ruff check .

redteam:  ## Attack the server; fails on any leak, write or wrong verdict
	python evals/run_red_team.py

clean:
	rm -rf warehouse/warehouse.duckdb logs
