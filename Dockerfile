FROM python:3.12-slim

WORKDIR /app
ENV PIP_NO_CACHE_DIR=1 PYTHONUNBUFFERED=1

COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install -e .

COPY . .
RUN warehouse-mcp build-sample

# stdio transport: run with `docker run -i --rm -e MCP_ROLE=analyst <image>`
ENTRYPOINT ["warehouse-mcp", "serve"]
