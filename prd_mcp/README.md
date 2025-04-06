# PRD MCP

## Run Inspector

This is a testing environment to check that mcp is working.

```bash
mcp dev src/prd_mcp/app.py
```

Under "Configuration", set `MCP_SERVER_REQUEST_TIMEOUT` as 100000

## Run Server

```bash
mcp run --transport sse src/prd_mcp/app.py:mcp
```

This runs on localhost:8000 by default.
