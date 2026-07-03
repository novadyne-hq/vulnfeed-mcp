# VulnFeed MCP server — stdio transport.
# Built from source so the image always matches the pinned commit
# (Docker MCP Registry builds + hosts this as mcp/vulnfeed).
FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY vulnfeed_mcp ./vulnfeed_mcp

RUN pip install --no-cache-dir .

# stdio MCP server — clients pipe to/from stdin/stdout.
ENTRYPOINT ["vulnfeed-mcp"]
