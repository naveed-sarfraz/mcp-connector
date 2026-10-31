# InsightMonk Reports MCP Server

An open, stateless MCP server for searching, reading, searching within, and
downloading active InsightMonk reports from Microsoft Copilot, Claude, ChatGPT,
MCP Inspector, and other streamable-HTTP MCP clients.

The connector itself requires no authentication. It calls two unauthenticated
public endpoints exposed by community-api:

- POST /v1/reports/public/search
- GET /v1/reports/public/content?reportId=REPORT_ID

## Security model

There is no OAuth, API key, bearer token, InsightMonk login, service account, or
database connection in this MCP server. Anyone who knows the deployed MCP URL
can invoke its tools and access any active report exposed by the public APIs.
Authentication to Microsoft, Anthropic, or OpenAI does not authenticate that
person to InsightMonk.

The short-lived signed PDF URL returned by community-api remains internal to
the MCP process. It is used only to download the PDF and is removed recursively
from metadata returned to MCP clients. Tokens, URLs, PDF text, and report search
queries are not written to application logs.

## MCP tools

- search_reports(query, limit, cursor, report_ids, topics, industry_type, year_from, year_to, latest_only)
- get_report_content(report_id)
- download_report_pdf(report_id)
- search_report_content(report_id, query, limit)

search_reports searches all indexed active report sections and defaults to the
latest edition. When its response contains hasMore: true, call it again within
two minutes using nextCursor as cursor and keep the query, filters, and limit
unchanged.

PDFs are downloaded only from validated public HTTPS hosts, with redirect and
size limits. Text is extracted with page numbers and cached in memory for 15
minutes by default. Empty image-only pages are reported as requiring OCR.

## Configuration

Copy .env.example to .env. No secret is required:

    INSIGHTMONK_BASE_URL=https://community-api.insightmonk.com
    MCP_SERVER_URL=http://127.0.0.1:8000/mcp
    MCP_TRANSPORT=streamable-http

Optional HTTP and PDF limits are documented in .env.example.

## Local installation

Python 3.11 or newer is required:

    python -m venv .venv
    source .venv/bin/activate
    python -m pip install -r requirements-dev.txt
    cp .env.example .env
    python tiny_server.py

Local endpoints:

- MCP: http://127.0.0.1:8000/mcp
- Health: http://127.0.0.1:8000/health
- Service information: http://127.0.0.1:8000/

Run a local STDIO smoke search:

    python tiny_client.py "What is the EV battery market size in 2035?"

## MCP Inspector

    python tiny_server.py
    npx @modelcontextprotocol/inspector

Choose Streamable HTTP, enter http://127.0.0.1:8000/mcp, and connect without
authentication.

## Deploy on Render

The repository includes a non-root Docker image and render.yaml Blueprint.

1. Push this repository to GitHub.
2. Create or update the Render Blueprint from the repository.
3. Deploy the service.
4. Verify https://YOUR-HOST/health.
5. Verify https://YOUR-HOST/ reports authentication: none.

MCP_SERVER_URL is derived automatically from RENDER_EXTERNAL_HOSTNAME. On
another provider, set it to the final public HTTPS URL ending in /mcp.

Remove these obsolete Render variables after deploying this version:

- INSIGHTMONK_EMAIL
- INSIGHTMONK_PASSWORD
- JWT_SECRET
- every MYSQL_* variable
- MCP_OAUTH_SIGNING_KEY
- MCP_AUTO_MIGRATE

## Connect AI platforms

Use the deployed URL:

    https://YOUR-HOST/mcp

Select None or No authentication. Existing OAuth-based connector registrations
from the previous MCP version should be deleted and recreated.

For Microsoft 365 Copilot, select None in the MCP connector authentication
field. For Claude and ChatGPT, add the same remote MCP URL as a custom
connector/app and choose no authentication when that option is available.

## Tests

Tests mock all HTTP calls and never require real credentials:

    python -m pytest -q

Coverage includes public API request/response parsing, cursor and filter
forwarding, validation, signed-URL redaction, all four tools, PDF extraction,
OCR detection, caching, size limits, and SSRF checks.
