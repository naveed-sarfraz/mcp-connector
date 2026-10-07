# Supabase Physician Search MCP Server

A read-only, remotely deployable MCP server for searching
`public.bis_physicians` by `physician_name` or `specialty`.

The public endpoint uses Streamable HTTP and supports both:

- OAuth 2.1 authorization-code flow with PKCE and dynamic client registration,
  for Claude and other OAuth-capable MCP clients.
- An optional static bearer token, for Lovable, Codex, scripts, and clients that
  allow a token to be entered directly.

Every database session is forced into read-only mode, SQL identifiers are fixed
in source, user values are parameterized, search results are capped at 50 rows,
and both exposed MCP tools carry read-only/non-destructive annotations.

## Important security step

An earlier copy of `.env.example` contained a real Supabase password. Rotate that
database password in Supabase before deploying. Use a dedicated read-only database
role for this connector when possible. `.env.example` now contains placeholders
only, and `.env` is excluded from Git and Docker builds.

## Local setup

Use Python 3.11 or newer:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
cp .env.example .env
```

Configure `.env`:

```dotenv
SUPABASE_DB_URL=postgresql://USERNAME:PASSWORD@HOST:5432/DATABASE
MCP_SERVER_URL=http://127.0.0.1:8000/mcp
MCP_AUTH_PASSWORD=choose-a-long-unique-password
MCP_OAUTH_SIGNING_KEY=generate-at-least-32-random-bytes
MCP_BEARER_TOKEN=generate-at-least-32-random-bytes
```

Generate suitable random values with `openssl rand -base64 32`. The auth password
is the value you type into the OAuth consent page. The signing key and bearer token
should be random machine credentials.

Start the server:

```bash
python tiny_server.py
```

Useful local URLs:

- MCP endpoint: `http://127.0.0.1:8000/mcp`
- Health check: `http://127.0.0.1:8000/health`
- OAuth metadata: `http://127.0.0.1:8000/.well-known/oauth-authorization-server`

Test a bearer-authenticated tool call:

```bash
python tiny_client.py cardiology
```

## Deploy on Render

This repository includes a non-root `Dockerfile` and a `render.yaml` Blueprint.
The Blueprint creates a free web service, generates the OAuth signing key and
bearer token, and prompts for the two values that must be supplied manually.

1. Rotate the exposed Supabase password and update your local `.env`.
2. Push this folder to a private GitHub or GitLab repository.
3. In Render, create a new Blueprint from that repository.
4. Enter `SUPABASE_DB_URL` and `MCP_AUTH_PASSWORD` when prompted. The password
   must be at least 16 characters.
5. Deploy and wait for `/health` to pass.
6. Copy the service URL and append `/mcp`, for example
   `https://bis-physicians-mcp.onrender.com/mcp`.

The application derives its external URL from Render's
`RENDER_EXTERNAL_HOSTNAME`. On another host, set `MCP_SERVER_URL` explicitly to
the final public HTTPS `/mcp` URL. The process binds to `0.0.0.0` and uses the
host-provided `PORT`.

Free Render services can sleep when idle, which can cause a connector's first
request to time out. Use an always-on instance for reliable day-to-day use.

## Connect Claude

Claude custom connectors support remote Streamable HTTP servers with OAuth.

1. Open **Settings > Connectors**.
2. Choose **Add custom connector**.
3. Enter the deployed `https://.../mcp` URL.
4. Choose OAuth if prompted and complete authorization.
5. On this server's authorization page, enter `MCP_AUTH_PASSWORD`.

For Claude Team or Enterprise, an owner might need to add the organization
connector before members can connect it individually.

## Connect Lovable

1. Open the connector catalog, select **+**, then **MCP server**.
2. Give the connector a name and enter the deployed `https://.../mcp` URL.
3. Choose **OAuth** and authorize with `MCP_AUTH_PASSWORD`.

Lovable also supports **Bearer token or API key**. If you choose that option,
copy the generated `MCP_BEARER_TOKEN` from the deployment's secret settings.
Never paste the Supabase URL into Lovable; clients only receive an OAuth access
token or the dedicated MCP bearer token.

## Other MCP clients

Use the same `https://.../mcp` URL with OAuth. For clients that support bearer
headers, send:

```text
Authorization: Bearer <MCP_BEARER_TOKEN>
```

For Codex:

```toml
[mcp_servers.bis_physicians]
url = "https://YOUR-SERVICE.example/mcp"
bearer_token_env_var = "MCP_BEARER_TOKEN"
```

## Tests

The default suite never contacts Supabase:

```bash
python -m pytest -q
```

Run the live read-only database check explicitly:

```bash
RUN_SUPABASE_INTEGRATION=1 python -m pytest -q
```

## Deployment notes

- Keep the service at one instance. Dynamic OAuth client registrations are held
  in process memory; if the instance is replaced, a client might need to reconnect
  and authorize again. Signed access and refresh tokens use the stable
  `MCP_OAUTH_SIGNING_KEY`.
- Do not change `MCP_OAUTH_SIGNING_KEY` unless you intend to invalidate existing
  OAuth tokens.
- Rotate `MCP_BEARER_TOKEN` immediately if it is exposed.
- Logs record the authenticated subject, tool, dataset, status, and row count.
  Database credentials are redacted from error details.
