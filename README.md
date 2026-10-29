# Supabase Physician Search MCP Server

A public, read-only remote MCP server for searching `public.bis_physicians` by
`physician_name` or `specialty`.

The server uses stateless Streamable HTTP and does not request a password, API
key, bearer token, or OAuth login. Users add the public MCP URL once in ChatGPT,
Claude, Codex, or another Streamable HTTP client. The AI platform keeps that
connector configuration in the user's platform account and reconnects without
asking for MCP credentials.

This is intentionally anonymous access: signing in to an AI platform does not
send that user's platform identity to a third-party MCP server. Do not expose
private or per-user data through this server without adding standards-based OAuth
through an external identity provider.

## Security model

- The public tools can only read physician names and specialties.
- Database sessions force `default_transaction_read_only=on` and use TLS.
- SQL identifiers are fixed in source and all search input is parameterized.
- Searches accept 1–100 characters and return at most 50 rows.
- Tool metadata marks every operation read-only, non-destructive, and idempotent.
- Database credentials stay on the server and are redacted from error logs.
- Remote deployments require HTTPS and the MCP path must be `/mcp`.

Because there is no MCP authentication, anyone who knows the URL can query these
two public fields. Add rate limiting at the hosting edge and use a dedicated,
read-only database role. If the data should not be public, use an OAuth identity
provider instead of this anonymous mode.

## Important security step

An earlier copy of `.env.example` contained a real Supabase password. Rotate that
database password in Supabase before deploying. Use a dedicated read-only database
role for this connector when possible. `.env.example` contains placeholders only,
and `.env` is excluded from Git and Docker builds.

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
```

Start the server:

```bash
python tiny_server.py
```

Useful local URLs:

- MCP endpoint: `http://127.0.0.1:8000/mcp`
- Health check: `http://127.0.0.1:8000/health`
- Service metadata: `http://127.0.0.1:8000/`

Try an unauthenticated tool call:

```bash
python tiny_client.py cardiology
```

## Deploy on Render

This repository includes a non-root `Dockerfile` and a `render.yaml` Blueprint.

1. Rotate the exposed Supabase password and update your local `.env`.
2. Push this folder to a private GitHub or GitLab repository.
3. In Render, create a Blueprint from that repository.
4. Enter `SUPABASE_DB_URL` when prompted.
5. Deploy and wait for `/health` to pass.
6. Copy the service URL and append `/mcp`, for example
   `https://bis-physicians-mcp.onrender.com/mcp`.

The application derives its external URL from `RENDER_EXTERNAL_HOSTNAME`. On
another host, set `MCP_SERVER_URL` to the final public HTTPS `/mcp` URL. The
process binds to `0.0.0.0` and uses the host-provided `PORT`.

Free Render services can sleep when idle, which can cause a connector's first
request to time out. Use an always-on instance for reliable day-to-day use and a
stable URL so saved platform connections continue working.

## Connect ChatGPT

1. In ChatGPT on the web, open **Plugins**, select **+**, then **Add custom MCP
   server**.
2. Enter the deployed `https://.../mcp` URL.
3. Choose no authentication if ChatGPT asks for an authentication method.
4. Create and install the plugin, then enable it in a conversation.

Workspace permissions and security restrictions can control whether a user may
add a custom MCP server.

## Connect Claude

1. Open **Customize > Connectors**.
2. Choose **+ Add**, then **Add custom connector**.
3. Enter the deployed `https://.../mcp` URL.
4. Under **Authentication**, select **No sign in**.
5. Add the connector and enable it in a conversation.

Team and Enterprise administrators may need to add the organization connector
before members can enable it. Claude stores remote connectors in the user's
Claude account, so the connection is available across supported Claude clients.

## Connect Codex

Add the URL without a token or authorization header:

```toml
[mcp_servers.bis_physicians]
url = "https://YOUR-SERVICE.example/mcp"
```

## Other MCP clients

Configure the same `https://.../mcp` URL as a Streamable HTTP server. Select
`None`, `No authentication`, or `No sign in` when the client asks for an
authentication method. Do not send an `Authorization` header.

## Tests

The default suite never contacts Supabase:

```bash
python -m pytest -q
```

Run the live read-only database check explicitly:

```bash
RUN_SUPABASE_INTEGRATION=1 python -m pytest -q
```

## Operations

- Stateless HTTP allows multiple service instances without sticky sessions.
- Keep the public URL stable; AI platforms retain that URL as the connector.
- Use an always-on deployment to avoid cold-start timeouts.
- Apply edge rate limits and monitor the structured tool audit logs.
- Rotate any old `MCP_AUTH_PASSWORD`, `MCP_OAUTH_SIGNING_KEY`, or
  `MCP_BEARER_TOKEN` values that were exposed, then remove them from deployment
  settings; this version does not read them.
