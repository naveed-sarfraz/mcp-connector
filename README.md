# InsightMonk Reports MCP Server

An authenticated MCP server for searching, reading, searching within, and downloading InsightMonk reports from ChatGPT, Claude, MCP Inspector, and other OAuth-capable MCP clients.

The old Supabase physician connector has been removed. Supabase is not used anywhere in this repository now. The unrelated `outlook-calendar` project still has its own Supabase usage and was not changed.

## Architecture

The server reuses the existing systems in `/home/naveed/BIS/community-api`:

- InsightMonk users sign in through `POST /v1/auth/login`; MFA users finish through `POST /v1/auth/verifyOTP`.
- The returned application JWT is verified with the same `JWT_SECRET` as `community-api`.
- Every MCP request reloads the user from the existing MySQL `users` table. Missing, inactive, or soft-deleted users are denied immediately.
- All active roles, plans, and companies can connect to MCP. No new MCP user table or copied user record is created.
- Existing full-report rules remain in force: platinum users, matching gold topic subscribers, individual purchases, and company purchases for client administrators.
- A server-side InsightMonk service account calls the report APIs only after user authorization. Its credentials and token never reach the MCP client.

Remote clients use OAuth 2.1 authorization code flow with PKCE S256, dynamic client registration, protected-resource metadata, rotating refresh tokens, revocation, and resource-bound access tokens. The AI platform stores and refreshes its connection. The user enters InsightMonk credentials only in the MCP server's HTTPS login page during initial authorization; passwords are never stored.

Three small MySQL tables store OAuth protocol state only:

- `mcp_oauth_clients`
- `mcp_oauth_artifacts`
- `mcp_oauth_revocations`

They do not duplicate application users. Client secrets are encrypted, authorization codes are hashed and one-time use, refresh tokens are hashed and rotated, and access tokens are signed. Active connections remain persistent because each normal refresh rotates the token and renews its lifetime.

## MCP tools

- `search_reports(search, from_date, to_date, report_type, page, limit)`
- `get_report_content(report_id)`
- `download_report_pdf(report_id)`
- `search_report_content(report_id, query, limit)`

PDFs are downloaded only from validated public HTTPS hosts, with redirect and size limits. Text is extracted page by page with page numbers and cached in memory for 15 minutes by default. Empty-image pages are reported as requiring OCR. The original PDF is returned as an embedded MCP resource, not as a signed storage URL.

## Required environment variables

Copy `.env.example` to `.env` and configure:

```dotenv
INSIGHTMONK_BASE_URL=https://community-api.insightmonk.com
INSIGHTMONK_EMAIL=service-account@example.com
INSIGHTMONK_PASSWORD=...

# Same value and database used by community-api.
JWT_SECRET=...
MYSQL_HOST=...
MYSQL_PORT=3306
MYSQL_USER=...
MYSQL_PASSWORD=...
MYSQL_DATABASE=...
MYSQL_SSL=1
MYSQL_SSL_CA=

MCP_SERVER_URL=http://127.0.0.1:8000/mcp
MCP_OAUTH_SIGNING_KEY=at-least-32-random-characters
MCP_AUTO_MIGRATE=1
MCP_TRANSPORT=streamable-http
```

Generate a signing key with:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Keep `MCP_OAUTH_SIGNING_KEY` stable across deployments and instances. Changing it signs everyone out. Do not reuse `JWT_SECRET` as the MCP signing key.

The service account must be able to retrieve all PDFs that legitimately authorized users may request. The MCP server independently enforces the connecting user's plan, topic, purchase, and company rules before returning content.

## Local installation

Python 3.11 or newer is required:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
cp .env.example .env
python tiny_server.py
```

Local endpoints:

- MCP: `http://127.0.0.1:8000/mcp`
- health: `http://127.0.0.1:8000/health`
- OAuth metadata: `http://127.0.0.1:8000/.well-known/oauth-authorization-server`
- protected-resource metadata: `http://127.0.0.1:8000/.well-known/oauth-protected-resource/mcp`

With `MCP_AUTO_MIGRATE=1`, startup creates the three MCP OAuth tables if needed. If the production DB role has no DDL permission, run `migrations/001_mcp_oauth.sql` once with a migration account and set `MCP_AUTO_MIGRATE=0`.

## MCP Inspector

For the complete remote-style OAuth flow:

```bash
python tiny_server.py
npx @modelcontextprotocol/inspector
```

In Inspector, choose Streamable HTTP and enter `http://127.0.0.1:8000/mcp`. Start OAuth, sign in with an active InsightMonk account, then list and call the tools.

For STDIO-only local development, set an existing active application user ID. This bypass exists only on loopback when the transport is explicitly STDIO:

```bash
MCP_TRANSPORT=stdio MCP_DEV_USER_ID=123 \
  npx @modelcontextprotocol/inspector .venv/bin/python tiny_server.py
```

The included smoke client uses the same development mode:

```bash
python tiny_client.py "artificial intelligence" --user-id 123
```

Never set `MCP_DEV_USER_ID` on Render or any remote deployment.

## Deploy on Render

The repository includes a non-root Docker image and `render.yaml` Blueprint.

1. Push this repository to GitHub or GitLab.
2. In Render, create a Blueprint from the repository.
3. Set the prompted InsightMonk, JWT, and MySQL values. `JWT_SECRET` must match `community-api`.
4. Set `MYSQL_SSL=1` when the database supports TLS. If it requires a CA file, add that file as a Render secret file and set `MYSQL_SSL_CA` to its path.
5. Let Render generate `MCP_OAUTH_SIGNING_KEY`, then keep the resulting value stable.
6. Deploy and verify `/health`.

`MCP_SERVER_URL` is automatically derived from `RENDER_EXTERNAL_HOSTNAME` as `https://HOST/mcp`. On another hosting provider, set it explicitly to the final public HTTPS URL before startup.

Use an always-on Render plan. OAuth callbacks and MCP calls are sensitive to cold-start timeouts, and clients retain the configured public URL. Multiple instances can share the same application database and `MCP_OAUTH_SIGNING_KEY`.

## Connect AI platforms

Add the deployed `https://YOUR-HOST/mcp` URL as a custom remote MCP server or connector. The client discovers OAuth metadata, dynamically registers, opens the InsightMonk login page, and saves the resulting connection. Do not configure a password, static bearer token, or API key in the AI platform.

For ChatGPT, create a custom MCP app/connector with the remote URL and complete the browser authorization flow. For Claude and other compatible clients, add a custom remote connector and allow automatic OAuth discovery. Exact menu labels vary by account type and platform release.

## Token management

- InsightMonk service-token expiry is decoded from the JWT `exp` claim. The observed production token currently lasts 12 hours, so the code does not assume the older 24-hour value.
- The token is renewed five minutes before expiry.
- A process-wide async lock prevents concurrent requests from logging in repeatedly.
- An upstream HTTP 401 clears the cached token, logs in again, and retries exactly once.
- MCP access tokens last one hour by default. Rotating refresh tokens use a sliding 30-day lifetime.
- Deactivating or soft-deleting a user invalidates access on the next request, even if the MCP token has not expired.

## Tests

Tests mock all InsightMonk HTTP calls and never use real credentials:

```bash
python -m pytest -q
```

Coverage includes active/inactive/missing users, expired JWTs, OAuth code and refresh rotation, token renewal and concurrency, retry after 401, report search/retrieval, entitlement and company boundaries, invalid report IDs, PDF extraction, OCR detection, caching, SSRF checks, and all four MCP tools.

## Verified API response assumptions

The production API was inspected without logging sensitive values:

- `/v1/auth/login` returns `access_token`, `refresh_token`, `uid`, `cid`, `role`, `status`, `message`, and `token_type`.
- The access JWT includes `user_id`, `company_id`, `role`, `token_type`, `iat`, `exp`, and `jti`.
- `/v1/reports/search` returns `success`, `list`, `page`, `limit`, `total`, and `next`.
- `/v1/reports/getContent` returns `success` plus `data`; `data` includes report metadata and a short-lived signed `url`.

The signed URL, tokens, passwords, authorization headers, and extracted report content are never written to logs. The current upstream report search implementation appears not to apply `to_date`; this MCP forwards the parameter correctly, but fixing that filter belongs in `community-api`. OCR itself is not implemented—scanned pages are identified so callers receive an explicit `ocr_required` result.
