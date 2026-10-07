"""A permission-checked, read-only MCP view of one Supabase table."""

import html
import json
import os
import re
from urllib.parse import urlparse

import psycopg
from dotenv import load_dotenv
from mcp.server import MCPServer
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from psycopg import sql
from pydantic import AnyHttpUrl
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse

from oauth_provider import OwnerOAuthProvider

load_dotenv()

DATASETS = {
    "supabase_data": {
        "schema": "public",
        "table": "bis_physicians",
        "searchable_columns": ("physician_name", "specialty"),
    }
}

PERMISSIONS = {
    "owner": {"supabase_data"},
    "asha": {"supabase_data"},
    "ravi": set(),
    "guest": set(),
}


def configured_server_url() -> str:
    """Return the externally reachable MCP URL or the local development URL."""
    configured_url = os.getenv("MCP_SERVER_URL")
    if configured_url:
        return configured_url.rstrip("/")
    render_hostname = os.getenv("RENDER_EXTERNAL_HOSTNAME")
    if render_hostname:
        return f"https://{render_hostname}/mcp"
    return "http://127.0.0.1:8000/mcp"


SERVER_URL = configured_server_url()
SERVER_URL_PARTS = urlparse(SERVER_URL)
SERVER_ORIGIN = f"{SERVER_URL_PARTS.scheme}://{SERVER_URL_PARTS.netloc}"
SUPABASE_DB_URL = os.getenv("SUPABASE_DB_URL")
MCP_AUTH_PASSWORD = os.getenv("MCP_AUTH_PASSWORD")
MCP_BEARER_TOKEN = os.getenv("MCP_BEARER_TOKEN")
MCP_OAUTH_SIGNING_KEY = os.getenv(
    "MCP_OAUTH_SIGNING_KEY", "local-development-signing-key"
)
DENIED_MESSAGE = "You do not have access to this dataset."
UNAVAILABLE_MESSAGE = "The dataset is temporarily unavailable."
# Temporary local testing mode: set True to enforce the per-user allowlist.
ENFORCE_USER_PERMISSIONS = False

if SERVER_URL_PARTS.hostname not in {"127.0.0.1", "localhost", "::1"}:
    missing_secrets = [
        name
        for name, value in (
            ("SUPABASE_DB_URL", SUPABASE_DB_URL),
            ("MCP_AUTH_PASSWORD", MCP_AUTH_PASSWORD),
            ("MCP_OAUTH_SIGNING_KEY", os.getenv("MCP_OAUTH_SIGNING_KEY")),
        )
        if not value
    ]
    if missing_secrets:
        raise RuntimeError(
            "Remote deployment is missing required secrets: "
            + ", ".join(missing_secrets)
        )
    if SERVER_URL_PARTS.scheme != "https":
        raise RuntimeError("MCP_SERVER_URL must use HTTPS for remote deployment")
    if SERVER_URL_PARTS.path != "/mcp":
        raise RuntimeError("MCP_SERVER_URL must end with /mcp")
    if len(MCP_AUTH_PASSWORD or "") < 16:
        raise RuntimeError("MCP_AUTH_PASSWORD must contain at least 16 characters")
    if (MCP_AUTH_PASSWORD or "").startswith("choose-"):
        raise RuntimeError("Replace the placeholder MCP_AUTH_PASSWORD")
    if len(MCP_OAUTH_SIGNING_KEY) < 32:
        raise RuntimeError("MCP_OAUTH_SIGNING_KEY must contain at least 32 characters")
    if MCP_OAUTH_SIGNING_KEY.startswith("generate-"):
        raise RuntimeError("Replace the placeholder MCP_OAUTH_SIGNING_KEY")
    if MCP_BEARER_TOKEN and len(MCP_BEARER_TOKEN) < 32:
        raise RuntimeError("MCP_BEARER_TOKEN must contain at least 32 characters")
    if MCP_BEARER_TOKEN and MCP_BEARER_TOKEN.startswith("generate-"):
        raise RuntimeError("Replace the placeholder MCP_BEARER_TOKEN")


def can_access(user: str, dataset: str) -> bool:
    """Return whether a known user is explicitly allowed to use a dataset."""
    return (
        isinstance(dataset, str)
        and dataset in DATASETS
        and dataset in PERMISSIONS.get(user, set())
    )


def log_attempt(
    user: str,
    tool: str,
    dataset: str,
    status: str,
    row_count: int,
    detail: str | None = None,
) -> None:
    """Write one structured event without logging credentials."""
    event = {
        "user": user,
        "tool": tool,
        "dataset": dataset,
        "status": status,
        "row_count": row_count,
    }
    if detail is not None:
        if SUPABASE_DB_URL:
            detail = detail.replace(SUPABASE_DB_URL, "[redacted connection string]")
        detail = re.sub(
            r"(?i)(postgres(?:ql)?://[^:/@\s]+:)[^@/\s]+@",
            r"\1[redacted]@",
            detail,
        )
        event["detail"] = detail
    print(json.dumps(event), flush=True)


oauth_provider = OwnerOAuthProvider(
    issuer_url=SERVER_ORIGIN,
    resource_url=SERVER_URL,
    signing_key=MCP_OAUTH_SIGNING_KEY,
    owner_password=MCP_AUTH_PASSWORD,
    bearer_token=MCP_BEARER_TOKEN,
)
mcp = MCPServer(
    "Supabase physician dataset",
    instructions=(
        "Read-only physician lookup. Search only by physician name or specialty; "
        "never infer that an empty result proves a physician does not exist."
    ),
    auth_server_provider=oauth_provider,
    auth=AuthSettings(
        issuer_url=AnyHttpUrl(SERVER_ORIGIN),
        resource_server_url=AnyHttpUrl(SERVER_URL),
        required_scopes=["datasets:read"],
        client_registration_options=ClientRegistrationOptions(
            enabled=True,
            valid_scopes=["datasets:read"],
            default_scopes=["datasets:read"],
        ),
        validate_token_resource=True,
    ),
)


def login_page(request_token: str, client_name: str, error: str | None = None) -> str:
    """Render the deliberately small connector authorization page."""
    error_html = (
        f'<p class="error" role="alert">{html.escape(error)}</p>' if error else ""
    )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Authorize physician connector</title>
  <style>
    :root {{ color-scheme: light dark; font-family: system-ui, sans-serif; }}
    body {{ margin: 0; min-height: 100vh; display: grid; place-items: center;
      background: #eef2f6; color: #17212b; }}
    main {{ width: min(26rem, calc(100% - 2rem)); padding: 2rem; border-radius: 1rem;
      background: white; box-shadow: 0 1rem 3rem #18324c22; }}
    h1 {{ margin-top: 0; font-size: 1.45rem; }}
    p {{ line-height: 1.5; }}
    label {{ display: block; margin: 1.25rem 0 .4rem; font-weight: 650; }}
    input, button {{ width: 100%; box-sizing: border-box; padding: .8rem;
      border-radius: .55rem; font: inherit; }}
    input {{ border: 1px solid #9aa7b4; }}
    button {{ margin-top: 1rem; border: 0; background: #1264a3; color: white;
      font-weight: 700; cursor: pointer; }}
    .error {{ padding: .7rem; border-radius: .4rem; background: #fff0f0; color: #a31515; }}
    .scope {{ color: #52616f; font-size: .92rem; }}
  </style>
</head>
<body>
  <main>
    <h1>Authorize physician search</h1>
    <p><strong>{html.escape(client_name)}</strong> is requesting read-only access to
      physician names and specialties.</p>
    <p class="scope">No tool can insert, update, or delete database rows.</p>
    {error_html}
    <form method="post" action="/oauth/login">
      <input type="hidden" name="request" value="{html.escape(request_token, quote=True)}">
      <label for="password">Connector password</label>
      <input id="password" name="password" type="password" required autocomplete="current-password">
      <button type="submit">Authorize connector</button>
    </form>
  </main>
</body>
</html>"""


@mcp.custom_route("/health", methods=["GET"], include_in_schema=False)
async def health(_: Request) -> JSONResponse:
    return JSONResponse({"status": "ok"})


@mcp.custom_route("/", methods=["GET"], include_in_schema=False)
async def service_info(_: Request) -> JSONResponse:
    return JSONResponse(
        {
            "name": "Supabase physician dataset MCP server",
            "transport": "streamable-http",
            "mcp_url": SERVER_URL,
            "authentication": ["oauth", "bearer"]
            if MCP_BEARER_TOKEN
            else ["oauth"],
        }
    )


@mcp.custom_route("/oauth/login", methods=["GET", "POST"], include_in_schema=False)
async def oauth_login(request: Request) -> HTMLResponse | RedirectResponse:
    if request.method == "GET":
        request_token = request.query_params.get("request", "")
        client_name = oauth_provider.login_client_name(request_token)
        if client_name is None:
            return HTMLResponse("Invalid or expired authorization request.", status_code=400)
        return HTMLResponse(
            login_page(request_token, client_name),
            headers={"Cache-Control": "no-store", "X-Frame-Options": "DENY"},
        )

    form = await request.form()
    request_token = str(form.get("request", ""))
    password = str(form.get("password", ""))
    redirect_url = oauth_provider.complete_login(request_token, password)
    if redirect_url is not None:
        return RedirectResponse(
            redirect_url,
            status_code=302,
            headers={"Cache-Control": "no-store"},
        )
    client_name = oauth_provider.login_client_name(request_token)
    if client_name is None:
        return HTMLResponse("Invalid or expired authorization request.", status_code=400)
    return HTMLResponse(
        login_page(request_token, client_name, "Incorrect connector password."),
        status_code=401,
        headers={"Cache-Control": "no-store", "X-Frame-Options": "DENY"},
    )


def _authorized_user(tool: str, dataset: str) -> str:
    """Verify the bearer identity and optionally enforce per-user access."""
    access_token = get_access_token()
    if access_token is None:
        log_attempt("unknown", tool, dataset, "DENIED", 0)
        raise ToolError("Authentication required.")

    user = access_token.subject or access_token.client_id
    if (
        not isinstance(dataset, str)
        or dataset not in DATASETS
        or (ENFORCE_USER_PERMISSIONS and not can_access(user, dataset))
    ):
        log_attempt(user, tool, dataset, "DENIED", 0)
        raise ToolError(DENIED_MESSAGE)
    return user


def query_supabase(dataset: str, text: str, limit: int) -> list[dict[str, str | None]]:
    """Search configured text columns using values bound as SQL parameters."""
    if not SUPABASE_DB_URL:
        raise RuntimeError("SUPABASE_DB_URL is not configured")

    config = DATASETS[dataset]
    columns = config["searchable_columns"]
    selected_columns = sql.SQL(", ").join(sql.Identifier(column) for column in columns)
    conditions = sql.SQL(" OR ").join(
        sql.SQL("{} ILIKE %s ESCAPE '\\'").format(sql.Identifier(column))
        for column in columns
    )
    statement = sql.SQL("SELECT {} FROM {}.{} WHERE ({}) LIMIT %s").format(
        selected_columns,
        sql.Identifier(config["schema"]),
        sql.Identifier(config["table"]),
        conditions,
    )
    escaped_text = text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    pattern = f"%{escaped_text}%"
    parameters = (*([pattern] * len(columns)), limit)

    with psycopg.connect(
        SUPABASE_DB_URL,
        connect_timeout=8,
        sslmode="require",
        options="-c default_transaction_read_only=on -c statement_timeout=10000",
    ) as connection:
        with connection.cursor() as cursor:
            cursor.execute(statement, parameters)
            return [dict(zip(columns, row)) for row in cursor.fetchall()]


@mcp.tool(
    title="Describe physician dataset",
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    ),
)
def describe_dataset(dataset: str) -> str:
    """Describe the searchable columns of an accessible dataset."""
    user = _authorized_user("describe_dataset", dataset)
    result = {
        "dataset": dataset,
        "searchable_columns": list(DATASETS[dataset]["searchable_columns"]),
    }
    log_attempt(user, "describe_dataset", dataset, "ALLOWED", 0)
    return json.dumps(result, indent=2)


@mcp.tool(
    title="Search physicians",
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
def search_dataset(dataset: str, text: str, limit: int = 10) -> str:
    """Find matching rows in an accessible dataset, with a bounded result size."""
    user = _authorized_user("search_dataset", dataset)
    search_text = text.strip() if isinstance(text, str) else ""
    if not 1 <= len(search_text) <= 100:
        log_attempt(
            user,
            "search_dataset",
            dataset,
            "DENIED",
            0,
            "search text must contain 1 to 100 characters",
        )
        raise ToolError("Search text must contain 1 to 100 characters.")

    bounded_limit = min(max(limit, 1), 50)
    try:
        rows = query_supabase(dataset, search_text, bounded_limit)
    except Exception as error:
        log_attempt(
            user,
            "search_dataset",
            dataset,
            "ERROR",
            0,
            f"{type(error).__name__}: {error}",
        )
        raise ToolError(UNAVAILABLE_MESSAGE) from None

    log_attempt(user, "search_dataset", dataset, "ALLOWED", len(rows))
    return json.dumps(rows, indent=2)


if __name__ == "__main__":
    mcp.run(
        transport="streamable-http",
        host="0.0.0.0",
        port=int(os.getenv("PORT", "8000")),
        json_response=True,
        stateless_http=True,
    )
