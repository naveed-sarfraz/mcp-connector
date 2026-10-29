"""A public, read-only MCP view of one Supabase table."""

import json
import os
import re
from urllib.parse import urlparse

import psycopg
from dotenv import load_dotenv
from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from psycopg import sql
from starlette.requests import Request
from starlette.responses import JSONResponse

load_dotenv()

DATASETS = {
    "supabase_data": {
        "schema": "public",
        "table": "bis_physicians",
        "searchable_columns": ("physician_name", "specialty"),
    }
}
DEFAULT_DATASET = "supabase_data"


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
SUPABASE_DB_URL = os.getenv("SUPABASE_DB_URL")
DENIED_MESSAGE = "You do not have access to this dataset."
UNAVAILABLE_MESSAGE = "The dataset is temporarily unavailable."

if SERVER_URL_PARTS.hostname not in {"127.0.0.1", "localhost", "::1"}:
    if not SUPABASE_DB_URL:
        raise RuntimeError("Remote deployment is missing SUPABASE_DB_URL")
    if SERVER_URL_PARTS.scheme != "https":
        raise RuntimeError("MCP_SERVER_URL must use HTTPS for remote deployment")
    if SERVER_URL_PARTS.path != "/mcp":
        raise RuntimeError("MCP_SERVER_URL must end with /mcp")


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


mcp = MCPServer(
    "Supabase physician dataset",
    instructions=(
        "Read-only physician lookup. Search only by physician name or specialty; "
        "never infer that an empty result proves a physician does not exist."
    ),
)


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
            "authentication": "none",
            "access": "public-read-only",
        }
    )


def _public_actor(tool: str, dataset: str) -> str:
    """Validate the fixed public dataset and return its audit-log actor."""
    if not isinstance(dataset, str) or dataset not in DATASETS:
        log_attempt("public", tool, dataset, "DENIED", 0)
        raise ToolError(DENIED_MESSAGE)
    return "public"


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
def describe_dataset() -> str:
    """Describe the physician dataset and the columns available for searching."""
    dataset = DEFAULT_DATASET
    user = _public_actor("describe_dataset", dataset)
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
def search_dataset(text: str, limit: int = 10) -> str:
    """Search physician names and specialties, returning at most 50 matches."""
    dataset = DEFAULT_DATASET
    user = _public_actor("search_dataset", dataset)
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
