"""Authenticated InsightMonk Reports MCP server."""

from __future__ import annotations

import base64
import html
import json
import logging
import os
import re
from contextlib import asynccontextmanager
from datetime import date
from typing import Any, AsyncIterator

from mcp.server import MCPServer
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AuthorizeError
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.request_state import RequestStateSecurity
from mcp.types import BlobResourceContents, EmbeddedResource, ToolAnnotations
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from config import settings
from database import Database, UserAccess
from insightmonk_client import InsightMonkClient, InsightMonkError
from oauth_provider import InsightMonkOAuthProvider
from pdf_processor import PDFDocument, PDFProcessingError, PDFProcessor

logger = logging.getLogger("insightmonk_mcp")
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))

REPORT_ID_PATTERN = re.compile(r"^[0-9a-fA-F]{24}$")
database = Database(settings)
insightmonk = InsightMonkClient(settings)
pdf_processor = PDFProcessor(settings)
oauth_provider = InsightMonkOAuthProvider(settings, database)


@asynccontextmanager
async def lifespan(_: MCPServer) -> AsyncIterator[None]:
    settings.validate()
    if settings.auto_migrate:
        await database.migrate()
    else:
        await database.ping()
    # Fail deployment early if the service credentials are invalid. The manager
    # renews from JWT exp and re-authenticates once after an upstream 401.
    await insightmonk.access_token()
    try:
        yield
    finally:
        await insightmonk.close()
        await pdf_processor.close()


mcp = MCPServer(
    "InsightMonk Reports",
    instructions=(
        "Search and read InsightMonk research reports. Every request uses the signed-in "
        "user's current application authorization and existing report entitlements."
    ),
    auth_server_provider=oauth_provider,
    auth=AuthSettings(
        issuer_url=settings.issuer_url,
        resource_server_url=settings.server_url,
        required_scopes=[oauth_provider.scope],
        validate_token_resource=True,
        client_registration_options=ClientRegistrationOptions(
            enabled=True,
            valid_scopes=[oauth_provider.scope],
            default_scopes=[oauth_provider.scope],
        ),
        revocation_options=RevocationOptions(enabled=True),
    ),
    request_state_security=RequestStateSecurity(keys=[settings.oauth_signing_key]),
    lifespan=lifespan,
)


def _security_headers(response: Response) -> Response:
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; "
        "base-uri 'none'; frame-ancestors 'none'"
    )
    return response


def _login_page(
    request_token: str,
    *,
    client_name: str = "your AI assistant",
    error: str | None = None,
) -> HTMLResponse:
    safe_request = html.escape(request_token, quote=True)
    safe_client = html.escape(client_name)
    error_html = f'<p class="error">{html.escape(error)}</p>' if error else ""
    body = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Connect InsightMonk</title><style>
body{{font-family:system-ui,sans-serif;background:#f4f6f8;color:#17202a;margin:0;padding:2rem}}
main{{max-width:28rem;margin:4vh auto;background:white;padding:2rem;border-radius:14px;box-shadow:0 8px 30px #0001}}
label{{display:block;margin:1rem 0 .35rem}}input{{box-sizing:border-box;width:100%;padding:.75rem;border:1px solid #aeb6bf;border-radius:8px}}
button{{width:100%;margin-top:1.4rem;padding:.8rem;border:0;border-radius:8px;background:#145a8d;color:white;font-weight:650}}
.note{{font-size:.9rem;color:#566573}}.error{{color:#a93226}}
</style></head><body><main><h1>Connect InsightMonk</h1>
<p>Sign in once to authorize <strong>{safe_client}</strong> to read reports available to your InsightMonk account.</p>
{error_html}<form method="post" action="/oauth/login" autocomplete="on">
<input type="hidden" name="request" value="{safe_request}">
<label for="email">InsightMonk email</label><input id="email" name="email" type="email" maxlength="254" required autocomplete="username">
<label for="password">Password</label><input id="password" name="password" type="password" maxlength="128" required autocomplete="current-password">
<button type="submit">Sign in and connect</button></form>
<p class="note">Your password is sent only to InsightMonk for this login and is never stored by the MCP server or shared with the AI platform.</p>
</main></body></html>"""
    return _security_headers(HTMLResponse(body))  # type: ignore[return-value]


def _otp_page(mfa_state: str, *, error: str | None = None) -> HTMLResponse:
    safe_state = html.escape(mfa_state, quote=True)
    error_html = f'<p class="error">{html.escape(error)}</p>' if error else ""
    body = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Verify InsightMonk login</title><style>
body{{font-family:system-ui,sans-serif;background:#f4f6f8;color:#17202a;margin:0;padding:2rem}}main{{max-width:28rem;margin:8vh auto;background:white;padding:2rem;border-radius:14px}}
label{{display:block;margin:1rem 0 .35rem}}input{{box-sizing:border-box;width:100%;padding:.75rem}}button{{width:100%;margin-top:1.4rem;padding:.8rem;background:#145a8d;color:white;border:0;border-radius:8px}}.error{{color:#a93226}}</style>
</head><body><main><h1>Verify your login</h1><p>Enter the one-time code sent by InsightMonk.</p>{error_html}
<form method="post" action="/oauth/verify"><input type="hidden" name="state" value="{safe_state}">
<label for="otp">Verification code</label><input id="otp" name="otp" inputmode="numeric" maxlength="12" required autocomplete="one-time-code">
<button type="submit">Verify and connect</button></form></main></body></html>"""
    return _security_headers(HTMLResponse(body))  # type: ignore[return-value]


async def _client_name(request_token: str) -> str:
    try:
        payload = oauth_provider.decode_authorization_request(request_token)
        client = await oauth_provider.get_client(str(payload.get("client_id", "")))
        return client.client_name if client and client.client_name else "your AI assistant"
    except AuthorizeError:
        return "your AI assistant"


@mcp.custom_route("/oauth/login", methods=["GET", "POST"], include_in_schema=False)
async def oauth_login(request: Request) -> Response:
    if request.method == "GET":
        request_token = request.query_params.get("request", "")
        try:
            oauth_provider.decode_authorization_request(request_token)
        except AuthorizeError:
            return _security_headers(HTMLResponse("Login request is invalid or expired.", status_code=400))
        return _login_page(request_token, client_name=await _client_name(request_token))

    form = await request.form()
    request_token = str(form.get("request") or "")
    email = str(form.get("email") or "").strip()
    password = str(form.get("password") or "")
    try:
        oauth_provider.decode_authorization_request(request_token)
    except AuthorizeError:
        return _security_headers(HTMLResponse("Login request is invalid or expired.", status_code=400))
    client_name = await _client_name(request_token)
    if not email or len(email) > 254 or not password or len(password) > 128:
        return _login_page(request_token, client_name=client_name, error="Enter a valid email and password.")
    try:
        result = await insightmonk.login_user(email, password)
        if result.status == "mfa" and result.email:
            return _otp_page(oauth_provider.create_mfa_state(result.email, request_token))
        if result.user_id is None:
            raise InsightMonkError("InsightMonk returned an invalid login response.")
        redirect_url = await oauth_provider.complete_authorization(request_token, result.user_id)
        return _security_headers(RedirectResponse(redirect_url, status_code=302))
    except (InsightMonkError, AuthorizeError) as error:
        return _login_page(request_token, client_name=client_name, error=str(error))


@mcp.custom_route("/oauth/verify", methods=["POST"], include_in_schema=False)
async def oauth_verify(request: Request) -> Response:
    form = await request.form()
    mfa_token = str(form.get("state") or "")
    otp = str(form.get("otp") or "").strip()
    try:
        mfa = oauth_provider.decode_mfa_state(mfa_token)
        if not otp or len(otp) > 12:
            return _otp_page(mfa_token, error="Enter a valid verification code.")
        result = await insightmonk.verify_user_otp(str(mfa["email"]), otp)
        if result.user_id is None:
            raise InsightMonkError("InsightMonk returned an invalid verification response.")
        redirect_url = await oauth_provider.complete_authorization(
            str(mfa["authorization_request"]), result.user_id
        )
        return _security_headers(RedirectResponse(redirect_url, status_code=302))
    except (InsightMonkError, AuthorizeError, KeyError) as error:
        message = str(error) if not isinstance(error, KeyError) else "The verification request is invalid."
        return _otp_page(mfa_token, error=message)


@mcp.custom_route("/health", methods=["GET"], include_in_schema=False)
async def health(_: Request) -> JSONResponse:
    return JSONResponse({"status": "ok"})


@mcp.custom_route("/", methods=["GET"], include_in_schema=False)
async def service_info(_: Request) -> JSONResponse:
    return JSONResponse(
        {
            "name": "InsightMonk Reports MCP server",
            "transport": "streamable-http",
            "mcp_url": settings.server_url,
            "authentication": "OAuth 2.1 authorization code with PKCE",
            "access_policy": "all active InsightMonk users; existing report entitlements apply",
        }
    )


def _audit(tool: str, user_id: int | None, status: str, report_id: str | None = None) -> None:
    event: dict[str, Any] = {"tool": tool, "user_id": user_id, "status": status}
    if report_id:
        event["report_id"] = report_id
    logger.info(json.dumps(event, separators=(",", ":")))


async def require_current_user() -> UserAccess:
    access_token = get_access_token()
    subject = access_token.subject if access_token else None
    if subject is None and settings.dev_mode and os.getenv("MCP_TRANSPORT") == "stdio":
        subject = os.getenv("MCP_DEV_USER_ID")
    if subject is None:
        raise ToolError("Authentication is required.")
    try:
        user = await database.get_user(subject)
    except Exception:
        raise ToolError("User authorization is temporarily unavailable.") from None
    if user is None or not user.mcp_allowed:
        raise ToolError("This InsightMonk account is not authorized to use MCP.")
    return user


def _validated_report_id(report_id: str) -> str:
    value = report_id.strip() if isinstance(report_id, str) else ""
    if not REPORT_ID_PATTERN.fullmatch(value):
        raise ToolError("report_id must be a 24-character hexadecimal ID.")
    return value.lower()


def _metadata_without_pdf_url(data: dict[str, Any]) -> dict[str, Any]:
    sensitive_keys = {"url", "access_token", "refresh_token", "password"}
    return {key: value for key, value in data.items() if key.lower() not in sensitive_keys}


async def _report_document(tool: str, report_id: str) -> tuple[UserAccess, dict[str, Any], PDFDocument]:
    user = await require_current_user()
    normalized_id = _validated_report_id(report_id)
    try:
        report = await insightmonk.get_report_content(normalized_id)
        raw_topics = report.get("topics")
        topics = raw_topics if isinstance(raw_topics, list) else []
        try:
            allowed = await database.can_access_full_report(user, normalized_id, topics)
        except Exception:
            _audit(tool, user.user_id, "ERROR", normalized_id)
            raise ToolError("Report authorization is temporarily unavailable.") from None
        if not allowed:
            _audit(tool, user.user_id, "DENIED", normalized_id)
            raise ToolError("This report is not available to your InsightMonk account.")
        document = await pdf_processor.get_document(normalized_id, str(report["url"]))
        return user, report, document
    except ToolError:
        raise
    except (InsightMonkError, PDFProcessingError) as error:
        _audit(tool, user.user_id, "ERROR", normalized_id)
        raise ToolError(str(error)) from None
    except Exception:
        _audit(tool, user.user_id, "ERROR", normalized_id)
        raise ToolError("The report is temporarily unavailable.") from None


READ_ONLY = ToolAnnotations(
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=True,
)


@mcp.tool(title="Search InsightMonk reports", annotations=READ_ONLY)
async def search_reports(
    search: str,
    from_date: str = "2000-01-01",
    to_date: str = "",
    report_type: str = "Full",
    page: int = 1,
    limit: int = 20,
) -> dict[str, Any]:
    """Search report metadata using configurable text, dates, type, page, and limit."""
    user = await require_current_user()
    search_text = search.strip() if isinstance(search, str) else ""
    if len(search_text) > 200:
        raise ToolError("search must contain at most 200 characters.")
    effective_to_date = to_date or date.today().isoformat()
    try:
        start = date.fromisoformat(from_date)
        end = date.fromisoformat(effective_to_date)
    except ValueError:
        raise ToolError("from_date and to_date must use YYYY-MM-DD.") from None
    if start > end:
        raise ToolError("from_date must not be after to_date.")
    normalized_type = report_type.strip() if isinstance(report_type, str) else ""
    if not normalized_type or len(normalized_type) > 40:
        raise ToolError("report_type must contain 1 to 40 characters.")
    if not 1 <= page <= 10000:
        raise ToolError("page must be between 1 and 10000.")
    if not 1 <= limit <= 100:
        raise ToolError("limit must be between 1 and 100.")

    payload = {
        "search": search_text,
        "from_date": from_date,
        "to_date": effective_to_date,
        "type": normalized_type,
        "page": page,
        "limit": limit,
    }
    try:
        result = await insightmonk.search_reports(payload)
    except InsightMonkError as error:
        _audit("search_reports", user.user_id, "ERROR")
        raise ToolError(str(error)) from None
    except Exception:
        _audit("search_reports", user.user_id, "ERROR")
        raise ToolError("Report search is temporarily unavailable.") from None
    _audit("search_reports", user.user_id, "ALLOWED")
    return result


@mcp.tool(title="Get report content", annotations=READ_ONLY)
async def get_report_content(report_id: str) -> dict[str, Any]:
    """Return authorized report metadata and page-numbered extracted PDF text."""
    user, report, document = await _report_document("get_report_content", report_id)
    remaining = settings.pdf_max_extracted_characters
    pages: list[dict[str, Any]] = []
    truncated = False
    for page_data in document.pages:
        if remaining <= 0:
            truncated = True
            break
        text = page_data.text
        if len(text) > remaining:
            text = text[:remaining]
            truncated = True
        pages.append({"page_number": page_data.page_number, "text": text})
        remaining -= len(text)
    _audit("get_report_content", user.user_id, "ALLOWED", document.report_id)
    return {
        "report": _metadata_without_pdf_url(report),
        "page_count": len(document.pages),
        "pages": pages,
        "truncated": truncated,
        "ocr_required": bool(document.ocr_required_pages),
        "ocr_required_pages": list(document.ocr_required_pages),
    }


@mcp.tool(title="Download report PDF", annotations=READ_ONLY)
async def download_report_pdf(report_id: str) -> EmbeddedResource:
    """Return the authorized original PDF as an embedded MCP file resource."""
    user, report, document = await _report_document("download_report_pdf", report_id)
    if len(document.content) > settings.pdf_max_embedded_bytes:
        raise ToolError(
            "The PDF is too large to return through MCP; use the InsightMonk application to download it."
        )
    title = str(report.get("reportName") or document.report_id)
    safe_name = re.sub(r"[^A-Za-z0-9._-]+", "-", title).strip("-.")[:100] or document.report_id
    _audit("download_report_pdf", user.user_id, "ALLOWED", document.report_id)
    return EmbeddedResource(
        resource=BlobResourceContents(
            uri=f"insightmonk://reports/{document.report_id}/{safe_name}.pdf",
            mimeType="application/pdf",
            blob=base64.b64encode(document.content).decode("ascii"),
        )
    )


@mcp.tool(title="Search inside a report", annotations=READ_ONLY)
async def search_report_content(
    report_id: str, query: str, limit: int = 20
) -> dict[str, Any]:
    """Search an authorized report and return matching passages with PDF page numbers."""
    search_text = query.strip() if isinstance(query, str) else ""
    if not 1 <= len(search_text) <= 200:
        raise ToolError("query must contain 1 to 200 characters.")
    if not 1 <= limit <= 50:
        raise ToolError("limit must be between 1 and 50.")
    user, report, document = await _report_document("search_report_content", report_id)
    matches = pdf_processor.search(document, search_text, limit=limit)
    _audit("search_report_content", user.user_id, "ALLOWED", document.report_id)
    return {
        "report": _metadata_without_pdf_url(report),
        "query": search_text,
        "matches": matches,
        "match_count": len(matches),
        "ocr_required": bool(document.ocr_required_pages),
        "ocr_required_pages": list(document.ocr_required_pages),
    }


if __name__ == "__main__":
    transport = os.getenv("MCP_TRANSPORT", "streamable-http").strip().lower()
    if transport == "stdio":
        mcp.run(transport="stdio")
    elif transport == "streamable-http":
        mcp.run(
            transport="streamable-http",
            host="0.0.0.0",
            port=int(os.getenv("PORT", "8000")),
            json_response=True,
            stateless_http=True,
        )
    else:
        raise RuntimeError("MCP_TRANSPORT must be 'stdio' or 'streamable-http'")
