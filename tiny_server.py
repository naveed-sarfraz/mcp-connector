"""Open InsightMonk Reports MCP server backed by public report APIs."""

from __future__ import annotations

import base64
import json
import logging
import os
import re
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import BlobResourceContents, EmbeddedResource, ToolAnnotations
from starlette.requests import Request
from starlette.responses import JSONResponse

from config import settings
from insightmonk_client import InsightMonkClient, InsightMonkError
from pdf_processor import PDFDocument, PDFProcessingError, PDFProcessor

logger = logging.getLogger("insightmonk_mcp")
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))

REPORT_ID_PATTERN = re.compile(r"^[0-9a-fA-F]{24}$")
insightmonk = InsightMonkClient(settings)
pdf_processor = PDFProcessor(settings)


@asynccontextmanager
async def lifespan(_: MCPServer) -> AsyncIterator[None]:
    settings.validate()
    try:
        yield
    finally:
        await insightmonk.close()
        await pdf_processor.close()


mcp = MCPServer(
    "InsightMonk Reports",
    instructions=(
        "Search and read active InsightMonk reports through the public report API. "
        "No connector authentication is required. For broad searches, continue with "
        "nextCursor while hasMore is true. Prefer the latest edition unless the user "
        "explicitly asks for historical editions."
    ),
    lifespan=lifespan,
)


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
            "authentication": "none",
            "access_policy": "public access to active reports exposed by the public API",
        }
    )


def _audit(tool: str, status: str, report_id: str | None = None) -> None:
    event: dict[str, Any] = {"tool": tool, "status": status}
    if report_id:
        event["report_id"] = report_id
    logger.info(json.dumps(event, separators=(",", ":")))


def _validated_report_id(report_id: str) -> str:
    value = report_id.strip() if isinstance(report_id, str) else ""
    if not REPORT_ID_PATTERN.fullmatch(value):
        raise ToolError("report_id must be a 24-character hexadecimal ID.")
    return value.lower()


def _metadata_without_pdf_url(data: dict[str, Any]) -> dict[str, Any]:
    sensitive_keys = {
        "url",
        "access_token",
        "refresh_token",
        "authorization",
        "password",
    }

    def redact(value: Any) -> Any:
        if isinstance(value, dict):
            return {
                key: redact(item)
                for key, item in value.items()
                if key.lower() not in sensitive_keys
            }
        if isinstance(value, list):
            return [redact(item) for item in value]
        return value

    result = redact(data)
    return result if isinstance(result, dict) else {}


async def _report_document(
    tool: str, report_id: str
) -> tuple[dict[str, Any], PDFDocument]:
    normalized_id = _validated_report_id(report_id)
    try:
        report = await insightmonk.get_report_content(normalized_id)
        pdf = report.get("pdf")
        if not isinstance(pdf, dict) or not isinstance(pdf.get("url"), str):
            raise InsightMonkError("This report does not include a downloadable PDF.")
        document = await pdf_processor.get_document(normalized_id, pdf["url"])
        return report, document
    except ToolError:
        raise
    except (InsightMonkError, PDFProcessingError) as error:
        _audit(tool, "ERROR", normalized_id)
        raise ToolError(str(error)) from None
    except Exception:
        _audit(tool, "ERROR", normalized_id)
        raise ToolError("The report is temporarily unavailable.") from None


READ_ONLY = ToolAnnotations(
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=True,
)


@mcp.tool(title="Search InsightMonk reports", annotations=READ_ONLY)
async def search_reports(
    query: str,
    limit: int = 20,
    cursor: str = "",
    report_ids: list[str] | None = None,
    topics: list[str] | None = None,
    industry_type: str = "",
    year_from: int | None = None,
    year_to: int | None = None,
    latest_only: bool = True,
) -> dict[str, Any]:
    """Search all indexed active reports and return passages with citations.

    When hasMore is true, call this tool again promptly with nextCursor as cursor
    and keep every other argument unchanged. Cursors expire after two minutes.
    """
    search_text = query.strip() if isinstance(query, str) else ""
    if not 2 <= len(search_text) <= 500:
        raise ToolError("query must contain 2 to 500 characters.")
    if not 1 <= limit <= 50:
        raise ToolError("limit must be between 1 and 50.")
    cursor_value = cursor.strip() if isinstance(cursor, str) else ""
    if len(cursor_value) > 12000:
        raise ToolError("cursor is invalid.")

    normalized_report_ids = report_ids or []
    if len(normalized_report_ids) > 50 or any(
        not isinstance(value, str) or not REPORT_ID_PATTERN.fullmatch(value.strip())
        for value in normalized_report_ids
    ):
        raise ToolError("report_ids must contain at most 50 valid report IDs.")
    normalized_report_ids = [value.strip().lower() for value in normalized_report_ids]

    normalized_topics = topics or []
    if len(normalized_topics) > 20 or any(
        not isinstance(value, str) or not 1 <= len(value.strip()) <= 100
        for value in normalized_topics
    ):
        raise ToolError("topics must contain at most 20 non-empty values.")
    normalized_topics = [value.strip() for value in normalized_topics]

    normalized_industry = (
        industry_type.strip() if isinstance(industry_type, str) else ""
    )
    if len(normalized_industry) > 100:
        raise ToolError("industry_type must contain at most 100 characters.")
    if year_from is not None and not 1900 <= year_from <= 2100:
        raise ToolError("year_from must be between 1900 and 2100.")
    if year_to is not None and not 1900 <= year_to <= 2100:
        raise ToolError("year_to must be between 1900 and 2100.")
    if year_from is not None and year_to is not None and year_from > year_to:
        raise ToolError("year_from must not be after year_to.")

    payload: dict[str, Any] = {
        "query": search_text,
        "limit": limit,
        "latestOnly": latest_only,
    }
    if cursor_value:
        payload["cursor"] = cursor_value
    if normalized_report_ids:
        payload["reportIds"] = normalized_report_ids
    if normalized_topics:
        payload["topics"] = normalized_topics
    if normalized_industry:
        payload["industryType"] = normalized_industry
    if year_from is not None:
        payload["yearFrom"] = year_from
    if year_to is not None:
        payload["yearTo"] = year_to

    try:
        result = await insightmonk.search_reports(payload)
    except InsightMonkError as error:
        _audit("search_reports", "ERROR")
        raise ToolError(str(error)) from None
    except Exception:
        _audit("search_reports", "ERROR")
        raise ToolError("Report search is temporarily unavailable.") from None
    _audit("search_reports", "ALLOWED")
    return result


@mcp.tool(title="Get report content", annotations=READ_ONLY)
async def get_report_content(report_id: str) -> dict[str, Any]:
    """Return report metadata and page-numbered extracted PDF text."""
    report, document = await _report_document("get_report_content", report_id)
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
    _audit("get_report_content", "ALLOWED", document.report_id)
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
    """Return the original report PDF as an embedded MCP file resource."""
    report, document = await _report_document("download_report_pdf", report_id)
    if len(document.content) > settings.pdf_max_embedded_bytes:
        raise ToolError(
            "The PDF is too large to return through MCP; use get_report_content instead."
        )
    title = str(report.get("reportName") or document.report_id)
    safe_name = (
        re.sub(r"[^A-Za-z0-9._-]+", "-", title).strip("-.")[:100]
        or document.report_id
    )
    _audit("download_report_pdf", "ALLOWED", document.report_id)
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
    """Search a report and return matching passages with PDF page numbers."""
    search_text = query.strip() if isinstance(query, str) else ""
    if not 1 <= len(search_text) <= 200:
        raise ToolError("query must contain 1 to 200 characters.")
    if not 1 <= limit <= 50:
        raise ToolError("limit must be between 1 and 50.")
    report, document = await _report_document("search_report_content", report_id)
    matches = pdf_processor.search(document, search_text, limit=limit)
    _audit("search_report_content", "ALLOWED", document.report_id)
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
