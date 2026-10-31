"""Tests for the four open MCP tool functions."""

from __future__ import annotations

import base64

import pytest
from mcp.server.mcpserver.exceptions import ToolError

import tiny_server
from pdf_processor import PDFDocument, PDFPage


REPORT_ID = "a" * 24
REPORT = {
    "reportId": REPORT_ID,
    "reportName": "AI Market",
    "topics": ["AI"],
    "pdf": {
        "url": "https://signed.example.test/report.pdf?secret=must-not-leak",
        "expiresIn": 300,
        "contentType": "application/pdf",
    },
}
DOCUMENT = PDFDocument(
    report_id=REPORT_ID,
    content=b"%PDF-test-content",
    pages=(
        PDFPage(1, "Artificial intelligence is growing."),
        PDFPage(2, "Market forecast and artificial intelligence adoption."),
    ),
    ocr_required_pages=(),
)


@pytest.mark.asyncio
async def test_search_reports_forwards_public_arguments(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payloads: list[dict[str, object]] = []

    class FakeClient:
        async def search_reports(self, payload: dict[str, object]) -> dict[str, object]:
            payloads.append(payload)
            return {
                "success": True,
                "results": [],
                "hasMore": False,
                "nextCursor": None,
            }

    monkeypatch.setattr(tiny_server, "insightmonk", FakeClient())
    result = await tiny_server.search_reports(
        query="quantum",
        limit=5,
        cursor="next",
        report_ids=[REPORT_ID.upper()],
        topics=["Deep Tech"],
        industry_type="Technology",
        year_from=2025,
        year_to=2030,
        latest_only=False,
    )
    assert result["success"] is True
    assert payloads == [
        {
            "query": "quantum",
            "limit": 5,
            "cursor": "next",
            "reportIds": [REPORT_ID],
            "topics": ["Deep Tech"],
            "industryType": "Technology",
            "yearFrom": 2025,
            "yearTo": 2030,
            "latestOnly": False,
        }
    ]


@pytest.mark.asyncio
async def test_get_report_content_omits_nested_signed_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def report_document(tool: str, report_id: str):  # type: ignore[no-untyped-def]
        return REPORT, DOCUMENT

    monkeypatch.setattr(tiny_server, "_report_document", report_document)
    result = await tiny_server.get_report_content(REPORT_ID)
    assert "url" not in result["report"]["pdf"]
    assert result["report"]["pdf"]["expiresIn"] == 300
    assert result["pages"][1]["page_number"] == 2
    assert result["ocr_required"] is False


@pytest.mark.asyncio
async def test_download_report_pdf_returns_embedded_file(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def report_document(tool: str, report_id: str):  # type: ignore[no-untyped-def]
        return REPORT, DOCUMENT

    monkeypatch.setattr(tiny_server, "_report_document", report_document)
    result = await tiny_server.download_report_pdf(REPORT_ID)
    assert result.resource.mime_type == "application/pdf"
    assert base64.b64decode(result.resource.blob) == DOCUMENT.content
    assert "signed.example.test" not in str(result.resource.uri)


@pytest.mark.asyncio
async def test_search_report_content_returns_matching_pages(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def report_document(tool: str, report_id: str):  # type: ignore[no-untyped-def]
        return REPORT, DOCUMENT

    monkeypatch.setattr(tiny_server, "_report_document", report_document)
    result = await tiny_server.search_report_content(REPORT_ID, "intelligence")
    assert [match["page_number"] for match in result["matches"]] == [1, 2]
    assert "url" not in result["report"]["pdf"]


@pytest.mark.asyncio
async def test_invalid_report_id_is_rejected_before_public_api(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeClient:
        async def get_report_content(self, report_id: str):  # type: ignore[no-untyped-def]
            pytest.fail("invalid ID must not reach InsightMonk")

    monkeypatch.setattr(tiny_server, "insightmonk", FakeClient())
    with pytest.raises(ToolError, match="24-character hexadecimal"):
        await tiny_server._report_document("get_report_content", "not-an-object-id")


@pytest.mark.asyncio
async def test_search_validation_rejects_invalid_range() -> None:
    with pytest.raises(ToolError, match="year_from"):
        await tiny_server.search_reports("battery", year_from=2035, year_to=2025)


def test_mcp_server_has_no_authentication_settings() -> None:
    assert getattr(tiny_server.mcp.settings, "auth", None) is None
