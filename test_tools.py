"""Tests for the four public MCP tool functions."""

from __future__ import annotations

import base64

import pytest
from mcp.server.mcpserver.exceptions import ToolError

import tiny_server
from database import UserAccess
from pdf_processor import PDFDocument, PDFPage


USER = UserAccess(42, True, False, "CLIENT", 7, False, "platinum")
REPORT_ID = "a" * 24
REPORT = {
    "_id": REPORT_ID,
    "reportName": "AI Market",
    "topics": ["AI"],
    "url": "https://signed.example.test/report.pdf?secret=must-not-leak",
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
async def test_search_reports_forwards_all_configurable_arguments(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payloads: list[dict[str, object]] = []

    class FakeClient:
        async def search_reports(self, payload: dict[str, object]) -> dict[str, object]:
            payloads.append(payload)
            return {"success": True, "list": [], "page": 2, "limit": 5, "total": 0}

    async def current_user() -> UserAccess:
        return USER

    monkeypatch.setattr(tiny_server, "require_current_user", current_user)
    monkeypatch.setattr(tiny_server, "insightmonk", FakeClient())
    result = await tiny_server.search_reports(
        "quantum", "2020-01-01", "2026-10-30", "Full", 2, 5
    )
    assert result["success"] is True
    assert payloads == [
        {
            "search": "quantum",
            "from_date": "2020-01-01",
            "to_date": "2026-10-30",
            "type": "Full",
            "page": 2,
            "limit": 5,
        }
    ]


@pytest.mark.asyncio
async def test_get_report_content_omits_signed_url(monkeypatch: pytest.MonkeyPatch) -> None:
    async def report_document(tool: str, report_id: str):  # type: ignore[no-untyped-def]
        return USER, REPORT, DOCUMENT

    monkeypatch.setattr(tiny_server, "_report_document", report_document)
    result = await tiny_server.get_report_content(REPORT_ID)
    assert "url" not in result["report"]
    assert result["pages"][1]["page_number"] == 2
    assert result["ocr_required"] is False


@pytest.mark.asyncio
async def test_download_report_pdf_returns_embedded_file(monkeypatch: pytest.MonkeyPatch) -> None:
    async def report_document(tool: str, report_id: str):  # type: ignore[no-untyped-def]
        return USER, REPORT, DOCUMENT

    monkeypatch.setattr(tiny_server, "_report_document", report_document)
    result = await tiny_server.download_report_pdf(REPORT_ID)
    assert result.resource.mime_type == "application/pdf"
    assert base64.b64decode(result.resource.blob) == DOCUMENT.content
    assert "signed.example.test" not in str(result.resource.uri)


@pytest.mark.asyncio
async def test_search_report_content_returns_matching_pages(monkeypatch: pytest.MonkeyPatch) -> None:
    async def report_document(tool: str, report_id: str):  # type: ignore[no-untyped-def]
        return USER, REPORT, DOCUMENT

    monkeypatch.setattr(tiny_server, "_report_document", report_document)
    result = await tiny_server.search_report_content(REPORT_ID, "intelligence")
    assert [match["page_number"] for match in result["matches"]] == [1, 2]
    assert "url" not in result["report"]


@pytest.mark.asyncio
async def test_invalid_report_id_is_rejected_before_entitlement_query(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeDatabase:
        async def can_access_full_report(
            self, user: UserAccess, report_id: str, topics: list[str] | None = None
        ) -> bool:
            pytest.fail("invalid ID must not reach the database")

    async def current_user() -> UserAccess:
        return USER

    class FakeClient:
        async def get_report_content(self, report_id: str):  # type: ignore[no-untyped-def]
            pytest.fail("invalid ID must not reach InsightMonk")

    monkeypatch.setattr(tiny_server, "require_current_user", current_user)
    monkeypatch.setattr(tiny_server, "database", FakeDatabase())
    monkeypatch.setattr(tiny_server, "insightmonk", FakeClient())
    with pytest.raises(ToolError, match="24-character hexadecimal"):
        await tiny_server._report_document("get_report_content", "not-an-object-id")

