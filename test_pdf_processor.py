"""Tests for secure PDF handling and page-aware extraction."""

from __future__ import annotations

from dataclasses import replace

import httpx
import pymupdf
import pytest

from config import settings
from pdf_processor import PDFProcessingError, PDFProcessor


def make_pdf(*page_texts: str) -> bytes:
    document = pymupdf.open()
    for text in page_texts:
        page = document.new_page()
        if text:
            page.insert_text((72, 72), text)
    content = document.tobytes()
    document.close()
    return content


def configured(**overrides: object):  # type: ignore[no-untyped-def]
    values = {
        "pdf_max_download_bytes": 1024 * 1024,
        "pdf_cache_max_bytes": 4 * 1024 * 1024,
        "pdf_cache_ttl_seconds": 60,
    }
    values.update(overrides)
    return replace(settings, **values)


def test_pdf_extraction_preserves_page_numbers_and_detects_scans() -> None:
    document = PDFProcessor._extract("a" * 24, make_pdf("Alpha result", "", "Beta result"))
    assert [page.page_number for page in document.pages] == [1, 2, 3]
    assert "Alpha" in document.pages[0].text
    assert document.ocr_required_pages == (2,)


def test_report_search_returns_page_numbered_passages() -> None:
    document = PDFProcessor._extract(
        "a" * 24, make_pdf("Artificial intelligence market", "Unrelated", "AI and intelligence")
    )
    matches = PDFProcessor.search(document, "intelligence")
    assert [match["page_number"] for match in matches] == [1, 3]
    assert all("intelligence" in str(match["passage"]).lower() for match in matches)


@pytest.mark.asyncio
async def test_pdf_download_and_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    content = make_pdf("Cached report")
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, headers={"content-type": "application/pdf"}, content=content)

    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    processor = PDFProcessor(configured(), http)

    async def trust_test_url(url: str) -> None:
        return None

    monkeypatch.setattr(processor, "_validate_url", trust_test_url)
    first = await processor.get_document("a" * 24, "https://files.example.test/report.pdf")
    second = await processor.get_document("a" * 24, "https://files.example.test/new-signature.pdf")
    assert first is second
    assert calls == 1
    await http.aclose()


@pytest.mark.asyncio
async def test_unsafe_pdf_url_is_rejected_before_download() -> None:
    http = httpx.AsyncClient(transport=httpx.MockTransport(lambda request: pytest.fail("no request expected")))
    processor = PDFProcessor(configured(), http)
    with pytest.raises(PDFProcessingError, match="unsafe PDF URL"):
        await processor._validate_url("http://127.0.0.1/private.pdf")
    await http.aclose()


@pytest.mark.asyncio
async def test_pdf_size_limit_is_enforced(monkeypatch: pytest.MonkeyPatch) -> None:
    content = make_pdf("Too large")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=content)

    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    processor = PDFProcessor(configured(pdf_max_download_bytes=100), http)

    async def trust_test_url(url: str) -> None:
        return None

    monkeypatch.setattr(processor, "_validate_url", trust_test_url)
    with pytest.raises(PDFProcessingError, match="download limit"):
        await processor.get_document("b" * 24, "https://files.example.test/report.pdf")
    await http.aclose()

