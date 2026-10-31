"""Tests for the unauthenticated InsightMonk public report API client."""

from __future__ import annotations

from dataclasses import replace

import httpx
import pytest

from config import settings
from insightmonk_client import InsightMonkClient, InsightMonkError


def configured():  # type: ignore[no-untyped-def]
    return replace(settings, insightmonk_base_url="https://api.example.test")


@pytest.mark.asyncio
async def test_search_uses_public_endpoint_without_authorization() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/reports/public/search"
        assert request.method == "POST"
        assert "authorization" not in request.headers
        assert request.read()
        return httpx.Response(
            200,
            json={
                "success": True,
                "query": "EV battery 2035",
                "totalMatches": 2,
                "returned": 1,
                "hasMore": True,
                "nextCursor": "cursor-2",
                "results": [{"reportId": "a" * 24, "passages": ["Forecast"]}],
            },
        )

    http = httpx.AsyncClient(
        base_url="https://api.example.test", transport=httpx.MockTransport(handler)
    )
    client = InsightMonkClient(configured(), http)
    result = await client.search_reports(
        {"query": "EV battery 2035", "limit": 10, "latestOnly": True}
    )
    assert result["hasMore"] is True
    assert result["nextCursor"] == "cursor-2"
    await http.aclose()


@pytest.mark.asyncio
async def test_search_forwards_cursor_and_filters() -> None:
    expected = {
        "query": "battery",
        "limit": 20,
        "cursor": "next",
        "reportIds": ["a" * 24],
        "topics": ["Mobility"],
        "industryType": "Automotive",
        "yearFrom": 2025,
        "yearTo": 2035,
        "latestOnly": False,
    }

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/reports/public/search"
        assert request.read()
        import json

        assert json.loads(request.content) == expected
        return httpx.Response(
            200,
            json={
                "success": True,
                "hasMore": False,
                "nextCursor": None,
                "results": [],
            },
        )

    http = httpx.AsyncClient(
        base_url="https://api.example.test", transport=httpx.MockTransport(handler)
    )
    client = InsightMonkClient(configured(), http)
    await client.search_reports(expected)
    await http.aclose()


@pytest.mark.asyncio
async def test_report_content_uses_public_endpoint_and_parses_pdf() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/reports/public/content"
        assert request.url.params["reportId"] == "a" * 24
        assert "authorization" not in request.headers
        return httpx.Response(
            200,
            json={
                "success": True,
                "data": {
                    "reportId": "a" * 24,
                    "reportName": "AI report",
                    "pdf": {
                        "url": "https://files.example.test/signed.pdf?secret=redacted",
                        "expiresIn": 300,
                        "contentType": "application/pdf",
                    },
                },
            },
        )

    http = httpx.AsyncClient(
        base_url="https://api.example.test", transport=httpx.MockTransport(handler)
    )
    client = InsightMonkClient(configured(), http)
    report = await client.get_report_content("a" * 24)
    assert report["reportName"] == "AI report"
    assert report["pdf"]["url"].startswith("https://files.example.test/")
    await http.aclose()


@pytest.mark.asyncio
async def test_rate_limit_returns_safe_error() -> None:
    http = httpx.AsyncClient(
        base_url="https://api.example.test",
        transport=httpx.MockTransport(
            lambda request: httpx.Response(429, json={"message": "limited"})
        ),
    )
    client = InsightMonkClient(configured(), http)
    with pytest.raises(InsightMonkError, match="rate limit"):
        await client.search_reports({"query": "battery"})
    await http.aclose()


@pytest.mark.asyncio
async def test_invalid_public_response_is_rejected() -> None:
    http = httpx.AsyncClient(
        base_url="https://api.example.test",
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json={"success": True})
        ),
    )
    client = InsightMonkClient(configured(), http)
    with pytest.raises(InsightMonkError, match="invalid report search"):
        await client.search_reports({"query": "battery"})
    await http.aclose()
