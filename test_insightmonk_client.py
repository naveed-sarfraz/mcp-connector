"""Tests for InsightMonk login, renewal, concurrency, retry, and API parsing."""

from __future__ import annotations

import asyncio
import time
from dataclasses import replace

import httpx
import jwt
import pytest

from config import settings
from insightmonk_client import InsightMonkClient, InsightMonkError

JWT_SECRET = "application-jwt-secret-for-tests"


def access_token(*, user_id: int = 42, expires_in: int = 3600) -> str:
    now = int(time.time())
    return jwt.encode(
        {
            "user_id": user_id,
            "role": "CLIENT",
            "company_id": 7,
            "token_type": "access",
            "iat": now,
            "exp": now + expires_in,
            "jti": f"test-{now}-{expires_in}",
        },
        JWT_SECRET,
        algorithm="HS256",
    )


def configured() :  # type: ignore[no-untyped-def]
    return replace(
        settings,
        insightmonk_base_url="https://api.example.test",
        insightmonk_email="service@example.test",
        insightmonk_password="service-password",
        insightmonk_jwt_secret=JWT_SECRET,
    )


@pytest.mark.asyncio
async def test_successful_user_authentication() -> None:
    token = access_token()

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/auth/login"
        return httpx.Response(
            200,
            json={"status": True, "message": "User logged in successfully.", "access_token": token},
        )

    http = httpx.AsyncClient(
        base_url="https://api.example.test", transport=httpx.MockTransport(handler)
    )
    client = InsightMonkClient(configured(), http)
    result = await client.login_user("user@example.test", "password")
    assert result.status == "success"
    assert result.user_id == 42
    await http.aclose()


@pytest.mark.asyncio
async def test_expired_application_login_jwt_is_rejected() -> None:
    token = access_token(expires_in=-60)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"status": True, "access_token": token})

    http = httpx.AsyncClient(
        base_url="https://api.example.test", transport=httpx.MockTransport(handler)
    )
    client = InsightMonkClient(configured(), http)
    with pytest.raises(InsightMonkError, match="invalid login token"):
        await client.login_user("user@example.test", "password")
    await http.aclose()


@pytest.mark.asyncio
async def test_automatic_service_token_renewal_five_minutes_early() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={"status": True, "access_token": access_token()})

    http = httpx.AsyncClient(
        base_url="https://api.example.test", transport=httpx.MockTransport(handler)
    )
    client = InsightMonkClient(configured(), http)
    client._service_token = "nearly-expired"
    client._service_expires_at = int(time.time()) + 299
    await client.access_token()
    assert calls == 1
    await client.access_token()
    assert calls == 1
    await http.aclose()


@pytest.mark.asyncio
async def test_concurrent_token_renewal_performs_one_login(monkeypatch: pytest.MonkeyPatch) -> None:
    http = httpx.AsyncClient(base_url="https://api.example.test", transport=httpx.MockTransport(lambda r: httpx.Response(500)))
    client = InsightMonkClient(configured(), http)
    calls = 0

    async def fake_login() -> str:
        nonlocal calls
        calls += 1
        await asyncio.sleep(0.01)
        client._service_token = "fresh-token"
        client._service_expires_at = int(time.time()) + 3600
        return "fresh-token"

    monkeypatch.setattr(client, "_login_service", fake_login)
    tokens = await asyncio.gather(*(client.access_token() for _ in range(12)))
    assert tokens == ["fresh-token"] * 12
    assert calls == 1
    await http.aclose()


@pytest.mark.asyncio
async def test_request_reauthenticates_and_retries_once_after_401() -> None:
    login_calls = 0
    search_calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal login_calls, search_calls
        if request.url.path == "/v1/auth/login":
            login_calls += 1
            return httpx.Response(200, json={"status": True, "access_token": access_token()})
        if request.url.path == "/v1/reports/search":
            search_calls += 1
            if search_calls == 1:
                return httpx.Response(401, json={"message": "expired"})
            return httpx.Response(
                200,
                json={"success": True, "list": [{"_id": "a" * 24}], "page": 1, "limit": 20, "total": 1},
            )
        return httpx.Response(404)

    http = httpx.AsyncClient(
        base_url="https://api.example.test", transport=httpx.MockTransport(handler)
    )
    client = InsightMonkClient(configured(), http)
    result = await client.search_reports({"search": "AI"})
    assert result["total"] == 1
    assert login_calls == 2
    assert search_calls == 2
    await http.aclose()


@pytest.mark.asyncio
async def test_successful_report_retrieval_parses_observed_response_shape() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/auth/login":
            return httpx.Response(200, json={"status": True, "access_token": access_token()})
        return httpx.Response(
            200,
            json={
                "success": True,
                "data": {
                    "_id": "a" * 24,
                    "reportName": "AI report",
                    "cost": 100,
                    "tag": ["AI"],
                    "topics": ["Artificial Intelligence"],
                    "url": "https://files.example.test/signed.pdf?signature=redacted",
                },
            },
        )

    http = httpx.AsyncClient(
        base_url="https://api.example.test", transport=httpx.MockTransport(handler)
    )
    client = InsightMonkClient(configured(), http)
    report = await client.get_report_content("a" * 24)
    assert report["reportName"] == "AI report"
    assert report["url"].startswith("https://files.example.test/")
    await http.aclose()

