"""Tests for permissions, validation, and the read-only Supabase connector."""

import asyncio
import json
import os
from types import SimpleNamespace

import pytest
import tiny_server
from mcp.server.mcpserver.exceptions import ToolError
from oauth_provider import OwnerOAuthProvider
from tiny_server import (
    DATASETS,
    SUPABASE_DB_URL,
    can_access,
    describe_dataset,
    search_dataset,
)


def set_verified_user(monkeypatch: pytest.MonkeyPatch, user: str | None) -> None:
    access_token = (
        None if user is None else SimpleNamespace(client_id=user, subject=None)
    )
    monkeypatch.setattr(tiny_server, "get_access_token", lambda: access_token)


def test_asha_can_describe_and_search_with_mocked_connector(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    set_verified_user(monkeypatch, "asha")
    calls: list[tuple[str, str, int]] = []

    def fake_query(dataset: str, text: str, limit: int) -> list[dict[str, str]]:
        calls.append((dataset, text, limit))
        return [{"physician_name": "Asha Rao", "specialty": "Cardiology"}]

    monkeypatch.setattr(tiny_server, "query_supabase", fake_query)
    description = json.loads(describe_dataset("supabase_data"))
    rows = json.loads(search_dataset("supabase_data", "cardio"))

    assert description["searchable_columns"] == ["physician_name", "specialty"]
    assert rows[0]["physician_name"] == "Asha Rao"
    assert calls == [("supabase_data", "cardio", 10)]


@pytest.mark.parametrize("user", ["ravi", "guest"])
def test_ravi_and_guest_can_search_when_permissions_are_disabled(
    monkeypatch: pytest.MonkeyPatch, user: str
) -> None:
    assert not tiny_server.ENFORCE_USER_PERMISSIONS
    set_verified_user(monkeypatch, user)
    calls: list[tuple[str, str, int]] = []

    def fake_query(dataset: str, text: str, limit: int) -> list[dict[str, str]]:
        calls.append((dataset, text, limit))
        return []

    monkeypatch.setattr(tiny_server, "query_supabase", fake_query)

    assert json.loads(search_dataset("supabase_data", "cardio")) == []
    assert calls == [("supabase_data", "cardio", 10)]


def test_unknown_and_forbidden_datasets_share_the_same_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(tiny_server, "ENFORCE_USER_PERMISSIONS", True)
    messages = []
    for user, dataset in (("guest", "supabase_data"), ("asha", "unknown")):
        set_verified_user(monkeypatch, user)
        with pytest.raises(ToolError) as error:
            describe_dataset(dataset)
        messages.append(str(error.value))
    assert messages == [tiny_server.DENIED_MESSAGE] * 2


def test_static_bearer_token_is_verified_without_exposing_it() -> None:
    provider = OwnerOAuthProvider(
        issuer_url="https://mcp.example.com",
        resource_url="https://mcp.example.com/mcp",
        signing_key="a-test-signing-key-that-is-long-enough",
        owner_password="test-password",
        bearer_token="expected-bearer-token",
    )
    accepted = asyncio.run(provider.load_access_token("expected-bearer-token"))
    rejected = asyncio.run(provider.load_access_token("wrong-token"))

    assert accepted is not None
    assert accepted.subject == "owner"
    assert accepted.resource == "https://mcp.example.com/mcp"
    assert rejected is None


@pytest.mark.parametrize("text", ["", "   ", "x" * 101])
def test_bad_search_text_is_rejected_before_connector(
    monkeypatch: pytest.MonkeyPatch, text: str
) -> None:
    set_verified_user(monkeypatch, "asha")
    monkeypatch.setattr(
        tiny_server,
        "query_supabase",
        lambda *args: pytest.fail("invalid text must not reach the connector"),
    )
    with pytest.raises(ToolError, match="1 to 100 characters"):
        search_dataset("supabase_data", text)


@pytest.mark.parametrize(("requested", "expected"), [(0, 1), (500, 50)])
def test_search_limit_is_clamped(
    monkeypatch: pytest.MonkeyPatch, requested: int, expected: int
) -> None:
    set_verified_user(monkeypatch, "asha")
    calls: list[int] = []
    monkeypatch.setattr(
        tiny_server,
        "query_supabase",
        lambda dataset, text, limit: calls.append(limit) or [],
    )
    search_dataset("supabase_data", "cardio", requested)
    assert calls == [expected]


def test_database_errors_are_generic_and_redacted(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    set_verified_user(monkeypatch, "asha")
    connection_url = "postgresql://dbuser:very-secret@db.example/postgres"
    monkeypatch.setattr(tiny_server, "SUPABASE_DB_URL", connection_url)

    def fail_query(dataset: str, text: str, limit: int) -> list[dict[str, str]]:
        raise RuntimeError(f"connection failed for {connection_url}")

    monkeypatch.setattr(tiny_server, "query_supabase", fail_query)
    with pytest.raises(ToolError) as error:
        search_dataset("supabase_data", "cardio")

    log = capsys.readouterr().out
    assert str(error.value) == tiny_server.UNAVAILABLE_MESSAGE
    assert "very-secret" not in log
    assert connection_url not in log
    assert "[redacted connection string]" in log


def test_unknown_and_forbidden_users_have_no_access() -> None:
    assert tiny_server.ENFORCE_USER_PERMISSIONS is False
    assert can_access("owner", "supabase_data")
    assert can_access("asha", "supabase_data")
    assert not can_access("ravi", "supabase_data")
    assert not can_access("guest", "supabase_data")
    assert not can_access("unknown", "supabase_data")
    assert not can_access("asha", "unknown")


def test_supabase_read_only_integration() -> None:
    if not SUPABASE_DB_URL or os.getenv("RUN_SUPABASE_INTEGRATION") != "1":
        pytest.skip("set RUN_SUPABASE_INTEGRATION=1 to run the live read-only test")

    rows = None
    error_type = None
    try:
        rows = tiny_server.query_supabase("supabase_data", "a", 1)
    except Exception as error:
        error_type = type(error).__name__
    if error_type is not None:
        pytest.fail(
            f"Supabase read failed ({error_type}); check the local database settings.",
            pytrace=False,
        )

    assert len(rows) <= 1
    assert all(
        set(row) == set(DATASETS["supabase_data"]["searchable_columns"])
        for row in rows
    )
