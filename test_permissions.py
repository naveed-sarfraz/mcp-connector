"""Tests for public access, validation, and the read-only connector."""

import json
import os

import pytest
import tiny_server
from mcp.server.mcpserver.exceptions import ToolError
from tiny_server import DATASETS, SUPABASE_DB_URL, describe_dataset, search_dataset


def test_server_has_no_mcp_authentication_provider() -> None:
    assert tiny_server.mcp._auth_server_provider is None
    assert tiny_server.mcp.settings.auth is None


def test_public_client_can_describe_and_search_with_mocked_connector(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, str, int]] = []

    def fake_query(dataset: str, text: str, limit: int) -> list[dict[str, str]]:
        calls.append((dataset, text, limit))
        return [{"physician_name": "Asha Rao", "specialty": "Cardiology"}]

    monkeypatch.setattr(tiny_server, "query_supabase", fake_query)
    description = json.loads(describe_dataset())
    rows = json.loads(search_dataset("cardio"))

    assert description["searchable_columns"] == ["physician_name", "specialty"]
    assert rows[0]["physician_name"] == "Asha Rao"
    assert calls == [("supabase_data", "cardio", 10)]


@pytest.mark.parametrize("text", ["", "   ", "x" * 101])
def test_bad_search_text_is_rejected_before_connector(
    monkeypatch: pytest.MonkeyPatch, text: str
) -> None:
    monkeypatch.setattr(
        tiny_server,
        "query_supabase",
        lambda *args: pytest.fail("invalid text must not reach the connector"),
    )
    with pytest.raises(ToolError, match="1 to 100 characters"):
        search_dataset(text)


@pytest.mark.parametrize(("requested", "expected"), [(0, 1), (500, 50)])
def test_search_limit_is_clamped(
    monkeypatch: pytest.MonkeyPatch, requested: int, expected: int
) -> None:
    calls: list[int] = []
    monkeypatch.setattr(
        tiny_server,
        "query_supabase",
        lambda dataset, text, limit: calls.append(limit) or [],
    )
    search_dataset("cardio", requested)
    assert calls == [expected]


def test_database_errors_are_generic_and_redacted(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    connection_url = "postgresql://dbuser:very-secret@db.example/postgres"
    monkeypatch.setattr(tiny_server, "SUPABASE_DB_URL", connection_url)

    def fail_query(dataset: str, text: str, limit: int) -> list[dict[str, str]]:
        raise RuntimeError(f"connection failed for {connection_url}")

    monkeypatch.setattr(tiny_server, "query_supabase", fail_query)
    with pytest.raises(ToolError) as error:
        search_dataset("cardio")

    log = capsys.readouterr().out
    assert str(error.value) == tiny_server.UNAVAILABLE_MESSAGE
    assert "very-secret" not in log
    assert connection_url not in log
    assert "[redacted connection string]" in log


def test_unknown_dataset_is_not_public() -> None:
    with pytest.raises(ToolError, match=tiny_server.DENIED_MESSAGE):
        tiny_server._public_actor("search_dataset", "unknown")


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
