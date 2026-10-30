"""Tests for MCP user and report authorization decisions."""

from __future__ import annotations

from dataclasses import replace

import pytest
from mcp.server.auth.provider import AccessToken
from mcp.server.mcpserver.exceptions import ToolError

import tiny_server
from config import settings
from database import Database, UserAccess


def user(**overrides: object) -> UserAccess:
    values = {
        "user_id": 42,
        "active": True,
        "soft_deleted": False,
        "role": "CLIENT",
        "company_id": 7,
        "client_admin": False,
        "membership": "silver",
    }
    values.update(overrides)
    return UserAccess(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("role", "membership", "company_id"),
    [("EXPERT", None, None), ("CLIENT", "personal", 7), ("ADMIN", "platinum", 3)],
)
def test_all_active_roles_plans_and_companies_can_use_mcp(
    role: str, membership: str | None, company_id: int | None
) -> None:
    assert user(role=role, membership=membership, company_id=company_id).mcp_allowed


@pytest.mark.parametrize(
    "record",
    [user(active=False), user(soft_deleted=True)],
)
def test_inactive_or_deleted_users_are_not_allowed(record: UserAccess) -> None:
    assert not record.mcp_allowed


@pytest.mark.asyncio
async def test_authenticated_active_user_is_loaded_from_database(monkeypatch: pytest.MonkeyPatch) -> None:
    record = user()

    class FakeDatabase:
        async def get_user(self, subject: str) -> UserAccess:
            assert subject == "42"
            return record

    token = AccessToken(
        token="opaque", client_id="client", scopes=["reports:read"], subject="42"
    )
    monkeypatch.setattr(tiny_server, "get_access_token", lambda: token)
    monkeypatch.setattr(tiny_server, "database", FakeDatabase())
    assert await tiny_server.require_current_user() == record


@pytest.mark.asyncio
@pytest.mark.parametrize("record", [None, user(active=False), user(soft_deleted=True)])
async def test_missing_inactive_or_deleted_user_is_denied(
    monkeypatch: pytest.MonkeyPatch, record: UserAccess | None
) -> None:
    class FakeDatabase:
        async def get_user(self, subject: str) -> UserAccess | None:
            return record

    token = AccessToken(
        token="opaque", client_id="client", scopes=["reports:read"], subject="42"
    )
    monkeypatch.setattr(tiny_server, "get_access_token", lambda: token)
    monkeypatch.setattr(tiny_server, "database", FakeDatabase())
    with pytest.raises(ToolError, match="not authorized"):
        await tiny_server.require_current_user()


@pytest.mark.asyncio
async def test_unauthenticated_remote_tool_call_is_denied(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tiny_server, "get_access_token", lambda: None)
    monkeypatch.delenv("MCP_TRANSPORT", raising=False)
    with pytest.raises(ToolError, match="Authentication is required"):
        await tiny_server.require_current_user()


class FakeCursor:
    def __init__(self, result: dict[str, int] | None = None):
        self.result = result
        self.statement = ""
        self.params: tuple[object, ...] = ()

    def __enter__(self) -> "FakeCursor":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def execute(self, statement: str, params: tuple[object, ...]) -> int:
        self.statement = statement
        self.params = params
        return 1

    def fetchone(self) -> dict[str, int] | None:
        return self.result


class FakeConnection:
    def __init__(self, cursor: FakeCursor):
        self._cursor = cursor

    def cursor(self) -> FakeCursor:
        return self._cursor


@pytest.mark.asyncio
async def test_company_admin_uses_company_purchase_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    configured = replace(settings, oauth_signing_key="x" * 48)
    db = Database(configured)
    cursor = FakeCursor({"allowed": 1})

    async def run(operation):  # type: ignore[no-untyped-def]
        return operation(FakeConnection(cursor))

    monkeypatch.setattr(db, "_run", run)
    allowed = await db.can_access_full_report(
        user(role="CLIENT", client_admin=True, company_id=7), "a" * 24
    )
    assert allowed
    assert "purchaser.company_id" in cursor.statement
    assert cursor.params == (7, "a" * 24)


@pytest.mark.asyncio
async def test_non_admin_cannot_use_another_company_purchase(monkeypatch: pytest.MonkeyPatch) -> None:
    configured = replace(settings, oauth_signing_key="x" * 48)
    db = Database(configured)
    cursor = FakeCursor(None)

    async def run(operation):  # type: ignore[no-untyped-def]
        return operation(FakeConnection(cursor))

    monkeypatch.setattr(db, "_run", run)
    allowed = await db.can_access_full_report(
        user(role="CLIENT", client_admin=False, company_id=7), "b" * 24
    )
    assert not allowed
    assert "WHERE user_id = %s" in cursor.statement
    assert cursor.params == (42, "b" * 24)


@pytest.mark.asyncio
async def test_platinum_membership_can_read_full_report_without_purchase(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configured = replace(settings, oauth_signing_key="x" * 48)
    db = Database(configured)
    monkeypatch.setattr(db, "_run", lambda operation: pytest.fail("database query not expected"))
    assert await db.can_access_full_report(user(membership="platinum"), "c" * 24)


@pytest.mark.asyncio
async def test_gold_topic_subscription_can_read_matching_full_report(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configured = replace(settings, oauth_signing_key="x" * 48)
    db = Database(configured)
    cursor = FakeCursor({"title": "Artificial Intelligence"})

    async def run(operation):  # type: ignore[no-untyped-def]
        return operation(FakeConnection(cursor))

    monkeypatch.setattr(db, "_run", run)
    assert await db.can_access_full_report(
        user(membership="gold"), "d" * 24, ["Artificial Intelligence"]
    )
    assert "user_sectors" in cursor.statement
