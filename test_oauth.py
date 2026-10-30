"""OAuth authorization-code, refresh, expiry, and user-state tests."""

from __future__ import annotations

import time
from dataclasses import replace
from urllib.parse import parse_qs, urlparse

import jwt
import pytest
from mcp.server.auth.provider import AuthorizationParams
from mcp.shared.auth import OAuthClientInformationFull

from config import settings
from database import OAuthArtifact, UserAccess, token_hash
from oauth_provider import InsightMonkOAuthProvider


class MemoryDatabase:
    def __init__(self) -> None:
        self.clients: dict[str, OAuthClientInformationFull] = {}
        self.users: dict[int, UserAccess] = {
            42: UserAccess(42, True, False, "CLIENT", 7, False, "silver")
        }
        self.artifacts: dict[tuple[str, str], tuple[OAuthArtifact, bool]] = {}
        self.revoked: set[str] = set()

    async def save_client(self, client: OAuthClientInformationFull) -> None:
        self.clients[client.client_id] = client

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        return self.clients.get(client_id)

    async def get_user(self, user_id: int | str) -> UserAccess | None:
        return self.users.get(int(user_id))

    async def save_artifact(self, **values) -> None:  # type: ignore[no-untyped-def]
        artifact = OAuthArtifact(
            token_hash=token_hash(values["token"]),
            kind=values["kind"],
            client_id=values["client_id"],
            subject=values["subject"],
            scopes=values["scopes"],
            resource=values["resource"],
            metadata=values["metadata"],
            expires_at=values["expires_at"],
        )
        self.artifacts[(values["token"], values["kind"])] = (artifact, False)

    async def load_artifact(self, token: str, kind: str) -> OAuthArtifact | None:
        value = self.artifacts.get((token, kind))
        if value is None or value[1] or value[0].expires_at <= time.time():
            return None
        return value[0]

    async def consume_artifact(self, token: str, kind: str) -> bool:
        value = self.artifacts.get((token, kind))
        if value is None or value[1] or value[0].expires_at <= time.time():
            return False
        self.artifacts[(token, kind)] = (value[0], True)
        return True

    async def is_access_jti_revoked(self, jti: str) -> bool:
        return jti in self.revoked

    async def revoke_access_jti(self, jti: str, expires_at: int) -> None:
        self.revoked.add(jti)

    async def consume_refresh_for_access_jti(self, jti: str) -> None:
        for key, (artifact, consumed) in list(self.artifacts.items()):
            if artifact.kind == "refresh" and artifact.metadata.get("access_jti") == jti:
                self.artifacts[key] = (artifact, True)


@pytest.fixture
def oauth() -> tuple[InsightMonkOAuthProvider, MemoryDatabase, OAuthClientInformationFull]:
    configured = replace(
        settings,
        server_url="https://mcp.example.com/mcp",
        issuer_url="https://mcp.example.com",
        oauth_signing_key="oauth-test-key-which-is-longer-than-thirty-two-characters",
        oauth_access_token_seconds=3600,
        oauth_refresh_token_seconds=86400,
        oauth_code_seconds=300,
    )
    db = MemoryDatabase()
    client = OAuthClientInformationFull(
        client_id="chatgpt-client",
        client_name="ChatGPT",
        redirect_uris=["https://chatgpt.com/connector/callback"],
        token_endpoint_auth_method="none",
        scope="reports:read",
    )
    db.clients[client.client_id] = client
    return InsightMonkOAuthProvider(configured, db), db, client


@pytest.mark.asyncio
async def test_authorization_code_and_rotating_refresh_flow(
    oauth: tuple[InsightMonkOAuthProvider, MemoryDatabase, OAuthClientInformationFull]
) -> None:
    provider, _, client = oauth
    login_url = await provider.authorize(
        client,
        AuthorizationParams(
            state="client-state",
            scopes=["reports:read"],
            code_challenge="challenge",
            redirect_uri="https://chatgpt.com/connector/callback",
            redirect_uri_provided_explicitly=True,
            resource="https://mcp.example.com/mcp",
        ),
    )
    request_token = parse_qs(urlparse(login_url).query)["request"][0]
    callback = await provider.complete_authorization(request_token, 42)
    callback_query = parse_qs(urlparse(callback).query)
    assert callback_query["state"] == ["client-state"]

    code_value = callback_query["code"][0]
    code = await provider.load_authorization_code(client, code_value)
    assert code is not None and code.subject == "42"
    tokens = await provider.exchange_authorization_code(client, code)
    assert await provider.load_authorization_code(client, code_value) is None
    access = await provider.load_access_token(tokens.access_token)
    assert access is not None and access.subject == "42"

    refresh = await provider.load_refresh_token(client, tokens.refresh_token or "")
    assert refresh is not None
    rotated = await provider.exchange_refresh_token(client, refresh, ["reports:read"])
    assert rotated.refresh_token != tokens.refresh_token
    assert await provider.load_refresh_token(client, tokens.refresh_token or "") is None


@pytest.mark.asyncio
async def test_inactive_user_invalidates_existing_access_token(
    oauth: tuple[InsightMonkOAuthProvider, MemoryDatabase, OAuthClientInformationFull]
) -> None:
    provider, db, _ = oauth
    tokens = await provider._issue_tokens(
        client_id="chatgpt-client",
        subject="42",
        scopes=["reports:read"],
        resource="https://mcp.example.com/mcp",
    )
    db.users[42] = replace(db.users[42], active=False)
    assert await provider.load_access_token(tokens.access_token) is None


@pytest.mark.asyncio
async def test_user_not_found_cannot_receive_tokens(
    oauth: tuple[InsightMonkOAuthProvider, MemoryDatabase, OAuthClientInformationFull]
) -> None:
    provider, _, _ = oauth
    with pytest.raises(Exception, match="not active"):
        await provider._issue_tokens(
            client_id="chatgpt-client",
            subject="999",
            scopes=["reports:read"],
            resource="https://mcp.example.com/mcp",
        )


@pytest.mark.asyncio
async def test_expired_user_jwt_is_rejected(
    oauth: tuple[InsightMonkOAuthProvider, MemoryDatabase, OAuthClientInformationFull]
) -> None:
    provider, _, _ = oauth
    now = int(time.time())
    token = jwt.encode(
        {
            "kind": "access",
            "iss": "https://mcp.example.com",
            "aud": "https://mcp.example.com/mcp",
            "sub": "42",
            "client_id": "chatgpt-client",
            "scope": "reports:read",
            "iat": now - 7200,
            "exp": now - 3600,
            "jti": "expired",
        },
        provider.settings.oauth_signing_key,
        algorithm="HS256",
    )
    assert await provider.load_access_token(token) is None


@pytest.mark.asyncio
async def test_access_token_revocation(
    oauth: tuple[InsightMonkOAuthProvider, MemoryDatabase, OAuthClientInformationFull]
) -> None:
    provider, _, client = oauth
    tokens = await provider._issue_tokens(
        client_id="chatgpt-client",
        subject="42",
        scopes=["reports:read"],
        resource="https://mcp.example.com/mcp",
    )
    access = await provider.load_access_token(tokens.access_token)
    assert access is not None
    await provider.revoke_token(access)
    assert await provider.load_access_token(tokens.access_token) is None
    assert await provider.load_refresh_token(client, tokens.refresh_token or "") is None


@pytest.mark.asyncio
async def test_refresh_revocation_also_revokes_paired_access_token(
    oauth: tuple[InsightMonkOAuthProvider, MemoryDatabase, OAuthClientInformationFull]
) -> None:
    provider, _, client = oauth
    tokens = await provider._issue_tokens(
        client_id="chatgpt-client",
        subject="42",
        scopes=["reports:read"],
        resource="https://mcp.example.com/mcp",
    )
    refresh = await provider.load_refresh_token(client, tokens.refresh_token or "")
    assert refresh is not None
    await provider.revoke_token(refresh)
    assert await provider.load_access_token(tokens.access_token) is None

