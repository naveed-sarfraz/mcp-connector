"""Small OAuth 2.1 provider for a single-owner remote MCP server.

The MCP SDK supplies the protocol routes and validation. This module supplies
dynamic client registration storage, a password-gated authorization decision,
and HMAC-signed access and refresh tokens.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Any
from urllib.parse import urlencode

from pydantic import AnyUrl

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    TokenError,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class OwnerOAuthProvider(
    OAuthAuthorizationServerProvider[AuthorizationCode, RefreshToken, AccessToken]
):
    """OAuth provider for a private, single-owner connector.

    Client registrations live in memory. Access, refresh, login, and
    authorization-code credentials are signed, so issued tokens survive a
    process restart. A client can transparently register again if a restart
    clears its dynamic registration.
    """

    def __init__(
        self,
        *,
        issuer_url: str,
        resource_url: str,
        signing_key: str,
        owner_password: str | None,
        bearer_token: str | None = None,
    ) -> None:
        self.issuer_url = issuer_url.rstrip("/")
        self.resource_url = resource_url
        self._signing_key = signing_key.encode("utf-8")
        self._owner_password = owner_password
        self._bearer_token = bearer_token
        self._clients: dict[str, OAuthClientInformationFull] = {}
        self._consumed_codes: dict[str, int] = {}
        self._revoked_tokens: dict[str, int] = {}

    def _encode(self, payload: dict[str, Any]) -> str:
        body = _b64encode(
            json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        )
        signature = _b64encode(
            hmac.new(self._signing_key, body.encode("ascii"), hashlib.sha256).digest()
        )
        return f"mcpv1.{body}.{signature}"

    def _decode(self, token: str, expected_kind: str) -> dict[str, Any] | None:
        try:
            prefix, body, supplied_signature = token.split(".", 2)
            if prefix != "mcpv1":
                return None
            expected_signature = _b64encode(
                hmac.new(
                    self._signing_key, body.encode("ascii"), hashlib.sha256
                ).digest()
            )
            if not hmac.compare_digest(supplied_signature, expected_signature):
                return None
            payload = json.loads(_b64decode(body))
            if payload.get("kind") != expected_kind:
                return None
            if int(payload.get("exp", 0)) <= int(time.time()):
                return None
            return payload
        except (ValueError, TypeError, json.JSONDecodeError, UnicodeDecodeError):
            return None

    def _prune_one_time_state(self) -> None:
        now = int(time.time())
        self._consumed_codes = {
            token_id: expiry
            for token_id, expiry in self._consumed_codes.items()
            if expiry > now
        }
        self._revoked_tokens = {
            token_id: expiry
            for token_id, expiry in self._revoked_tokens.items()
            if expiry > now
        }

    def _mint_token(
        self,
        *,
        kind: str,
        client_id: str,
        scopes: list[str],
        resource: str,
        lifetime: int,
    ) -> str:
        now = int(time.time())
        return self._encode(
            {
                "kind": kind,
                "client_id": client_id,
                "scopes": scopes,
                "resource": resource,
                "subject": "owner",
                "iat": now,
                "exp": now + lifetime,
                "jti": secrets.token_urlsafe(18),
            }
        )

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        return self._clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        if len(self._clients) >= 1000:
            oldest_client = min(
                self._clients.values(),
                key=lambda client: client.client_id_issued_at or 0,
            )
            self._clients.pop(oldest_client.client_id, None)
        self._clients[client_info.client_id] = client_info

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        if not self._owner_password:
            raise AuthorizeError(
                error="temporarily_unavailable",
                error_description="OAuth login is not configured on this server.",
            )
        resource = params.resource or self.resource_url
        if resource != self.resource_url:
            raise AuthorizeError(
                error="invalid_target",
                error_description="The requested resource is not this MCP server.",
            )
        request_token = self._encode(
            {
                "kind": "login",
                "client_id": client.client_id,
                "scopes": params.scopes or ["datasets:read"],
                "code_challenge": params.code_challenge,
                "redirect_uri": str(params.redirect_uri),
                "redirect_uri_provided_explicitly": (
                    params.redirect_uri_provided_explicitly
                ),
                "resource": resource,
                "state": params.state,
                "exp": int(time.time()) + 600,
            }
        )
        return f"{self.issuer_url}/oauth/login?{urlencode({'request': request_token})}"

    def login_client_name(self, request_token: str) -> str | None:
        payload = self._decode(request_token, "login")
        if payload is None:
            return None
        client = self._clients.get(str(payload["client_id"]))
        if client is None:
            return None
        return client.client_name or "MCP client"

    def complete_login(self, request_token: str, password: str) -> str | None:
        payload = self._decode(request_token, "login")
        if payload is None or not self._owner_password:
            return None
        if not secrets.compare_digest(password, self._owner_password):
            return None
        client_id = str(payload["client_id"])
        if client_id not in self._clients:
            return None

        now = int(time.time())
        authorization_code = self._encode(
            {
                "kind": "code",
                "client_id": client_id,
                "scopes": list(payload["scopes"]),
                "code_challenge": str(payload["code_challenge"]),
                "redirect_uri": str(payload["redirect_uri"]),
                "redirect_uri_provided_explicitly": bool(
                    payload["redirect_uri_provided_explicitly"]
                ),
                "resource": str(payload["resource"]),
                "subject": "owner",
                "iat": now,
                "exp": now + 300,
                "jti": secrets.token_urlsafe(18),
            }
        )
        return construct_redirect_uri(
            str(payload["redirect_uri"]),
            code=authorization_code,
            state=payload.get("state"),
        )

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        payload = self._decode(authorization_code, "code")
        if payload is None or payload.get("client_id") != client.client_id:
            return None
        self._prune_one_time_state()
        if str(payload["jti"]) in self._consumed_codes:
            return None
        return AuthorizationCode(
            code=authorization_code,
            scopes=list(payload["scopes"]),
            expires_at=float(payload["exp"]),
            client_id=str(payload["client_id"]),
            code_challenge=str(payload["code_challenge"]),
            redirect_uri=AnyUrl(str(payload["redirect_uri"])),
            redirect_uri_provided_explicitly=bool(
                payload["redirect_uri_provided_explicitly"]
            ),
            resource=str(payload["resource"]),
            subject="owner",
        )

    async def exchange_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: AuthorizationCode,
    ) -> OAuthToken:
        payload = self._decode(authorization_code.code, "code")
        if payload is None or payload.get("client_id") != client.client_id:
            raise TokenError("invalid_grant", "Invalid authorization code.")
        token_id = str(payload["jti"])
        self._prune_one_time_state()
        if token_id in self._consumed_codes:
            raise TokenError("invalid_grant", "Authorization code was already used.")
        self._consumed_codes[token_id] = int(payload["exp"])

        access_token = self._mint_token(
            kind="access",
            client_id=authorization_code.client_id,
            scopes=authorization_code.scopes,
            resource=authorization_code.resource or self.resource_url,
            lifetime=3600,
        )
        refresh_token = self._mint_token(
            kind="refresh",
            client_id=authorization_code.client_id,
            scopes=authorization_code.scopes,
            resource=authorization_code.resource or self.resource_url,
            lifetime=30 * 24 * 3600,
        )
        return OAuthToken(
            access_token=access_token,
            token_type="Bearer",
            expires_in=3600,
            scope=" ".join(authorization_code.scopes),
            refresh_token=refresh_token,
        )

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RefreshToken | None:
        payload = self._decode(refresh_token, "refresh")
        if payload is None or payload.get("client_id") != client.client_id:
            return None
        self._prune_one_time_state()
        if str(payload["jti"]) in self._revoked_tokens:
            return None
        return RefreshToken(
            token=refresh_token,
            client_id=str(payload["client_id"]),
            scopes=list(payload["scopes"]),
            expires_at=int(payload["exp"]),
            resource=str(payload["resource"]),
            subject="owner",
        )

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        payload = self._decode(refresh_token.token, "refresh")
        if payload is None or payload.get("client_id") != client.client_id:
            raise TokenError("invalid_grant", "Invalid refresh token.")
        self._prune_one_time_state()
        token_id = str(payload["jti"])
        if token_id in self._revoked_tokens:
            raise TokenError("invalid_grant", "Refresh token was already used.")
        self._revoked_tokens[token_id] = int(payload["exp"])

        access_token = self._mint_token(
            kind="access",
            client_id=client.client_id,
            scopes=scopes,
            resource=refresh_token.resource or self.resource_url,
            lifetime=3600,
        )
        new_refresh_token = self._mint_token(
            kind="refresh",
            client_id=client.client_id,
            scopes=scopes,
            resource=refresh_token.resource or self.resource_url,
            lifetime=30 * 24 * 3600,
        )
        return OAuthToken(
            access_token=access_token,
            token_type="Bearer",
            expires_in=3600,
            scope=" ".join(scopes),
            refresh_token=new_refresh_token,
        )

    async def load_access_token(self, token: str) -> AccessToken | None:
        if self._bearer_token and secrets.compare_digest(token, self._bearer_token):
            return AccessToken(
                token=token,
                client_id="static-bearer-client",
                scopes=["datasets:read"],
                resource=self.resource_url,
                subject="owner",
            )

        payload = self._decode(token, "access")
        if payload is None:
            return None
        self._prune_one_time_state()
        if str(payload["jti"]) in self._revoked_tokens:
            return None
        return AccessToken(
            token=token,
            client_id=str(payload["client_id"]),
            scopes=list(payload["scopes"]),
            expires_at=int(payload["exp"]),
            resource=str(payload["resource"]),
            subject=str(payload["subject"]),
            claims={"iss": self.issuer_url},
        )

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        for kind in ("access", "refresh"):
            payload = self._decode(token.token, kind)
            if payload is not None:
                self._revoked_tokens[str(payload["jti"])] = int(payload["exp"])
                return
