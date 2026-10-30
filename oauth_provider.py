"""OAuth 2.1 authorization-code bridge for remote MCP clients."""

from __future__ import annotations

import secrets
import time
from typing import Any
from urllib.parse import urlencode

import jwt
from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    RefreshToken,
    TokenError,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

from config import Settings
from database import Database, OAuthArtifact


class InsightMonkOAuthProvider:
    """Issue MCP-specific tokens after an existing InsightMonk user signs in."""

    scope = "reports:read"

    def __init__(self, settings: Settings, database: Database):
        self.settings = settings
        self.database = database

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        return await self.database.get_client(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        await self.database.save_client(client_info)

    def _encode_state(
        self, kind: str, payload: dict[str, Any], *, expires_in: int = 300
    ) -> str:
        now = int(time.time())
        return jwt.encode(
            {
                **payload,
                "kind": kind,
                "iss": self.settings.issuer_url,
                "aud": "mcp-login",
                "iat": now,
                "exp": now + expires_in,
                "jti": secrets.token_urlsafe(18),
            },
            self.settings.oauth_signing_key,
            algorithm="HS256",
        )

    def _decode_state(self, token: str, expected_kind: str) -> dict[str, Any]:
        try:
            payload = jwt.decode(
                token,
                self.settings.oauth_signing_key,
                algorithms=["HS256"],
                issuer=self.settings.issuer_url,
                audience="mcp-login",
                options={"require": ["exp", "iat", "jti", "kind"]},
            )
        except jwt.PyJWTError as error:
            raise AuthorizeError("invalid_request", "The login request has expired.") from error
        if payload.get("kind") != expected_kind:
            raise AuthorizeError("invalid_request", "The login request is invalid.")
        return payload

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        resource = params.resource or self.settings.server_url
        if resource.rstrip("/") != self.settings.server_url.rstrip("/"):
            raise AuthorizeError("invalid_target", "Unknown MCP resource.")
        scopes = params.scopes or [self.scope]
        if any(scope != self.scope for scope in scopes):
            raise AuthorizeError("invalid_scope", "Only reports:read is supported.")
        request_token = self._encode_state(
            "authorization_request",
            {
                "client_id": client.client_id,
                "redirect_uri": str(params.redirect_uri),
                "redirect_uri_provided_explicitly": params.redirect_uri_provided_explicitly,
                "code_challenge": params.code_challenge,
                "scopes": scopes,
                "state": params.state,
                "resource": resource,
            },
        )
        return f"{self.settings.issuer_url}/oauth/login?{urlencode({'request': request_token})}"

    def decode_authorization_request(self, token: str) -> dict[str, Any]:
        return self._decode_state(token, "authorization_request")

    def create_mfa_state(self, email: str, authorization_request: str) -> str:
        return self._encode_state(
            "mfa_request",
            {"email": email, "authorization_request": authorization_request},
            expires_in=180,
        )

    def decode_mfa_state(self, token: str) -> dict[str, Any]:
        return self._decode_state(token, "mfa_request")

    async def complete_authorization(self, request_token: str, user_id: int) -> str:
        request = self.decode_authorization_request(request_token)
        client_id = str(request.get("client_id", ""))
        client = await self.get_client(client_id)
        if client is None:
            raise AuthorizeError("invalid_request", "The OAuth client is no longer registered.")
        user = await self.database.get_user(user_id)
        if user is None or not user.mcp_allowed:
            raise AuthorizeError("access_denied", "This InsightMonk account cannot use MCP.")

        code = secrets.token_urlsafe(32)
        expires_at = int(time.time()) + self.settings.oauth_code_seconds
        scopes = [str(value) for value in request.get("scopes", [self.scope])]
        metadata = {
            "code_challenge": str(request["code_challenge"]),
            "redirect_uri": str(request["redirect_uri"]),
            "redirect_uri_provided_explicitly": bool(
                request.get("redirect_uri_provided_explicitly")
            ),
            "state": request.get("state"),
        }
        await self.database.save_artifact(
            token=code,
            kind="code",
            client_id=client_id,
            subject=str(user.user_id),
            scopes=scopes,
            resource=str(request.get("resource") or self.settings.server_url),
            metadata=metadata,
            expires_at=expires_at,
        )
        return construct_redirect_uri(
            metadata["redirect_uri"], code=code, state=metadata.get("state")
        )

    @staticmethod
    def _authorization_code(token: str, artifact: OAuthArtifact) -> AuthorizationCode:
        return AuthorizationCode(
            code=token,
            scopes=artifact.scopes,
            expires_at=artifact.expires_at,
            client_id=artifact.client_id,
            code_challenge=str(artifact.metadata["code_challenge"]),
            redirect_uri=str(artifact.metadata["redirect_uri"]),
            redirect_uri_provided_explicitly=bool(
                artifact.metadata.get("redirect_uri_provided_explicitly")
            ),
            resource=artifact.resource,
            subject=artifact.subject,
        )

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        artifact = await self.database.load_artifact(authorization_code, "code")
        if artifact is None or artifact.client_id != client.client_id:
            return None
        return self._authorization_code(authorization_code, artifact)

    async def _issue_tokens(
        self,
        *,
        client_id: str,
        subject: str,
        scopes: list[str],
        resource: str | None,
    ) -> OAuthToken:
        user = await self.database.get_user(subject)
        if user is None or not user.mcp_allowed:
            raise TokenError("invalid_grant", "The InsightMonk account is not active.")

        now = int(time.time())
        access_expiry = now + self.settings.oauth_access_token_seconds
        jti = secrets.token_urlsafe(24)
        bound_resource = resource or self.settings.server_url
        access_token = jwt.encode(
            {
                "kind": "access",
                "iss": self.settings.issuer_url,
                "aud": bound_resource,
                "sub": str(user.user_id),
                "client_id": client_id,
                "scope": " ".join(scopes),
                "role": user.role,
                "company_id": user.company_id,
                "iat": now,
                "exp": access_expiry,
                "jti": jti,
            },
            self.settings.oauth_signing_key,
            algorithm="HS256",
        )

        refresh_token = secrets.token_urlsafe(48)
        refresh_expiry = now + self.settings.oauth_refresh_token_seconds
        await self.database.save_artifact(
            token=refresh_token,
            kind="refresh",
            client_id=client_id,
            subject=str(user.user_id),
            scopes=scopes,
            resource=bound_resource,
            metadata={"access_jti": jti, "access_expires_at": access_expiry},
            expires_at=refresh_expiry,
        )
        return OAuthToken(
            access_token=access_token,
            expires_in=self.settings.oauth_access_token_seconds,
            scope=" ".join(scopes),
            refresh_token=refresh_token,
        )

    async def exchange_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: AuthorizationCode,
    ) -> OAuthToken:
        if not await self.database.consume_artifact(authorization_code.code, "code"):
            raise TokenError("invalid_grant", "The authorization code was already used.")
        if authorization_code.subject is None:
            raise TokenError("invalid_grant", "The authorization code has no user.")
        return await self._issue_tokens(
            client_id=client.client_id,
            subject=authorization_code.subject,
            scopes=authorization_code.scopes,
            resource=authorization_code.resource,
        )

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RefreshToken | None:
        artifact = await self.database.load_artifact(refresh_token, "refresh")
        if artifact is None or artifact.client_id != client.client_id:
            return None
        user = await self.database.get_user(artifact.subject)
        if user is None or not user.mcp_allowed:
            return None
        return RefreshToken(
            token=refresh_token,
            client_id=artifact.client_id,
            scopes=artifact.scopes,
            expires_at=artifact.expires_at,
            resource=artifact.resource,
            subject=artifact.subject,
        )

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        if not await self.database.consume_artifact(refresh_token.token, "refresh"):
            raise TokenError("invalid_grant", "The refresh token was already used.")
        if refresh_token.subject is None:
            raise TokenError("invalid_grant", "The refresh token has no user.")
        return await self._issue_tokens(
            client_id=client.client_id,
            subject=refresh_token.subject,
            scopes=scopes,
            resource=refresh_token.resource,
        )

    async def load_access_token(self, token: str) -> AccessToken | None:
        try:
            claims = jwt.decode(
                token,
                self.settings.oauth_signing_key,
                algorithms=["HS256"],
                issuer=self.settings.issuer_url,
                audience=self.settings.server_url,
                options={
                    "require": [
                        "exp",
                        "iat",
                        "jti",
                        "sub",
                        "client_id",
                        "kind",
                    ]
                },
            )
        except jwt.PyJWTError:
            return None
        if claims.get("kind") != "access":
            return None
        jti = str(claims["jti"])
        if await self.database.is_access_jti_revoked(jti):
            return None
        user = await self.database.get_user(str(claims["sub"]))
        if user is None or not user.mcp_allowed:
            return None
        scopes = str(claims.get("scope") or "").split()
        return AccessToken(
            token=token,
            client_id=str(claims["client_id"]),
            scopes=scopes,
            expires_at=int(claims["exp"]),
            resource=self.settings.server_url,
            subject=str(user.user_id),
            claims={
                "iss": self.settings.issuer_url,
                "role": user.role,
                "company_id": user.company_id,
                "membership": user.membership,
            },
        )

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        if isinstance(token, RefreshToken):
            artifact = await self.database.load_artifact(token.token, "refresh")
            await self.database.consume_artifact(token.token, "refresh")
            if artifact:
                jti = artifact.metadata.get("access_jti")
                expires_at = artifact.metadata.get("access_expires_at")
                if isinstance(jti, str) and isinstance(expires_at, int):
                    await self.database.revoke_access_jti(jti, expires_at)
            return
        try:
            claims = jwt.decode(
                token.token,
                self.settings.oauth_signing_key,
                algorithms=["HS256"],
                options={"verify_aud": False},
            )
            jti = str(claims["jti"])
            await self.database.revoke_access_jti(jti, int(claims["exp"]))
            await self.database.consume_refresh_for_access_jti(jti)
        except (jwt.PyJWTError, KeyError, TypeError, ValueError):
            return

