"""InsightMonk API client with safe, centralized service-token management."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Any

import httpx
import jwt

from config import Settings


class InsightMonkError(RuntimeError):
    """A safe-to-display upstream integration failure."""


@dataclass(frozen=True, slots=True)
class UserLoginResult:
    status: str
    email: str | None = None
    user_id: int | None = None
    claims: dict[str, Any] | None = None


class InsightMonkClient:
    def __init__(self, settings: Settings, client: httpx.AsyncClient | None = None):
        self.settings = settings
        self._client = client or httpx.AsyncClient(
            base_url=settings.insightmonk_base_url,
            timeout=httpx.Timeout(settings.http_timeout_seconds),
            follow_redirects=False,
            headers={"Accept": "application/json"},
        )
        self._owns_client = client is None
        self._service_token: str | None = None
        self._service_expires_at = 0
        self._login_lock = asyncio.Lock()

    async def close(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    @staticmethod
    def _json_object(response: httpx.Response) -> dict[str, Any]:
        try:
            value = response.json()
        except ValueError as error:
            raise InsightMonkError("InsightMonk returned an invalid response.") from error
        if not isinstance(value, dict):
            raise InsightMonkError("InsightMonk returned an invalid response.")
        return value

    def verify_user_access_token(self, token: str) -> dict[str, Any]:
        try:
            claims = jwt.decode(
                token,
                self.settings.insightmonk_jwt_secret,
                algorithms=["HS256"],
                options={"require": ["exp", "user_id", "token_type"]},
            )
        except jwt.PyJWTError as error:
            raise InsightMonkError("InsightMonk returned an invalid login token.") from error
        if claims.get("token_type") != "access":
            raise InsightMonkError("InsightMonk returned an invalid login token.")
        try:
            claims["user_id"] = int(claims["user_id"])
        except (TypeError, ValueError) as error:
            raise InsightMonkError("InsightMonk returned an invalid login token.") from error
        return claims

    async def login_user(self, email: str, password: str) -> UserLoginResult:
        try:
            response = await self._client.post(
                "/v1/auth/login", json={"email": email, "password": password}
            )
        except httpx.HTTPError as error:
            raise InsightMonkError("InsightMonk login is temporarily unavailable.") from error

        body = self._json_object(response)
        if response.status_code != 200 or body.get("status") is not True:
            raise InsightMonkError("The email or password was not accepted.")
        if body.get("message") == "MFA":
            return UserLoginResult(status="mfa", email=str(body.get("email") or email))

        access_token = body.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise InsightMonkError("InsightMonk returned an invalid login response.")
        claims = self.verify_user_access_token(access_token)
        return UserLoginResult(
            status="success", user_id=int(claims["user_id"]), claims=claims
        )

    async def verify_user_otp(self, email: str, otp: str) -> UserLoginResult:
        try:
            response = await self._client.post(
                "/v1/auth/verifyOTP", json={"uEmail": email, "otp": otp}
            )
        except httpx.HTTPError as error:
            raise InsightMonkError("InsightMonk verification is temporarily unavailable.") from error

        body = self._json_object(response)
        if response.status_code != 200 or body.get("status") is not True:
            raise InsightMonkError("The verification code was not accepted.")
        access_token = body.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise InsightMonkError("InsightMonk returned an invalid verification response.")
        claims = self.verify_user_access_token(access_token)
        return UserLoginResult(
            status="success", user_id=int(claims["user_id"]), claims=claims
        )

    @staticmethod
    def _unverified_expiry(token: str) -> int:
        try:
            claims = jwt.decode(
                token,
                options={"verify_signature": False, "verify_exp": False},
                algorithms=["HS256"],
            )
            return int(claims["exp"])
        except (jwt.PyJWTError, KeyError, TypeError, ValueError) as error:
            raise InsightMonkError("InsightMonk returned an invalid service token.") from error

    async def _login_service(self) -> str:
        if not self.settings.insightmonk_email or not self.settings.insightmonk_password:
            raise InsightMonkError("InsightMonk service credentials are not configured.")
        try:
            response = await self._client.post(
                "/v1/auth/login",
                json={
                    "email": self.settings.insightmonk_email,
                    "password": self.settings.insightmonk_password,
                },
            )
        except httpx.HTTPError as error:
            raise InsightMonkError("InsightMonk authentication is temporarily unavailable.") from error

        body = self._json_object(response)
        if response.status_code != 200 or body.get("status") is not True:
            raise InsightMonkError("InsightMonk service authentication failed.")
        if body.get("message") == "MFA":
            raise InsightMonkError(
                "The configured InsightMonk service account requires interactive MFA."
            )
        token = body.get("access_token")
        if not isinstance(token, str) or not token:
            raise InsightMonkError("InsightMonk returned an invalid service login response.")
        self._service_token = token
        self._service_expires_at = self._unverified_expiry(token)
        return token

    async def access_token(self, *, force: bool = False) -> str:
        # Refresh five minutes early. The observed production token lifetime is 12h,
        # so expiry is always derived from the JWT instead of a fixed assumption.
        if (
            not force
            and self._service_token
            and self._service_expires_at - int(time.time()) > 300
        ):
            return self._service_token

        async with self._login_lock:
            if (
                not force
                and self._service_token
                and self._service_expires_at - int(time.time()) > 300
            ):
                return self._service_token
            return await self._login_service()

    async def request(
        self,
        method: str,
        path: str,
        *,
        json_body: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        for attempt in range(2):
            token = await self.access_token(force=attempt == 1)
            try:
                response = await self._client.request(
                    method,
                    path,
                    json=json_body,
                    params=params,
                    headers={"Authorization": f"Bearer {token}"},
                )
            except httpx.HTTPError as error:
                raise InsightMonkError("InsightMonk is temporarily unavailable.") from error
            if response.status_code == 401 and attempt == 0:
                self._service_token = None
                self._service_expires_at = 0
                continue
            if response.status_code == 404:
                raise InsightMonkError("The requested report was not found.")
            if response.status_code == 403:
                raise InsightMonkError("The configured service account cannot access this report.")
            if response.status_code >= 400:
                raise InsightMonkError("InsightMonk could not complete the request.")
            return self._json_object(response)
        raise InsightMonkError("InsightMonk service authentication failed.")

    async def search_reports(self, payload: dict[str, Any]) -> dict[str, Any]:
        body = await self.request("POST", "/v1/reports/search", json_body=payload)
        if body.get("success") is not True or not isinstance(body.get("list"), list):
            raise InsightMonkError("InsightMonk returned an invalid report search response.")
        return body

    async def get_report_content(self, report_id: str) -> dict[str, Any]:
        body = await self.request(
            "GET", "/v1/reports/getContent", params={"reportId": report_id}
        )
        data = body.get("data")
        if body.get("success") is not True or not isinstance(data, dict):
            raise InsightMonkError("InsightMonk returned an invalid report response.")
        url = data.get("url")
        if not isinstance(url, str) or not url:
            raise InsightMonkError("This report does not include a downloadable PDF.")
        return data

