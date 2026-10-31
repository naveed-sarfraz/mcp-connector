"""Client for the unauthenticated InsightMonk public report APIs."""

from __future__ import annotations

from typing import Any

import httpx

from config import Settings


class InsightMonkError(RuntimeError):
    """A safe-to-display upstream integration failure."""


class InsightMonkClient:
    def __init__(self, settings: Settings, client: httpx.AsyncClient | None = None):
        self._client = client or httpx.AsyncClient(
            base_url=settings.insightmonk_base_url,
            timeout=httpx.Timeout(settings.http_timeout_seconds),
            follow_redirects=False,
            headers={"Accept": "application/json"},
        )
        self._owns_client = client is None

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

    async def request(
        self,
        method: str,
        path: str,
        *,
        json_body: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        try:
            response = await self._client.request(
                method, path, json=json_body, params=params
            )
        except httpx.HTTPError as error:
            raise InsightMonkError("InsightMonk is temporarily unavailable.") from error

        if response.status_code == 404:
            raise InsightMonkError("The requested report was not found.")
        if response.status_code == 410:
            raise InsightMonkError(
                "The report search cursor expired. Start the search again."
            )
        if response.status_code == 429:
            raise InsightMonkError(
                "The public report API rate limit was reached. Please try again shortly."
            )
        if response.status_code >= 400:
            raise InsightMonkError("InsightMonk could not complete the request.")
        return self._json_object(response)

    async def search_reports(self, payload: dict[str, Any]) -> dict[str, Any]:
        body = await self.request(
            "POST", "/v1/reports/public/search", json_body=payload
        )
        if (
            body.get("success") is not True
            or not isinstance(body.get("results"), list)
            or not isinstance(body.get("hasMore"), bool)
        ):
            raise InsightMonkError(
                "InsightMonk returned an invalid report search response."
            )
        return body

    async def get_report_content(self, report_id: str) -> dict[str, Any]:
        body = await self.request(
            "GET", "/v1/reports/public/content", params={"reportId": report_id}
        )
        data = body.get("data")
        if body.get("success") is not True or not isinstance(data, dict):
            raise InsightMonkError("InsightMonk returned an invalid report response.")
        pdf = data.get("pdf")
        if (
            not isinstance(pdf, dict)
            or not isinstance(pdf.get("url"), str)
            or not pdf["url"]
        ):
            raise InsightMonkError("This report does not include a downloadable PDF.")
        return data
