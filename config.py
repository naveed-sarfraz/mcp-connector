"""Environment-backed configuration for the open InsightMonk MCP server."""

from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import urlparse

from dotenv import load_dotenv

load_dotenv()


def configured_server_url() -> str:
    configured = os.getenv("MCP_SERVER_URL")
    if configured:
        return configured.rstrip("/")
    render_hostname = os.getenv("RENDER_EXTERNAL_HOSTNAME")
    if render_hostname:
        return f"https://{render_hostname}/mcp"
    return "http://127.0.0.1:8000/mcp"


@dataclass(frozen=True, slots=True)
class Settings:
    server_url: str
    insightmonk_base_url: str
    http_timeout_seconds: float
    pdf_max_download_bytes: int
    pdf_max_embedded_bytes: int
    pdf_max_extracted_characters: int
    pdf_cache_ttl_seconds: int
    pdf_cache_max_bytes: int
    dev_mode: bool

    @classmethod
    def from_env(cls) -> "Settings":
        server_url = configured_server_url()
        parts = urlparse(server_url)
        remote = parts.hostname not in {"127.0.0.1", "localhost", "::1"}
        return cls(
            server_url=server_url,
            insightmonk_base_url=os.getenv(
                "INSIGHTMONK_BASE_URL", "https://community-api.insightmonk.com"
            ).rstrip("/"),
            http_timeout_seconds=float(os.getenv("HTTP_TIMEOUT_SECONDS", "30")),
            pdf_max_download_bytes=int(
                os.getenv("PDF_MAX_DOWNLOAD_BYTES", str(50 * 1024 * 1024))
            ),
            pdf_max_embedded_bytes=int(
                os.getenv("PDF_MAX_EMBEDDED_BYTES", str(20 * 1024 * 1024))
            ),
            pdf_max_extracted_characters=int(
                os.getenv("PDF_MAX_EXTRACTED_CHARACTERS", "500000")
            ),
            pdf_cache_ttl_seconds=int(os.getenv("PDF_CACHE_TTL_SECONDS", "900")),
            pdf_cache_max_bytes=int(
                os.getenv("PDF_CACHE_MAX_BYTES", str(128 * 1024 * 1024))
            ),
            dev_mode=not remote,
        )

    def validate(self) -> None:
        parts = urlparse(self.server_url)
        if parts.path != "/mcp":
            raise RuntimeError("MCP_SERVER_URL must end with /mcp")
        if not self.dev_mode and parts.scheme != "https":
            raise RuntimeError("MCP_SERVER_URL must use HTTPS outside local development")
        if not self.insightmonk_base_url.startswith("https://"):
            raise RuntimeError("INSIGHTMONK_BASE_URL must use HTTPS")

        positive_values = {
            "HTTP_TIMEOUT_SECONDS": self.http_timeout_seconds,
            "PDF_MAX_DOWNLOAD_BYTES": self.pdf_max_download_bytes,
            "PDF_MAX_EMBEDDED_BYTES": self.pdf_max_embedded_bytes,
            "PDF_MAX_EXTRACTED_CHARACTERS": self.pdf_max_extracted_characters,
            "PDF_CACHE_TTL_SECONDS": self.pdf_cache_ttl_seconds,
            "PDF_CACHE_MAX_BYTES": self.pdf_cache_max_bytes,
        }
        invalid = [name for name, value in positive_values.items() if value <= 0]
        if invalid:
            raise RuntimeError(
                f"Environment variables must be greater than zero: {', '.join(invalid)}"
            )


settings = Settings.from_env()
