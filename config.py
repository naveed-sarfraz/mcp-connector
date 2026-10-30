"""Environment-backed configuration for the InsightMonk MCP server."""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from urllib.parse import urlparse

from dotenv import load_dotenv

load_dotenv()


def _bool_env(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


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
    issuer_url: str
    insightmonk_base_url: str
    insightmonk_email: str
    insightmonk_password: str
    insightmonk_jwt_secret: str
    oauth_signing_key: str
    mysql_host: str
    mysql_port: int
    mysql_user: str
    mysql_password: str
    mysql_database: str
    mysql_ssl: bool
    mysql_ssl_ca: str | None
    http_timeout_seconds: float
    pdf_max_download_bytes: int
    pdf_max_embedded_bytes: int
    pdf_max_extracted_characters: int
    pdf_cache_ttl_seconds: int
    pdf_cache_max_bytes: int
    oauth_access_token_seconds: int
    oauth_refresh_token_seconds: int
    oauth_code_seconds: int
    auto_migrate: bool
    dev_mode: bool

    @classmethod
    def from_env(cls) -> "Settings":
        server_url = configured_server_url()
        parts = urlparse(server_url)
        issuer_url = f"{parts.scheme}://{parts.netloc}"
        remote = parts.hostname not in {"127.0.0.1", "localhost", "::1"}
        signing_key = os.getenv("MCP_OAUTH_SIGNING_KEY", "")
        dev_mode = not remote
        if not signing_key and dev_mode:
            # Local-only convenience. Restarting invalidates local OAuth sessions.
            signing_key = secrets.token_urlsafe(48)

        return cls(
            server_url=server_url,
            issuer_url=issuer_url,
            insightmonk_base_url=os.getenv(
                "INSIGHTMONK_BASE_URL", "https://community-api.insightmonk.com"
            ).rstrip("/"),
            insightmonk_email=os.getenv("INSIGHTMONK_EMAIL", ""),
            insightmonk_password=os.getenv("INSIGHTMONK_PASSWORD", ""),
            insightmonk_jwt_secret=os.getenv("JWT_SECRET", ""),
            oauth_signing_key=signing_key,
            mysql_host=os.getenv("MYSQL_HOST", ""),
            mysql_port=int(os.getenv("MYSQL_PORT", "3306")),
            mysql_user=os.getenv("MYSQL_USER", ""),
            mysql_password=os.getenv("MYSQL_PASSWORD", ""),
            mysql_database=os.getenv("MYSQL_DATABASE", ""),
            mysql_ssl=_bool_env("MYSQL_SSL", False),
            mysql_ssl_ca=os.getenv("MYSQL_SSL_CA") or None,
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
            oauth_access_token_seconds=int(
                os.getenv("MCP_ACCESS_TOKEN_SECONDS", "3600")
            ),
            oauth_refresh_token_seconds=int(
                os.getenv("MCP_REFRESH_TOKEN_SECONDS", str(30 * 24 * 3600))
            ),
            oauth_code_seconds=int(os.getenv("MCP_AUTH_CODE_SECONDS", "300")),
            auto_migrate=_bool_env("MCP_AUTO_MIGRATE", True),
            dev_mode=dev_mode,
        )

    def validate(self) -> None:
        parts = urlparse(self.server_url)
        if parts.path != "/mcp":
            raise RuntimeError("MCP_SERVER_URL must end with /mcp")
        if not self.dev_mode and parts.scheme != "https":
            raise RuntimeError("MCP_SERVER_URL must use HTTPS outside local development")

        required = {
            "INSIGHTMONK_EMAIL": self.insightmonk_email,
            "INSIGHTMONK_PASSWORD": self.insightmonk_password,
            "JWT_SECRET": self.insightmonk_jwt_secret,
            "MCP_OAUTH_SIGNING_KEY": self.oauth_signing_key,
            "MYSQL_HOST": self.mysql_host,
            "MYSQL_USER": self.mysql_user,
            "MYSQL_PASSWORD": self.mysql_password,
            "MYSQL_DATABASE": self.mysql_database,
        }
        missing = [name for name, value in required.items() if not value]
        if missing:
            raise RuntimeError(f"Missing required environment variables: {', '.join(missing)}")
        if len(self.oauth_signing_key) < 32:
            raise RuntimeError("MCP_OAUTH_SIGNING_KEY must contain at least 32 characters")
        if not self.insightmonk_base_url.startswith("https://"):
            raise RuntimeError("INSIGHTMONK_BASE_URL must use HTTPS")


settings = Settings.from_env()
