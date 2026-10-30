"""Read-only application authorization plus persistent MCP OAuth state."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, TypeVar

import pymysql
from cryptography.fernet import Fernet, InvalidToken
from mcp.shared.auth import OAuthClientInformationFull
from pymysql.cursors import DictCursor

from config import Settings

T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class UserAccess:
    user_id: int
    active: bool
    soft_deleted: bool
    role: str | None
    company_id: int | None
    client_admin: bool
    membership: str | None

    @property
    def mcp_allowed(self) -> bool:
        # Product decision: every active, non-deleted role/plan/company is allowed.
        return self.active and not self.soft_deleted


@dataclass(frozen=True, slots=True)
class OAuthArtifact:
    token_hash: str
    kind: str
    client_id: str
    subject: str
    scopes: list[str]
    resource: str | None
    metadata: dict[str, Any]
    expires_at: int


MIGRATION_STATEMENTS = (
    """
    CREATE TABLE IF NOT EXISTS mcp_oauth_clients (
        client_id VARCHAR(128) NOT NULL PRIMARY KEY,
        client_info LONGTEXT NOT NULL,
        encrypted_secret LONGTEXT NULL,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """,
    """
    CREATE TABLE IF NOT EXISTS mcp_oauth_artifacts (
        token_hash CHAR(64) NOT NULL PRIMARY KEY,
        kind VARCHAR(16) NOT NULL,
        client_id VARCHAR(128) NOT NULL,
        subject VARCHAR(128) NOT NULL,
        scopes LONGTEXT NOT NULL,
        resource VARCHAR(512) NULL,
        metadata LONGTEXT NOT NULL,
        expires_at DATETIME NOT NULL,
        consumed_at DATETIME NULL,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_mcp_artifact_expiry (expires_at),
        INDEX idx_mcp_artifact_client_subject (client_id, subject)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """,
    """
    CREATE TABLE IF NOT EXISTS mcp_oauth_revocations (
        jti VARCHAR(128) NOT NULL PRIMARY KEY,
        expires_at DATETIME NOT NULL,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_mcp_revocation_expiry (expires_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """,
)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _as_utc_datetime(timestamp: int | float) -> datetime:
    return datetime.fromtimestamp(timestamp, timezone.utc).replace(tzinfo=None)


class Database:
    """Small connection facade over the same MySQL database used by community-api."""

    def __init__(self, settings: Settings):
        self.settings = settings
        fernet_key = base64.urlsafe_b64encode(
            hashlib.sha256(settings.oauth_signing_key.encode("utf-8")).digest()
        )
        self._fernet = Fernet(fernet_key)

    def _connect(self) -> pymysql.Connection:
        ssl: dict[str, str] | None = None
        if self.settings.mysql_ssl:
            ssl = {"ca": self.settings.mysql_ssl_ca} if self.settings.mysql_ssl_ca else {}
        return pymysql.connect(
            host=self.settings.mysql_host,
            port=self.settings.mysql_port,
            user=self.settings.mysql_user,
            password=self.settings.mysql_password,
            database=self.settings.mysql_database,
            charset="utf8mb4",
            cursorclass=DictCursor,
            connect_timeout=8,
            read_timeout=10,
            write_timeout=10,
            autocommit=True,
            ssl=ssl,
        )

    async def _run(self, operation: Callable[[pymysql.Connection], T]) -> T:
        def execute() -> T:
            connection = self._connect()
            try:
                return operation(connection)
            finally:
                connection.close()

        return await asyncio.to_thread(execute)

    async def migrate(self) -> None:
        def operation(connection: pymysql.Connection) -> None:
            with connection.cursor() as cursor:
                for statement in MIGRATION_STATEMENTS:
                    cursor.execute(statement)

        await self._run(operation)

    async def ping(self) -> None:
        def operation(connection: pymysql.Connection) -> None:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
                cursor.fetchone()

        await self._run(operation)

    async def get_user(self, user_id: int | str) -> UserAccess | None:
        try:
            normalized_id = int(user_id)
        except (TypeError, ValueError):
            return None

        def operation(connection: pymysql.Connection) -> UserAccess | None:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT
                        u.id,
                        u.is_active,
                        u.soft_delete,
                        u.company_id,
                        COALESCE(u.is_client_admin, 0) AS is_client_admin,
                        ur.code AS role,
                        (
                            SELECT um.plan
                            FROM user_memberships AS um
                            WHERE um.user_id = u.id AND um.expiry > NOW()
                            ORDER BY um.id DESC
                            LIMIT 1
                        ) AS membership
                    FROM users AS u
                    LEFT JOIN user_roles AS ur ON ur.id = u.user_type_id
                    WHERE u.id = %s
                    LIMIT 1
                    """,
                    (normalized_id,),
                )
                row = cursor.fetchone()
            if row is None:
                return None
            return UserAccess(
                user_id=int(row["id"]),
                active=bool(row["is_active"]),
                soft_deleted=bool(row["soft_delete"]),
                role=row.get("role"),
                company_id=(
                    int(row["company_id"]) if row.get("company_id") is not None else None
                ),
                client_admin=bool(row["is_client_admin"]),
                membership=row.get("membership"),
            )

        return await self._run(operation)

    async def can_access_full_report(
        self, user: UserAccess, report_id: str, topics: list[str] | None = None
    ) -> bool:
        """Mirror community-api's full-report plan, topic, and library rules."""
        if user.membership == "platinum":
            return True

        normalized_topics = {
            topic.strip()
            for topic in (topics or [])[:100]
            if isinstance(topic, str) and 0 < len(topic.strip()) <= 200
        }

        def operation(connection: pymysql.Connection) -> bool:
            with connection.cursor() as cursor:
                if user.membership == "gold" and normalized_topics:
                    cursor.execute(
                        """
                        SELECT t.title
                        FROM user_sectors AS us
                        INNER JOIN topics AS t ON t.id = us.topic_id
                        WHERE us.user_id = %s AND us.expiry >= NOW()
                        ORDER BY us.id DESC
                        LIMIT 1
                        """,
                        (user.user_id,),
                    )
                    subscribed_topic = cursor.fetchone()
                    if subscribed_topic and subscribed_topic.get("title") in normalized_topics:
                        return True
                if user.role == "CLIENT" and user.client_admin and user.company_id is not None:
                    cursor.execute(
                        """
                        SELECT 1
                        FROM user_purchases AS up
                        INNER JOIN users AS purchaser ON purchaser.id = up.user_id
                        WHERE purchaser.company_id = %s AND up.item_id = %s
                        LIMIT 1
                        """,
                        (user.company_id, report_id),
                    )
                else:
                    cursor.execute(
                        """
                        SELECT 1
                        FROM user_purchases
                        WHERE user_id = %s AND item_id = %s
                        LIMIT 1
                        """,
                        (user.user_id, report_id),
                    )
                return cursor.fetchone() is not None

        return await self._run(operation)

    async def save_client(self, client: OAuthClientInformationFull) -> None:
        data = client.model_dump(mode="json")
        secret = data.pop("client_secret", None)
        encrypted_secret = (
            self._fernet.encrypt(secret.encode("utf-8")).decode("ascii") if secret else None
        )
        serialized = json.dumps(data, separators=(",", ":"), sort_keys=True)

        def operation(connection: pymysql.Connection) -> None:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO mcp_oauth_clients (client_id, client_info, encrypted_secret)
                    VALUES (%s, %s, %s)
                    ON DUPLICATE KEY UPDATE
                        client_info = VALUES(client_info),
                        encrypted_secret = VALUES(encrypted_secret)
                    """,
                    (client.client_id, serialized, encrypted_secret),
                )

        await self._run(operation)

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        def operation(connection: pymysql.Connection) -> dict[str, Any] | None:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT client_info, encrypted_secret
                    FROM mcp_oauth_clients
                    WHERE client_id = %s
                    LIMIT 1
                    """,
                    (client_id,),
                )
                return cursor.fetchone()

        row = await self._run(operation)
        if row is None:
            return None
        try:
            data = json.loads(row["client_info"])
            encrypted_secret = row.get("encrypted_secret")
            if encrypted_secret:
                data["client_secret"] = self._fernet.decrypt(
                    encrypted_secret.encode("ascii")
                ).decode("utf-8")
            return OAuthClientInformationFull.model_validate(data)
        except (InvalidToken, ValueError, TypeError, json.JSONDecodeError):
            return None

    async def save_artifact(
        self,
        *,
        token: str,
        kind: str,
        client_id: str,
        subject: str,
        scopes: list[str],
        resource: str | None,
        metadata: dict[str, Any],
        expires_at: int,
    ) -> None:
        hashed = token_hash(token)

        def operation(connection: pymysql.Connection) -> None:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO mcp_oauth_artifacts
                        (token_hash, kind, client_id, subject, scopes, resource, metadata, expires_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        hashed,
                        kind,
                        client_id,
                        subject,
                        json.dumps(scopes, separators=(",", ":")),
                        resource,
                        json.dumps(metadata, separators=(",", ":"), sort_keys=True),
                        _as_utc_datetime(expires_at),
                    ),
                )

        await self._run(operation)

    async def load_artifact(self, token: str, kind: str) -> OAuthArtifact | None:
        hashed = token_hash(token)

        def operation(connection: pymysql.Connection) -> dict[str, Any] | None:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT token_hash, kind, client_id, subject, scopes, resource,
                           metadata, UNIX_TIMESTAMP(expires_at) AS expires_at
                    FROM mcp_oauth_artifacts
                    WHERE token_hash = %s AND kind = %s AND consumed_at IS NULL
                          AND expires_at > UTC_TIMESTAMP()
                    LIMIT 1
                    """,
                    (hashed, kind),
                )
                return cursor.fetchone()

        row = await self._run(operation)
        if row is None:
            return None
        try:
            return OAuthArtifact(
                token_hash=row["token_hash"],
                kind=row["kind"],
                client_id=row["client_id"],
                subject=row["subject"],
                scopes=list(json.loads(row["scopes"])),
                resource=row.get("resource"),
                metadata=dict(json.loads(row["metadata"])),
                expires_at=int(row["expires_at"]),
            )
        except (ValueError, TypeError, json.JSONDecodeError):
            return None

    async def consume_artifact(self, token: str, kind: str) -> bool:
        hashed = token_hash(token)

        def operation(connection: pymysql.Connection) -> bool:
            with connection.cursor() as cursor:
                affected = cursor.execute(
                    """
                    UPDATE mcp_oauth_artifacts
                    SET consumed_at = UTC_TIMESTAMP()
                    WHERE token_hash = %s AND kind = %s AND consumed_at IS NULL
                          AND expires_at > UTC_TIMESTAMP()
                    """,
                    (hashed, kind),
                )
                return affected == 1

        return await self._run(operation)

    async def consume_refresh_for_access_jti(self, jti: str) -> None:
        def operation(connection: pymysql.Connection) -> None:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE mcp_oauth_artifacts
                    SET consumed_at = UTC_TIMESTAMP()
                    WHERE kind = 'refresh' AND consumed_at IS NULL
                          AND JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.access_jti')) = %s
                    """,
                    (jti,),
                )

        await self._run(operation)

    async def revoke_access_jti(self, jti: str, expires_at: int) -> None:
        def operation(connection: pymysql.Connection) -> None:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO mcp_oauth_revocations (jti, expires_at)
                    VALUES (%s, %s)
                    ON DUPLICATE KEY UPDATE expires_at = VALUES(expires_at)
                    """,
                    (jti, _as_utc_datetime(expires_at)),
                )

        await self._run(operation)

    async def is_access_jti_revoked(self, jti: str) -> bool:
        def operation(connection: pymysql.Connection) -> bool:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT 1 FROM mcp_oauth_revocations
                    WHERE jti = %s AND expires_at > UTC_TIMESTAMP()
                    LIMIT 1
                    """,
                    (jti,),
                )
                return cursor.fetchone() is not None

        return await self._run(operation)

