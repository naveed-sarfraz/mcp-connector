-- MCP protocol state only. Existing application users remain in community-api's users table.
CREATE TABLE IF NOT EXISTS mcp_oauth_clients (
    client_id VARCHAR(128) NOT NULL PRIMARY KEY,
    client_info LONGTEXT NOT NULL,
    encrypted_secret LONGTEXT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS mcp_oauth_revocations (
    jti VARCHAR(128) NOT NULL PRIMARY KEY,
    expires_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_mcp_revocation_expiry (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
