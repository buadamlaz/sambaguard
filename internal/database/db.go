// Package database handles SQLite setup and schema migrations.
// We use modernc.org/sqlite (pure Go, no CGO required) for portability.
package database

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

// DB wraps sql.DB with the driver name for reference.
type DB struct {
	*sql.DB
}

// New opens (or creates) the SQLite database at the given path.
// The directory is created if it does not exist.
func New(path string) (*DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return nil, fmt.Errorf("create db directory: %w", err)
	}

	// SQLite pragmas for security and performance
	dsn := fmt.Sprintf("%s?_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)&_pragma=busy_timeout(5000)", path)

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	// Limit connections — SQLite performs best with a small pool
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping database: %w", err)
	}

	return &DB{db}, nil
}

// Migrate runs all embedded SQL migrations in order.
// It is idempotent: migrations that have already run are skipped.
func Migrate(db *DB) error {
	// Create migrations table if it doesn't exist
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version     INTEGER PRIMARY KEY,
		applied_at  DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
	)`)
	if err != nil {
		return fmt.Errorf("create migrations table: %w", err)
	}

	for _, m := range migrations {
		var count int
		err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, m.version).Scan(&count)
		if err != nil {
			return fmt.Errorf("check migration %d: %w", m.version, err)
		}
		if count > 0 {
			continue // already applied
		}

		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("begin migration %d: %w", m.version, err)
		}

		if _, err := tx.Exec(m.sql); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("run migration %d: %w", m.version, err)
		}

		if _, err := tx.Exec(`INSERT INTO schema_migrations (version) VALUES (?)`, m.version); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("record migration %d: %w", m.version, err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %d: %w", m.version, err)
		}
	}

	return nil
}

type migration struct {
	version int
	sql     string
}

var migrations = []migration{
	{
		version: 1,
		sql: `
-- Panel users (admins / operators / viewers)
CREATE TABLE IF NOT EXISTS panel_users (
    id                  TEXT PRIMARY KEY,
    username            TEXT NOT NULL UNIQUE,
    password_hash       TEXT NOT NULL,
    role                TEXT NOT NULL CHECK(role IN ('admin','operator','viewer')),
    email               TEXT NOT NULL DEFAULT '',
    must_change_pass    INTEGER NOT NULL DEFAULT 1,
    disabled            INTEGER NOT NULL DEFAULT 0,
    last_login_at       DATETIME,
    failed_login_count  INTEGER NOT NULL DEFAULT 0,
    locked_until        DATETIME,
    created_at          DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at          DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- Samba users (OS-level, managed by the panel)
CREATE TABLE IF NOT EXISTS samba_users (
    id           TEXT PRIMARY KEY,
    username     TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL DEFAULT '',
    status       TEXT NOT NULL DEFAULT 'enabled' CHECK(status IN ('enabled','disabled')),
    comment      TEXT NOT NULL DEFAULT '',
    created_at   DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at   DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    created_by   TEXT NOT NULL REFERENCES panel_users(id)
);

-- Samba groups (Linux groups)
CREATE TABLE IF NOT EXISTS samba_groups (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    created_at  DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at  DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    created_by  TEXT NOT NULL REFERENCES panel_users(id)
);

-- Group memberships (many-to-many)
CREATE TABLE IF NOT EXISTS group_members (
    group_id   TEXT NOT NULL REFERENCES samba_groups(id) ON DELETE CASCADE,
    user_id    TEXT NOT NULL REFERENCES samba_users(id) ON DELETE CASCADE,
    added_at   DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    added_by   TEXT NOT NULL REFERENCES panel_users(id),
    PRIMARY KEY (group_id, user_id)
);

-- Shares
CREATE TABLE IF NOT EXISTS shares (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    path        TEXT NOT NULL,
    comment     TEXT NOT NULL DEFAULT '',
    enabled     INTEGER NOT NULL DEFAULT 1,
    browseable  INTEGER NOT NULL DEFAULT 1,
    guest_ok    INTEGER NOT NULL DEFAULT 0,
    read_only   INTEGER NOT NULL DEFAULT 0,
    owner_group TEXT NOT NULL DEFAULT '',
    create_mask TEXT NOT NULL DEFAULT '0664',
    dir_mask    TEXT NOT NULL DEFAULT '0775',
    created_at  DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at  DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    created_by  TEXT NOT NULL REFERENCES panel_users(id)
);

-- Share ACL entries
CREATE TABLE IF NOT EXISTS share_acl (
    id         TEXT PRIMARY KEY,
    share_id   TEXT NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
    principal  TEXT NOT NULL,   -- username or @groupname
    permission TEXT NOT NULL CHECK(permission IN ('read_only','read_write')),
    UNIQUE(share_id, principal)
);

-- Config state (single-row table)
CREATE TABLE IF NOT EXISTS config_state (
    id                  INTEGER PRIMARY KEY CHECK(id = 1),
    has_pending_changes INTEGER NOT NULL DEFAULT 0,
    last_applied_at     DATETIME,
    last_modified_at    DATETIME,
    pending_since       DATETIME
);
INSERT OR IGNORE INTO config_state (id) VALUES (1);

-- Config backups
CREATE TABLE IF NOT EXISTS config_backups (
    id         TEXT PRIMARY KEY,
    filename   TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    created_by TEXT NOT NULL REFERENCES panel_users(id),
    size_bytes INTEGER NOT NULL DEFAULT 0,
    note       TEXT NOT NULL DEFAULT ''
);

-- Config versions (history)
CREATE TABLE IF NOT EXISTS config_versions (
    id         TEXT PRIMARY KEY,
    content    TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    created_by TEXT NOT NULL REFERENCES panel_users(id),
    note       TEXT NOT NULL DEFAULT ''
);

-- Audit log
CREATE TABLE IF NOT EXISTS audit_log (
    id          TEXT PRIMARY KEY,
    timestamp   DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    actor_id    TEXT NOT NULL,
    actor_name  TEXT NOT NULL,
    action      TEXT NOT NULL,
    target_type TEXT NOT NULL DEFAULT '',
    target_id   TEXT NOT NULL DEFAULT '',
    target_name TEXT NOT NULL DEFAULT '',
    details     TEXT NOT NULL DEFAULT '{}',
    ip_address  TEXT NOT NULL DEFAULT '',
    success     INTEGER NOT NULL DEFAULT 1,
    error_msg   TEXT NOT NULL DEFAULT ''
);

-- Refresh tokens (stored server-side for revocation)
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES panel_users(id) ON DELETE CASCADE,
    token_hash  TEXT NOT NULL UNIQUE,  -- SHA-256 hash of the actual token
    issued_at   DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    expires_at  DATETIME NOT NULL,
    revoked     INTEGER NOT NULL DEFAULT 0,
    ip_address  TEXT NOT NULL DEFAULT '',
    user_agent  TEXT NOT NULL DEFAULT ''
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_audit_timestamp   ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_actor       ON audit_log(actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_action      ON audit_log(action);
CREATE INDEX IF NOT EXISTS idx_refresh_user      ON refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_hash      ON refresh_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_share_acl_share   ON share_acl(share_id);
CREATE INDEX IF NOT EXISTS idx_group_members_grp ON group_members(group_id);
CREATE INDEX IF NOT EXISTS idx_group_members_usr ON group_members(user_id);
`,
	},
}
