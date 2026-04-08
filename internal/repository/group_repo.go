package repository

import (
	"database/sql"
	"time"

	"github.com/buadamlaz/sambaguard/internal/database"
	"github.com/buadamlaz/sambaguard/internal/model"
)

// SambaGroupRepo handles persistence for Samba group records.
type SambaGroupRepo struct {
	db *database.DB
}

func NewSambaGroupRepo(db *database.DB) *SambaGroupRepo {
	return &SambaGroupRepo{db: db}
}

func (r *SambaGroupRepo) Create(g *model.SambaGroup) error {
	_, err := r.db.Exec(`
		INSERT INTO samba_groups (id, name, description, created_at, updated_at, created_by)
		VALUES (?, ?, ?, ?, ?, ?)`,
		g.ID, g.Name, g.Description, g.CreatedAt.UTC(), g.UpdatedAt.UTC(), g.CreatedBy,
	)
	return err
}

func (r *SambaGroupRepo) GetByID(id string) (*model.SambaGroup, error) {
	row := r.db.QueryRow(`SELECT * FROM samba_groups WHERE id = ?`, id)
	g, err := scanGroup(row)
	if err != nil {
		return nil, err
	}
	g.Members, err = r.GetMembers(id)
	return g, err
}

func (r *SambaGroupRepo) GetByName(name string) (*model.SambaGroup, error) {
	row := r.db.QueryRow(`SELECT * FROM samba_groups WHERE name = ?`, name)
	g, err := scanGroup(row)
	if err != nil {
		return nil, err
	}
	g.Members, err = r.GetMembers(g.ID)
	return g, err
}

func (r *SambaGroupRepo) List(search string, limit, offset int) ([]*model.SambaGroup, int64, error) {
	where := "1=1"
	args := []any{}

	if search != "" {
		where = "(name LIKE ? OR description LIKE ?)"
		s := "%" + search + "%"
		args = append(args, s, s)
	}

	var total int64
	if err := r.db.QueryRow("SELECT COUNT(*) FROM samba_groups WHERE "+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	lim, off := listParams(limit, offset)
	queryArgs := append(args, lim, off)
	rows, err := r.db.Query(
		"SELECT * FROM samba_groups WHERE "+where+" ORDER BY name ASC LIMIT ? OFFSET ?",
		queryArgs...,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var groups []*model.SambaGroup
	for rows.Next() {
		g, err := scanGroupRow(rows)
		if err != nil {
			return nil, 0, err
		}
		members, _ := r.GetMembers(g.ID)
		g.Members = members
		groups = append(groups, g)
	}
	return groups, total, rows.Err()
}

func (r *SambaGroupRepo) Update(g *model.SambaGroup) error {
	g.UpdatedAt = time.Now().UTC()
	_, err := r.db.Exec(`
		UPDATE samba_groups SET description = ?, updated_at = ? WHERE id = ?`,
		g.Description, g.UpdatedAt, g.ID,
	)
	return err
}

func (r *SambaGroupRepo) Delete(id string) error {
	_, err := r.db.Exec(`DELETE FROM samba_groups WHERE id = ?`, id)
	return err
}

func (r *SambaGroupRepo) AddMember(groupID, userID, addedBy string) error {
	_, err := r.db.Exec(`
		INSERT OR IGNORE INTO group_members (group_id, user_id, added_by) VALUES (?, ?, ?)`,
		groupID, userID, addedBy,
	)
	return err
}

func (r *SambaGroupRepo) RemoveMember(groupID, userID string) error {
	_, err := r.db.Exec(`DELETE FROM group_members WHERE group_id = ? AND user_id = ?`, groupID, userID)
	return err
}

func (r *SambaGroupRepo) GetMembers(groupID string) ([]string, error) {
	rows, err := r.db.Query(`
		SELECT u.username FROM samba_users u
		JOIN group_members gm ON u.id = gm.user_id
		WHERE gm.group_id = ?
		ORDER BY u.username`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var members []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		members = append(members, name)
	}
	return members, rows.Err()
}

// IsMember checks if a user is in a group.
func (r *SambaGroupRepo) IsMember(groupID, userID string) (bool, error) {
	var count int
	err := r.db.QueryRow(`
		SELECT COUNT(*) FROM group_members WHERE group_id = ? AND user_id = ?`,
		groupID, userID,
	).Scan(&count)
	return count > 0, err
}

// GetGroupNames returns names of all groups (used for smb.conf generation).
func (r *SambaGroupRepo) GetGroupNames() ([]string, error) {
	rows, err := r.db.Query(`SELECT name FROM samba_groups ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		names = append(names, n)
	}
	return names, rows.Err()
}

// ─── scanners ─────────────────────────────────────────────────────────────────

func scanGroup(s scanner) (*model.SambaGroup, error) {
	g := &model.SambaGroup{}
	err := s.Scan(&g.ID, &g.Name, &g.Description, &g.CreatedAt, &g.UpdatedAt, &g.CreatedBy)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	return g, err
}

func scanGroupRow(rows *sql.Rows) (*model.SambaGroup, error) {
	g := &model.SambaGroup{}
	err := rows.Scan(&g.ID, &g.Name, &g.Description, &g.CreatedAt, &g.UpdatedAt, &g.CreatedBy)
	return g, err
}

// GetGroupsForUser returns group names that a samba user belongs to (by username).
func (r *SambaGroupRepo) GetGroupNamesForUser(userID string) ([]string, error) {
	rows, err := r.db.Query(`
		SELECT g.name FROM samba_groups g
		JOIN group_members gm ON g.id = gm.group_id
		WHERE gm.user_id = ?
		ORDER BY g.name`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		names = append(names, n)
	}
	return names, rows.Err()
}

// ─── Config-state repo (lives here for convenience) ───────────────────────────

// ConfigStateRepo manages the single-row config_state table.
type ConfigStateRepo struct {
	db *database.DB
}

func NewConfigStateRepo(db *database.DB) *ConfigStateRepo {
	return &ConfigStateRepo{db: db}
}

func (r *ConfigStateRepo) Get() (*model.ConfigStatus, error) {
	var (
		pending             int
		lastApplied, lastMod, pendingSince sql.NullString
	)
	err := r.db.QueryRow(`
		SELECT has_pending_changes, last_applied_at, last_modified_at, pending_since
		FROM config_state WHERE id = 1`,
	).Scan(&pending, &lastApplied, &lastMod, &pendingSince)
	if err != nil {
		return nil, err
	}

	s := &model.ConfigStatus{HasPendingChanges: pending == 1}

	parseNullTime := func(ns sql.NullString) *time.Time {
		if !ns.Valid {
			return nil
		}
		t, err := time.Parse(time.RFC3339Nano, ns.String)
		if err != nil {
			return nil
		}
		return &t
	}

	s.LastAppliedAt = parseNullTime(lastApplied)
	s.LastModifiedAt = parseNullTime(lastMod)
	s.PendingSince = parseNullTime(pendingSince)
	return s, nil
}

func (r *ConfigStateRepo) MarkPending() error {
	now := time.Now().UTC()
	_, err := r.db.Exec(`
		UPDATE config_state SET
		  has_pending_changes = 1,
		  last_modified_at = ?,
		  pending_since = COALESCE(pending_since, ?)
		WHERE id = 1`, now, now)
	return err
}

func (r *ConfigStateRepo) MarkApplied() error {
	now := time.Now().UTC()
	_, err := r.db.Exec(`
		UPDATE config_state SET
		  has_pending_changes = 0,
		  last_applied_at = ?,
		  pending_since = NULL
		WHERE id = 1`, now)
	return err
}

// ─── Refresh Token Repo ───────────────────────────────────────────────────────

// RefreshTokenRepo manages server-side refresh token storage.
type RefreshTokenRepo struct {
	db *database.DB
}

func NewRefreshTokenRepo(db *database.DB) *RefreshTokenRepo {
	return &RefreshTokenRepo{db: db}
}

func (r *RefreshTokenRepo) Store(id, userID, tokenHash string, expiresAt time.Time, ip, ua string) error {
	_, err := r.db.Exec(`
		INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at, ip_address, user_agent)
		VALUES (?, ?, ?, ?, ?, ?)`,
		id, userID, tokenHash, expiresAt.UTC(), ip, ua,
	)
	return err
}

func (r *RefreshTokenRepo) Verify(tokenHash string) (userID string, valid bool, err error) {
	var expiresAt time.Time
	var revoked int
	err = r.db.QueryRow(`
		SELECT user_id, expires_at, revoked FROM refresh_tokens WHERE token_hash = ?`,
		tokenHash,
	).Scan(&userID, &expiresAt, &revoked)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if revoked == 1 || time.Now().After(expiresAt) {
		return "", false, nil
	}
	return userID, true, nil
}

func (r *RefreshTokenRepo) Revoke(tokenHash string) error {
	_, err := r.db.Exec(`UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = ?`, tokenHash)
	return err
}

func (r *RefreshTokenRepo) RevokeAllForUser(userID string) error {
	_, err := r.db.Exec(`UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?`, userID)
	return err
}

func (r *RefreshTokenRepo) Cleanup() error {
	_, err := r.db.Exec(`DELETE FROM refresh_tokens WHERE expires_at < ? OR revoked = 1`,
		time.Now().UTC())
	return err
}

// ─── Config Backup / Version Repo ─────────────────────────────────────────────

type ConfigBackupRepo struct {
	db *database.DB
}

func NewConfigBackupRepo(db *database.DB) *ConfigBackupRepo {
	return &ConfigBackupRepo{db: db}
}

func (r *ConfigBackupRepo) Create(b *model.ConfigBackup) error {
	_, err := r.db.Exec(`
		INSERT INTO config_backups (id, filename, created_at, created_by, size_bytes, note)
		VALUES (?, ?, ?, ?, ?, ?)`,
		b.ID, b.Filename, b.CreatedAt.UTC(), b.CreatedBy, b.Size, b.Note,
	)
	return err
}

func (r *ConfigBackupRepo) List(limit, offset int) ([]*model.ConfigBackup, int64, error) {
	var total int64
	if err := r.db.QueryRow(`SELECT COUNT(*) FROM config_backups`).Scan(&total); err != nil {
		return nil, 0, err
	}

	lim, off := listParams(limit, offset)
	rows, err := r.db.Query(`
		SELECT id, filename, created_at, created_by, size_bytes, note
		FROM config_backups ORDER BY created_at DESC LIMIT ? OFFSET ?`, lim, off)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var backups []*model.ConfigBackup
	for rows.Next() {
		b := &model.ConfigBackup{}
		if err := rows.Scan(&b.ID, &b.Filename, &b.CreatedAt, &b.CreatedBy, &b.Size, &b.Note); err != nil {
			return nil, 0, err
		}
		backups = append(backups, b)
	}
	return backups, total, rows.Err()
}

type ConfigVersionRepo struct {
	db *database.DB
}

func NewConfigVersionRepo(db *database.DB) *ConfigVersionRepo {
	return &ConfigVersionRepo{db: db}
}

func (r *ConfigVersionRepo) Create(v *model.ConfigVersion) error {
	_, err := r.db.Exec(`
		INSERT INTO config_versions (id, content, created_at, created_by, note)
		VALUES (?, ?, ?, ?, ?)`,
		v.ID, v.Content, v.CreatedAt.UTC(), v.CreatedBy, v.Note,
	)
	return err
}

func (r *ConfigVersionRepo) List(limit, offset int) ([]*model.ConfigVersion, int64, error) {
	var total int64
	if err := r.db.QueryRow(`SELECT COUNT(*) FROM config_versions`).Scan(&total); err != nil {
		return nil, 0, err
	}

	lim, off := listParams(limit, offset)
	rows, err := r.db.Query(`
		SELECT id, created_at, created_by, note FROM config_versions
		ORDER BY created_at DESC LIMIT ? OFFSET ?`, lim, off)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var versions []*model.ConfigVersion
	for rows.Next() {
		v := &model.ConfigVersion{}
		if err := rows.Scan(&v.ID, &v.CreatedAt, &v.CreatedBy, &v.Note); err != nil {
			return nil, 0, err
		}
		versions = append(versions, v)
	}
	return versions, total, rows.Err()
}

func (r *ConfigVersionRepo) GetContent(id string) (string, error) {
	var content string
	err := r.db.QueryRow(`SELECT content FROM config_versions WHERE id = ?`, id).Scan(&content)
	if err == sql.ErrNoRows {
		return "", ErrNotFound
	}
	return content, err
}

// Prune keeps only the N most recent versions.
func (r *ConfigVersionRepo) Prune(keepN int) error {
	_, err := r.db.Exec(`
		DELETE FROM config_versions WHERE id NOT IN (
		  SELECT id FROM config_versions ORDER BY created_at DESC LIMIT ?
		)`, keepN)
	return err
}

