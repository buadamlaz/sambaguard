package repository

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/buadamlaz/sambaguard/internal/database"
	"github.com/buadamlaz/sambaguard/internal/model"
)

// PanelUserRepo handles persistence for panel admin accounts.
type PanelUserRepo struct {
	db *database.DB
}

func NewPanelUserRepo(db *database.DB) *PanelUserRepo {
	return &PanelUserRepo{db: db}
}

func (r *PanelUserRepo) Create(u *model.PanelUser) error {
	_, err := r.db.Exec(`
		INSERT INTO panel_users
		  (id, username, password_hash, role, email, must_change_pass, disabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		u.ID, u.Username, u.PasswordHash, string(u.Role),
		u.Email, boolToInt(u.MustChangePass), boolToInt(u.Disabled),
		u.CreatedAt.UTC(), u.UpdatedAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf("insert panel_user: %w", err)
	}
	return nil
}

func (r *PanelUserRepo) GetByID(id string) (*model.PanelUser, error) {
	row := r.db.QueryRow(`SELECT * FROM panel_users WHERE id = ?`, id)
	return scanPanelUser(row)
}

func (r *PanelUserRepo) GetByUsername(username string) (*model.PanelUser, error) {
	row := r.db.QueryRow(`SELECT * FROM panel_users WHERE username = ?`, username)
	return scanPanelUser(row)
}

func (r *PanelUserRepo) Count() (int64, error) {
	var n int64
	err := r.db.QueryRow(`SELECT COUNT(*) FROM panel_users`).Scan(&n)
	return n, err
}

func (r *PanelUserRepo) List(f *model.PanelUserFilter) ([]*model.PanelUser, int64, error) {
	where := []string{"1=1"}
	args := []any{}

	if f.Role != "" {
		where = append(where, "role = ?")
		args = append(args, string(f.Role))
	}
	if f.Search != "" {
		where = append(where, "(username LIKE ? OR email LIKE ?)")
		s := "%" + f.Search + "%"
		args = append(args, s, s)
	}

	whereSQL := strings.Join(where, " AND ")

	var total int64
	if err := r.db.QueryRow("SELECT COUNT(*) FROM panel_users WHERE "+whereSQL, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	limit, offset := listParams(f.Limit, f.Offset)
	queryArgs := append(args, limit, offset)
	rows, err := r.db.Query(
		"SELECT * FROM panel_users WHERE "+whereSQL+" ORDER BY username ASC LIMIT ? OFFSET ?",
		queryArgs...,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var users []*model.PanelUser
	for rows.Next() {
		u, err := scanPanelUserRow(rows)
		if err != nil {
			return nil, 0, err
		}
		users = append(users, u)
	}
	return users, total, rows.Err()
}

func (r *PanelUserRepo) Update(u *model.PanelUser) error {
	u.UpdatedAt = time.Now().UTC()
	_, err := r.db.Exec(`
		UPDATE panel_users SET
		  username = ?, password_hash = ?, role = ?, email = ?,
		  must_change_pass = ?, disabled = ?, last_login_at = ?,
		  failed_login_count = ?, locked_until = ?, updated_at = ?
		WHERE id = ?`,
		u.Username, u.PasswordHash, string(u.Role), u.Email,
		boolToInt(u.MustChangePass), boolToInt(u.Disabled),
		nullableTime(u.LastLoginAt), u.FailedLoginCount,
		nullableTime(u.LockedUntil), u.UpdatedAt,
		u.ID,
	)
	return err
}

func (r *PanelUserRepo) Delete(id string) error {
	_, err := r.db.Exec(`DELETE FROM panel_users WHERE id = ?`, id)
	return err
}

// ─── Samba User Repo ──────────────────────────────────────────────────────────

// SambaUserRepo handles persistence for Samba user records.
type SambaUserRepo struct {
	db *database.DB
}

func NewSambaUserRepo(db *database.DB) *SambaUserRepo {
	return &SambaUserRepo{db: db}
}

func (r *SambaUserRepo) Create(u *model.SambaUser) error {
	_, err := r.db.Exec(`
		INSERT INTO samba_users (id, username, display_name, status, comment, created_at, updated_at, created_by)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		u.ID, u.Username, u.DisplayName, string(u.Status),
		u.Comment, u.CreatedAt.UTC(), u.UpdatedAt.UTC(), u.CreatedBy,
	)
	return err
}

func (r *SambaUserRepo) GetByID(id string) (*model.SambaUser, error) {
	row := r.db.QueryRow(`SELECT * FROM samba_users WHERE id = ?`, id)
	u, err := scanSambaUser(row)
	if err != nil {
		return nil, err
	}
	u.Groups, err = r.GetUserGroups(u.ID)
	return u, err
}

func (r *SambaUserRepo) GetByUsername(username string) (*model.SambaUser, error) {
	row := r.db.QueryRow(`SELECT * FROM samba_users WHERE username = ?`, username)
	u, err := scanSambaUser(row)
	if err != nil {
		return nil, err
	}
	u.Groups, err = r.GetUserGroups(u.ID)
	return u, err
}

func (r *SambaUserRepo) List(f *model.SambaUserFilter) ([]*model.SambaUser, int64, error) {
	where := []string{"1=1"}
	args := []any{}

	if f.Status != "" {
		where = append(where, "status = ?")
		args = append(args, string(f.Status))
	}
	if f.Search != "" {
		where = append(where, "(username LIKE ? OR display_name LIKE ? OR comment LIKE ?)")
		s := "%" + f.Search + "%"
		args = append(args, s, s, s)
	}

	whereSQL := strings.Join(where, " AND ")

	var total int64
	if err := r.db.QueryRow("SELECT COUNT(*) FROM samba_users WHERE "+whereSQL, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	limit, offset := listParams(f.Limit, f.Offset)
	queryArgs := append(args, limit, offset)
	rows, err := r.db.Query(
		"SELECT * FROM samba_users WHERE "+whereSQL+" ORDER BY username ASC LIMIT ? OFFSET ?",
		queryArgs...,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var users []*model.SambaUser
	for rows.Next() {
		u, err := scanSambaUserRow(rows)
		if err != nil {
			return nil, 0, err
		}
		groups, _ := r.GetUserGroups(u.ID)
		u.Groups = groups
		users = append(users, u)
	}
	return users, total, rows.Err()
}

func (r *SambaUserRepo) Update(u *model.SambaUser) error {
	u.UpdatedAt = time.Now().UTC()
	_, err := r.db.Exec(`
		UPDATE samba_users SET display_name = ?, status = ?, comment = ?, updated_at = ?
		WHERE id = ?`,
		u.DisplayName, string(u.Status), u.Comment, u.UpdatedAt, u.ID,
	)
	return err
}

func (r *SambaUserRepo) Delete(id string) error {
	_, err := r.db.Exec(`DELETE FROM samba_users WHERE id = ?`, id)
	return err
}

func (r *SambaUserRepo) GetUserGroups(userID string) ([]string, error) {
	rows, err := r.db.Query(`
		SELECT g.name FROM samba_groups g
		JOIN group_members gm ON g.id = gm.group_id
		WHERE gm.user_id = ?`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var groups []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		groups = append(groups, name)
	}
	return groups, rows.Err()
}

// ─── scanners ─────────────────────────────────────────────────────────────────

type scanner interface {
	Scan(dest ...any) error
}

func scanPanelUser(s scanner) (*model.PanelUser, error) {
	u := &model.PanelUser{}
	var mustChange, disabled int
	var lastLogin, lockedUntil sql.NullString
	err := s.Scan(
		&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.Email,
		&mustChange, &disabled, &lastLogin, &u.FailedLoginCount,
		&lockedUntil, &u.CreatedAt, &u.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	u.MustChangePass = mustChange == 1
	u.Disabled = disabled == 1
	if lastLogin.Valid {
		t, _ := time.Parse(time.RFC3339Nano, lastLogin.String)
		u.LastLoginAt = &t
	}
	if lockedUntil.Valid {
		t, _ := time.Parse(time.RFC3339Nano, lockedUntil.String)
		u.LockedUntil = &t
	}
	return u, nil
}

// scanPanelUserRow scans from sql.Rows (same columns, different receiver type).
func scanPanelUserRow(rows *sql.Rows) (*model.PanelUser, error) {
	u := &model.PanelUser{}
	var mustChange, disabled int
	var lastLogin, lockedUntil sql.NullString
	err := rows.Scan(
		&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.Email,
		&mustChange, &disabled, &lastLogin, &u.FailedLoginCount,
		&lockedUntil, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	u.MustChangePass = mustChange == 1
	u.Disabled = disabled == 1
	if lastLogin.Valid {
		t, _ := time.Parse(time.RFC3339Nano, lastLogin.String)
		u.LastLoginAt = &t
	}
	if lockedUntil.Valid {
		t, _ := time.Parse(time.RFC3339Nano, lockedUntil.String)
		u.LockedUntil = &t
	}
	return u, nil
}

func scanSambaUser(s scanner) (*model.SambaUser, error) {
	u := &model.SambaUser{}
	err := s.Scan(
		&u.ID, &u.Username, &u.DisplayName, &u.Status,
		&u.Comment, &u.CreatedAt, &u.UpdatedAt, &u.CreatedBy,
	)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	return u, err
}

func scanSambaUserRow(rows *sql.Rows) (*model.SambaUser, error) {
	u := &model.SambaUser{}
	err := rows.Scan(
		&u.ID, &u.Username, &u.DisplayName, &u.Status,
		&u.Comment, &u.CreatedAt, &u.UpdatedAt, &u.CreatedBy,
	)
	return u, err
}

// ─── helpers ──────────────────────────────────────────────────────────────────

// ErrNotFound is returned when a record doesn't exist.
var ErrNotFound = fmt.Errorf("record not found")

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func nullableTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UTC()
}

func listParams(limit, offset int) (int, int) {
	if limit <= 0 || limit > 1000 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}
