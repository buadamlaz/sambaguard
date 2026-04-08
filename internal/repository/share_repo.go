package repository

import (
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"github.com/buadamlaz/sambaguard/internal/database"
	"github.com/buadamlaz/sambaguard/internal/model"
)

// ShareRepo handles persistence for Samba shares.
type ShareRepo struct {
	db *database.DB
}

func NewShareRepo(db *database.DB) *ShareRepo {
	return &ShareRepo{db: db}
}

func (r *ShareRepo) Create(s *model.Share) error {
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	_, err = tx.Exec(`
		INSERT INTO shares
		  (id, name, path, comment, enabled, browseable, guest_ok, read_only,
		   owner_group, create_mask, dir_mask, created_at, updated_at, created_by)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		s.ID, s.Name, s.Path, s.Comment,
		boolToInt(s.Enabled), boolToInt(s.Browseable),
		boolToInt(s.GuestOk), boolToInt(s.ReadOnly),
		s.OwnerGroup, s.CreateMask, s.DirMask,
		s.CreatedAt.UTC(), s.UpdatedAt.UTC(), s.CreatedBy,
	)
	if err != nil {
		return fmt.Errorf("insert share: %w", err)
	}

	if err := insertACL(tx, s.ID, s.ACL); err != nil {
		return err
	}

	return tx.Commit()
}

func (r *ShareRepo) GetByID(id string) (*model.Share, error) {
	row := r.db.QueryRow(`SELECT * FROM shares WHERE id = ?`, id)
	s, err := scanShare(row)
	if err != nil {
		return nil, err
	}
	s.ACL, err = r.getACL(s.ID)
	return s, err
}

func (r *ShareRepo) GetByName(name string) (*model.Share, error) {
	row := r.db.QueryRow(`SELECT * FROM shares WHERE name = ?`, name)
	s, err := scanShare(row)
	if err != nil {
		return nil, err
	}
	s.ACL, err = r.getACL(s.ID)
	return s, err
}

func (r *ShareRepo) List(search string, limit, offset int) ([]*model.Share, int64, error) {
	where := "1=1"
	args := []any{}
	if search != "" {
		where = "(name LIKE ? OR path LIKE ? OR comment LIKE ?)"
		s := "%" + search + "%"
		args = append(args, s, s, s)
	}

	var total int64
	if err := r.db.QueryRow("SELECT COUNT(*) FROM shares WHERE "+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	lim, off := listParams(limit, offset)
	queryArgs := append(args, lim, off)
	rows, err := r.db.Query(
		"SELECT * FROM shares WHERE "+where+" ORDER BY name ASC LIMIT ? OFFSET ?",
		queryArgs...,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var shares []*model.Share
	for rows.Next() {
		s, err := scanShareRow(rows)
		if err != nil {
			return nil, 0, err
		}
		acl, _ := r.getACL(s.ID)
		s.ACL = acl
		shares = append(shares, s)
	}
	return shares, total, rows.Err()
}

// ListAll returns all enabled shares (used for smb.conf generation).
func (r *ShareRepo) ListAll() ([]*model.Share, error) {
	rows, err := r.db.Query(`SELECT * FROM shares ORDER BY name ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var shares []*model.Share
	for rows.Next() {
		s, err := scanShareRow(rows)
		if err != nil {
			return nil, err
		}
		acl, _ := r.getACL(s.ID)
		s.ACL = acl
		shares = append(shares, s)
	}
	return shares, rows.Err()
}

func (r *ShareRepo) Update(s *model.Share) error {
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	_, err = tx.Exec(`
		UPDATE shares SET
		  path = ?, comment = ?, enabled = ?, browseable = ?,
		  guest_ok = ?, read_only = ?, owner_group = ?,
		  create_mask = ?, dir_mask = ?, updated_at = ?
		WHERE id = ?`,
		s.Path, s.Comment,
		boolToInt(s.Enabled), boolToInt(s.Browseable),
		boolToInt(s.GuestOk), boolToInt(s.ReadOnly),
		s.OwnerGroup, s.CreateMask, s.DirMask,
		s.UpdatedAt.UTC(), s.ID,
	)
	if err != nil {
		return fmt.Errorf("update share: %w", err)
	}

	// Replace ACL entries
	if _, err := tx.Exec(`DELETE FROM share_acl WHERE share_id = ?`, s.ID); err != nil {
		return fmt.Errorf("delete old ACL: %w", err)
	}
	if err := insertACL(tx, s.ID, s.ACL); err != nil {
		return err
	}

	return tx.Commit()
}

func (r *ShareRepo) Delete(id string) error {
	_, err := r.db.Exec(`DELETE FROM shares WHERE id = ?`, id)
	return err
}

// ─── ACL helpers ──────────────────────────────────────────────────────────────

func insertACL(tx *sql.Tx, shareID string, acl []model.ShareACLEntry) error {
	for _, entry := range acl {
		_, err := tx.Exec(`
			INSERT INTO share_acl (id, share_id, principal, permission) VALUES (?, ?, ?, ?)`,
			uuid.New().String(), shareID, entry.Principal, string(entry.Permission),
		)
		if err != nil {
			return fmt.Errorf("insert ACL entry: %w", err)
		}
	}
	return nil
}

func (r *ShareRepo) getACL(shareID string) ([]model.ShareACLEntry, error) {
	rows, err := r.db.Query(`
		SELECT principal, permission FROM share_acl WHERE share_id = ? ORDER BY principal`,
		shareID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var acl []model.ShareACLEntry
	for rows.Next() {
		var e model.ShareACLEntry
		if err := rows.Scan(&e.Principal, &e.Permission); err != nil {
			return nil, err
		}
		acl = append(acl, e)
	}
	return acl, rows.Err()
}

// ─── scanners ─────────────────────────────────────────────────────────────────

func scanShare(s scanner) (*model.Share, error) {
	sh := &model.Share{}
	var enabled, browseable, guestOk, readOnly int
	err := s.Scan(
		&sh.ID, &sh.Name, &sh.Path, &sh.Comment,
		&enabled, &browseable, &guestOk, &readOnly,
		&sh.OwnerGroup, &sh.CreateMask, &sh.DirMask,
		&sh.CreatedAt, &sh.UpdatedAt, &sh.CreatedBy,
	)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	sh.Enabled = enabled == 1
	sh.Browseable = browseable == 1
	sh.GuestOk = guestOk == 1
	sh.ReadOnly = readOnly == 1
	return sh, nil
}

func scanShareRow(rows *sql.Rows) (*model.Share, error) {
	sh := &model.Share{}
	var enabled, browseable, guestOk, readOnly int
	err := rows.Scan(
		&sh.ID, &sh.Name, &sh.Path, &sh.Comment,
		&enabled, &browseable, &guestOk, &readOnly,
		&sh.OwnerGroup, &sh.CreateMask, &sh.DirMask,
		&sh.CreatedAt, &sh.UpdatedAt, &sh.CreatedBy,
	)
	if err != nil {
		return nil, err
	}
	sh.Enabled = enabled == 1
	sh.Browseable = browseable == 1
	sh.GuestOk = guestOk == 1
	sh.ReadOnly = readOnly == 1
	return sh, nil
}

