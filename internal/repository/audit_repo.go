package repository

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/buadamlaz/sambaguard/internal/database"
	"github.com/buadamlaz/sambaguard/internal/model"
)

// AuditRepo handles persistence for audit log entries.
type AuditRepo struct {
	db *database.DB
}

func NewAuditRepo(db *database.DB) *AuditRepo {
	return &AuditRepo{db: db}
}

// Append adds a new audit log entry.
func (r *AuditRepo) Append(entry *model.AuditLog) error {
	_, err := r.db.Exec(`
		INSERT INTO audit_log
		  (id, timestamp, actor_id, actor_name, action, target_type, target_id,
		   target_name, details, ip_address, success, error_msg)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		entry.ID, entry.Timestamp.UTC(), entry.ActorID, entry.ActorName,
		string(entry.Action), entry.TargetType, entry.TargetID, entry.TargetName,
		entry.Details, entry.IPAddress, boolToInt(entry.Success), entry.ErrorMsg,
	)
	if err != nil {
		return fmt.Errorf("insert audit_log: %w", err)
	}
	return nil
}

// List returns audit log entries with optional filtering.
func (r *AuditRepo) List(f *model.AuditLogFilter) ([]*model.AuditLog, int64, error) {
	where := []string{"1=1"}
	args := []any{}

	if f.ActorID != "" {
		where = append(where, "actor_id = ?")
		args = append(args, f.ActorID)
	}
	if f.Action != "" {
		where = append(where, "action = ?")
		args = append(args, string(f.Action))
	}
	if f.TargetType != "" {
		where = append(where, "target_type = ?")
		args = append(args, f.TargetType)
	}
	if f.Since != nil {
		where = append(where, "timestamp >= ?")
		args = append(args, f.Since.UTC())
	}
	if f.Until != nil {
		where = append(where, "timestamp <= ?")
		args = append(args, f.Until.UTC())
	}
	if f.Search != "" {
		where = append(where, "(actor_name LIKE ? OR target_name LIKE ? OR details LIKE ?)")
		s := "%" + f.Search + "%"
		args = append(args, s, s, s)
	}

	whereSQL := strings.Join(where, " AND ")

	var total int64
	if err := r.db.QueryRow("SELECT COUNT(*) FROM audit_log WHERE "+whereSQL, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	limit, offset := listParams(f.Limit, f.Offset)
	queryArgs := append(args, limit, offset)

	rows, err := r.db.Query(`
		SELECT id, timestamp, actor_id, actor_name, action, target_type, target_id,
		       target_name, details, ip_address, success, error_msg
		FROM audit_log WHERE `+whereSQL+`
		ORDER BY timestamp DESC LIMIT ? OFFSET ?`,
		queryArgs...,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var entries []*model.AuditLog
	for rows.Next() {
		e := &model.AuditLog{}
		var success int
		err := rows.Scan(
			&e.ID, &e.Timestamp, &e.ActorID, &e.ActorName,
			&e.Action, &e.TargetType, &e.TargetID, &e.TargetName,
			&e.Details, &e.IPAddress, &success, &e.ErrorMsg,
		)
		if err != nil {
			return nil, 0, err
		}
		e.Success = success == 1
		entries = append(entries, e)
	}
	return entries, total, rows.Err()
}

// GetRecentByActor returns the N most recent entries for a given actor.
func (r *AuditRepo) GetRecentByActor(actorID string, n int) ([]*model.AuditLog, error) {
	rows, err := r.db.Query(`
		SELECT id, timestamp, actor_id, actor_name, action, target_type, target_id,
		       target_name, details, ip_address, success, error_msg
		FROM audit_log WHERE actor_id = ?
		ORDER BY timestamp DESC LIMIT ?`, actorID, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []*model.AuditLog
	for rows.Next() {
		e := &model.AuditLog{}
		var success int
		err := rows.Scan(
			&e.ID, &e.Timestamp, &e.ActorID, &e.ActorName,
			&e.Action, &e.TargetType, &e.TargetID, &e.TargetName,
			&e.Details, &e.IPAddress, &success, &e.ErrorMsg,
		)
		if err != nil {
			return nil, err
		}
		e.Success = success == 1
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// PruneOlderThan deletes audit entries older than the given duration in days.
func (r *AuditRepo) PruneOlderThan(days int) (int64, error) {
	res, err := r.db.Exec(`
		DELETE FROM audit_log WHERE timestamp < datetime('now', ? || ' days')`,
		fmt.Sprintf("-%d", days),
	)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// Stats returns summary counts for the dashboard.
func (r *AuditRepo) Stats() (map[string]int64, error) {
	stats := make(map[string]int64)

	queries := map[string]string{
		"total_samba_users":  `SELECT COUNT(*) FROM samba_users`,
		"enabled_users":      `SELECT COUNT(*) FROM samba_users WHERE status = 'enabled'`,
		"total_groups":       `SELECT COUNT(*) FROM samba_groups`,
		"total_shares":       `SELECT COUNT(*) FROM shares`,
		"enabled_shares":     `SELECT COUNT(*) FROM shares WHERE enabled = 1`,
		"audit_today":        `SELECT COUNT(*) FROM audit_log WHERE timestamp >= date('now')`,
		"panel_users":        `SELECT COUNT(*) FROM panel_users WHERE disabled = 0`,
	}

	for key, q := range queries {
		var n int64
		if err := r.db.QueryRow(q).Scan(&n); err != nil && err != sql.ErrNoRows {
			return nil, fmt.Errorf("stats query %s: %w", key, err)
		}
		stats[key] = n
	}
	return stats, nil
}
