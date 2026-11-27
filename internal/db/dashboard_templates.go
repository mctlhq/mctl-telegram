package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// ErrDashboardTemplateNotFound is returned when the account has no custom
// template with that id.
var ErrDashboardTemplateNotFound = errors.New("dashboard template not found")

// ErrDashboardTemplateQuota is returned when the account already holds the
// maximum number of custom templates and this save would add another.
var ErrDashboardTemplateQuota = errors.New("too many dashboard templates")

// DashboardTemplate is one custom template stored for an account.
type DashboardTemplate struct {
	ID        string
	Title     string
	Body      string
	UpdatedAt time.Time
}

// ListDashboardTemplates returns the account's custom templates, oldest id
// first. Built-ins are not rows.
func (s *Store) ListDashboardTemplates(ctx context.Context, userID int64) ([]DashboardTemplate, error) {
	rows, err := s.DB.QueryContext(ctx,
		`SELECT template_id, title, body, updated_at FROM dashboard_templates WHERE user_id = $1 ORDER BY template_id`,
		userID)
	if err != nil {
		return nil, fmt.Errorf("list dashboard templates: %w", err)
	}
	defer rows.Close()
	var out []DashboardTemplate
	for rows.Next() {
		row, err := scanDashboardTemplate(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list dashboard templates: %w", err)
	}
	return out, nil
}

// GetDashboardTemplate returns one custom template. A missing row is
// ErrDashboardTemplateNotFound.
func (s *Store) GetDashboardTemplate(ctx context.Context, userID int64, id string) (DashboardTemplate, error) {
	row := s.DB.QueryRowContext(ctx,
		`SELECT template_id, title, body, updated_at FROM dashboard_templates WHERE user_id = $1 AND template_id = $2`,
		userID, id)
	tpl, err := scanDashboardTemplate(row)
	if errors.Is(err, sql.ErrNoRows) {
		return DashboardTemplate{}, ErrDashboardTemplateNotFound
	}
	if err != nil {
		return DashboardTemplate{}, fmt.Errorf("get dashboard template: %w", err)
	}
	return tpl, nil
}

// SaveDashboardTemplate inserts or replaces one custom template. maxN is the
// account's quota. Replacing an existing id does not consume a new slot.
func (s *Store) SaveDashboardTemplate(ctx context.Context, userID int64, id, title, body string, maxN int) error {
	if maxN < 1 {
		return ErrDashboardTemplateQuota
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("save dashboard template: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var others int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM dashboard_templates WHERE user_id = $1 AND template_id <> $2`,
		userID, id).Scan(&others); err != nil {
		return fmt.Errorf("save dashboard template: %w", err)
	}
	if others >= maxN {
		return ErrDashboardTemplateQuota
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO dashboard_templates (user_id, template_id, title, body, updated_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (user_id, template_id) DO UPDATE SET
			title = excluded.title,
			body = excluded.body,
			updated_at = excluded.updated_at`,
		userID, id, title, body, now); err != nil {
		return fmt.Errorf("save dashboard template: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("save dashboard template: %w", err)
	}
	return nil
}

// DeleteDashboardTemplate removes one custom template.
func (s *Store) DeleteDashboardTemplate(ctx context.Context, userID int64, id string) error {
	res, err := s.DB.ExecContext(ctx,
		`DELETE FROM dashboard_templates WHERE user_id = $1 AND template_id = $2`,
		userID, id)
	if err != nil {
		return fmt.Errorf("delete dashboard template: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete dashboard template: %w", err)
	}
	if n == 0 {
		return ErrDashboardTemplateNotFound
	}
	return nil
}

type dashboardScanner interface {
	Scan(dest ...any) error
}

func scanDashboardTemplate(sc dashboardScanner) (DashboardTemplate, error) {
	var tpl DashboardTemplate
	var updated string
	if err := sc.Scan(&tpl.ID, &tpl.Title, &tpl.Body, &updated); err != nil {
		return DashboardTemplate{}, err
	}
	if t, err := time.Parse(time.RFC3339, updated); err == nil {
		tpl.UpdatedAt = t
	}
	return tpl, nil
}
