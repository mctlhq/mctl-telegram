package db

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/sanitize"
)

// Acquisition states, mirrored from internal/acquisition so this package
// does not import it.
const (
	AcquisitionAttributed = "attributed"
	AcquisitionDirect     = "direct"
	AcquisitionUnknown    = "unknown"
)

// Acquisition label fallbacks used by reports.
const (
	AcquisitionLabelPreCapture  = "unknown (pre-capture)"
	AcquisitionLabelNotRecorded = "unknown (not recorded)"
)

// Acquisition is the immutable sign-up source of one user.
type Acquisition struct {
	State        string
	ReferrerHost string
	UTMSource    string
	UTMMedium    string
	UTMCampaign  string
	UTMContent   string
	UTMTerm      string
	LandingPath  string
	MCPClient    string
	CapturedAt   time.Time
}

// insertAcquisitionBestEffort writes the user_acquisition row for a user the
// enclosing transaction just created. The insert is the only statement under
// SAVEPOINT acq; on failure the savepoint is rolled back, the failure is
// logged (never with its values) and counted, and the user row
// stays. A failed write leaves the row absent; it never becomes "direct".
func (s *Store) insertAcquisitionBestEffort(ctx context.Context, tx *sql.Tx, login string, a Acquisition) {
	fail := func(stage string, err error) {
		slog.Warn("acquisition: write failed", "stage", stage, "err", err)
		if s.metrics != nil {
			s.metrics.CountAcquisitionWriteFailure()
		}
	}
	if _, err := tx.ExecContext(ctx, `SAVEPOINT acq`); err != nil {
		fail("savepoint", err)
		return
	}
	now := time.Now().UTC()
	captured := a.CapturedAt.UTC()
	if a.CapturedAt.IsZero() {
		captured = now
	}
	// Resolve the id and insert under the savepoint, so any failure of
	// either statement is rolled back without poisoning the transaction.
	var uid int64
	err := tx.QueryRowContext(ctx, `SELECT id FROM users WHERE github_login = $1`, login).Scan(&uid)
	if err == nil {
		_, err = tx.ExecContext(ctx,
			`INSERT INTO user_acquisition(
			     user_id, state, referrer_host, utm_source, utm_medium, utm_campaign,
			     utm_content, utm_term, landing_path, mcp_client, captured_at, recorded_at
			 )
			 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
			 ON CONFLICT (user_id) DO NOTHING`,
			uid, a.State, a.ReferrerHost, a.UTMSource, a.UTMMedium, a.UTMCampaign,
			a.UTMContent, a.UTMTerm, a.LandingPath, a.MCPClient, captured, now,
		)
	}
	if err != nil {
		if _, rerr := tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT acq`); rerr != nil {
			fail("rollback", rerr)
			return
		}
		fail("insert", err)
	}
	_, _ = tx.ExecContext(ctx, `RELEASE SAVEPOINT acq`)
}

// HeardFromUnanswered reports whether the user has a sign-up record created
// at or after since with no answer yet. No record means false, so an account
// from before capture, or one whose write failed, is not asked.
func (s *Store) HeardFromUnanswered(ctx context.Context, userID int64, since time.Time) (bool, error) {
	var n int
	err := s.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM user_acquisition
		 WHERE user_id = $1 AND heard_from = '' AND recorded_at >= $2`, userID, since.UTC()).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("heard_from lookup: %w", err)
	}
	return n > 0, nil
}

// RecordHeardFrom stores the answer on the user's sign-up record. The first
// answer stays: a later call changes nothing.
func (s *Store) RecordHeardFrom(ctx context.Context, userID int64, answer string) error {
	_, err := s.DB.ExecContext(ctx,
		`UPDATE user_acquisition SET heard_from = $1 WHERE user_id = $2 AND heard_from = ''`, answer, userID)
	if err != nil {
		if s.metrics != nil {
			s.metrics.CountAcquisitionWriteFailure()
		}
		return fmt.Errorf("heard_from write: %w", err)
	}
	return nil
}

// acquisitionLabelSQL is the report label expression over alias a
// (user_acquisition, possibly NULL) and u (users) and e (epoch).
const acquisitionLabelSQL = `CASE
	WHEN a.user_id IS NULL THEN
		CASE WHEN e.enabled_at IS NOT NULL AND u.created_at < e.enabled_at
			THEN '` + AcquisitionLabelPreCapture + `'
			ELSE '` + AcquisitionLabelNotRecorded + `' END
	WHEN a.heard_from <> '' THEN a.heard_from
	WHEN a.utm_source <> '' THEN a.utm_source
	WHEN a.referrer_host <> '' THEN a.referrer_host
	WHEN a.state = 'direct' THEN 'direct'
	ELSE 'unknown' END`

// SanitizeAcquisitionLabel makes a stored label safe to render.
func SanitizeAcquisitionLabel(l string) string {
	l = sanitize.Name(l, 60)
	if l == "" || l == "[empty]" {
		return AcquisitionLabelNotRecorded
	}
	return l
}

// AcquisitionLabelsFor returns the source label of each Telegram id in one
// bounded query: the heard_from answer, else utm_source, else referrer_host
// (those two only on records from before the cookie was removed), else direct, unknown,
// "unknown (pre-capture)" or "unknown (not recorded)". Ids with no users
// row are absent from the map.
func (s *Store) AcquisitionLabelsFor(ctx context.Context, tgIDs []int64) (map[int64]string, error) {
	out := make(map[int64]string, len(tgIDs))
	if len(tgIDs) == 0 {
		return out, nil
	}
	ph := make([]string, len(tgIDs))
	args := make([]any, len(tgIDs))
	for i, id := range tgIDs {
		ph[i] = fmt.Sprintf("$%d", i+1)
		args[i] = id
	}
	rows, err := s.DB.QueryContext(ctx,
		`SELECT u.telegram_login_id, `+acquisitionLabelSQL+`
		 FROM users u
		 LEFT JOIN user_acquisition a ON a.user_id = u.id
		 LEFT JOIN acquisition_capture_epoch e ON e.id = 1
		 WHERE u.telegram_login_id IN (`+strings.Join(ph, ",")+`)`, args...)
	if err != nil {
		return nil, fmt.Errorf("acquisition labels: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var label string
		if err := rows.Scan(&id, &label); err != nil {
			return nil, fmt.Errorf("acquisition labels: scan: %w", err)
		}
		out[id] = SanitizeAcquisitionLabel(label)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("acquisition labels: %w", err)
	}
	return out, nil
}

// AcquisitionBucket is one row of the acquisition report.
type AcquisitionBucket struct {
	Source          string `json:"source"`
	Signups         int64  `json:"signups"`
	ToolCallUsers   int64  `json:"tool_call_users"`
	Active2PlusDays int64  `json:"active_2plus_days"`
}

// AcquisitionReport groups users created at or after since by source label:
// sign-ups, users with at least one audited tool call, and users with tool
// calls on two or more distinct UTC days.
func (s *Store) AcquisitionReport(ctx context.Context, since time.Time) ([]AcquisitionBucket, error) {
	pg, err := s.postgresDialect(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquisition report: %w", err)
	}
	day := `substr(l.created_at, 1, 10)`
	if pg {
		day = `(l.created_at AT TIME ZONE 'UTC')::date`
	}
	rows, err := s.DB.QueryContext(ctx,
		`WITH per_user AS (
		     SELECT u.id AS uid, `+acquisitionLabelSQL+` AS label,
		            (SELECT COUNT(*) FROM audit_logs l WHERE l.user_id = u.id) AS calls,
		            (SELECT COUNT(DISTINCT `+day+`) FROM audit_logs l WHERE l.user_id = u.id) AS days
		     FROM users u
		     LEFT JOIN user_acquisition a ON a.user_id = u.id
		     LEFT JOIN acquisition_capture_epoch e ON e.id = 1
		     WHERE u.created_at >= $1
		 )
		 SELECT label, COUNT(*),
		        SUM(CASE WHEN calls > 0 THEN 1 ELSE 0 END),
		        SUM(CASE WHEN days >= 2 THEN 1 ELSE 0 END)
		 FROM per_user GROUP BY label ORDER BY COUNT(*) DESC, label`, since.UTC())
	if err != nil {
		return nil, fmt.Errorf("acquisition report: %w", err)
	}
	defer rows.Close()
	var out []AcquisitionBucket
	for rows.Next() {
		var b AcquisitionBucket
		if err := rows.Scan(&b.Source, &b.Signups, &b.ToolCallUsers, &b.Active2PlusDays); err != nil {
			return nil, fmt.Errorf("acquisition report: scan: %w", err)
		}
		b.Source = SanitizeAcquisitionLabel(b.Source)
		out = append(out, b)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("acquisition report: %w", err)
	}
	return out, nil
}
