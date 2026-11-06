package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// jobLeadSealedFields is what a lead keeps encrypted in data_encrypted. status
// stays in the clear: it is the lead's workflow state, not something the
// recruiter said.
type jobLeadSealedFields struct {
	Company       string `json:"company,omitempty"`
	Role          string `json:"role,omitempty"`
	RecruiterName string `json:"recruiter_name,omitempty"`
	RecruiterTGID int64  `json:"recruiter_tg_id,omitempty"`
	Compensation  string `json:"compensation,omitempty"`
	Detail        string `json:"detail,omitempty"`
}

const jobLeadColumns = `id, user_id, conversation_id, company, role, recruiter_name, recruiter_tg_id,
		        compensation, status, detail, data_encrypted, created_at, updated_at`

// jobLeadHasPlaintext matches a row that still carries fields in the clear:
// one written before encryption, or by an older binary after a rollback.
const jobLeadHasPlaintext = `(company IS NOT NULL OR role IS NOT NULL OR recruiter_name IS NOT NULL
		    OR recruiter_tg_id IS NOT NULL OR compensation IS NOT NULL OR detail <> '{}')`

// scanJobLead reads one jobLeadColumns row. Fields in the clear win over the
// sealed ones: only an older binary writes them, so after a rollback they are
// the newer values. A blob that does not open is an error, never an empty
// lead, so no caller can mistake it for a lead with nothing in it.
func (s *Store) scanJobLead(scan func(...any) error) (JobLead, error) {
	var (
		l                              JobLead
		convID, recruiterTGID          sql.NullInt64
		company, role, recruiter, comp sql.NullString
		sealed                         []byte
	)
	if err := scan(&l.ID, &l.UserID, &convID, &company, &role, &recruiter, &recruiterTGID,
		&comp, &l.Status, &l.Detail, &sealed, &l.CreatedAt, &l.UpdatedAt); err != nil {
		return JobLead{}, err
	}
	l.ConversationID = convID.Int64
	var fields jobLeadSealedFields
	if len(sealed) > 0 {
		if s.Crypt == nil {
			return JobLead{}, errors.New("open job lead: no crypt configured")
		}
		plain, err := s.Crypt.OpenForUser(sealed, l.UserID)
		if err != nil {
			return JobLead{}, fmt.Errorf("open job lead %d: %w", l.ID, err)
		}
		if err := json.Unmarshal(plain, &fields); err != nil {
			return JobLead{}, fmt.Errorf("decode job lead %d: %w", l.ID, err)
		}
	}
	l.Company = firstNonEmpty(company.String, fields.Company)
	l.Role = firstNonEmpty(role.String, fields.Role)
	l.RecruiterName = firstNonEmpty(recruiter.String, fields.RecruiterName)
	l.Compensation = firstNonEmpty(comp.String, fields.Compensation)
	l.RecruiterTGID = recruiterTGID.Int64
	if l.RecruiterTGID == 0 {
		l.RecruiterTGID = fields.RecruiterTGID
	}
	if (l.Detail == "" || l.Detail == "{}") && fields.Detail != "" {
		l.Detail = fields.Detail
	}
	return l, nil
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// sealJobLead returns the encrypted form of a lead's private fields.
func (s *Store) sealJobLead(l JobLead) ([]byte, error) {
	if s.Crypt == nil {
		return nil, errors.New("seal job lead: no crypt configured")
	}
	plain, err := json.Marshal(jobLeadSealedFields{
		Company:       l.Company,
		Role:          l.Role,
		RecruiterName: l.RecruiterName,
		RecruiterTGID: l.RecruiterTGID,
		Compensation:  l.Compensation,
		Detail:        l.Detail,
	})
	if err != nil {
		return nil, fmt.Errorf("encode job lead: %w", err)
	}
	sealed, err := s.Crypt.SealForUser(plain, l.UserID)
	if err != nil {
		return nil, fmt.Errorf("seal job lead: %w", err)
	}
	return sealed, nil
}

// leadRowLock is the lock a read-modify-write of a lead takes on Postgres.
// The fields live in one blob, so without it two concurrent saves would lose
// one of them. SQLite serializes writers and has no FOR UPDATE.
func (s *Store) leadRowLock(ctx context.Context) (string, error) {
	pg, err := s.postgresDialect(ctx)
	if err != nil {
		return "", fmt.Errorf("lead row lock: %w", err)
	}
	if pg {
		return " FOR UPDATE", nil
	}
	return "", nil
}

// jobLeadSealBatch bounds one page of SealPlaintextJobLeads.
const jobLeadSealBatch = 100

// SealPlaintextJobLeads encrypts every lead that still has fields in the
// clear and returns how many it sealed and how many it could not. A row it
// cannot handle stays as it is, for the next pass. Sealing leaves updated_at
// alone: it is the retention clock and the order leads are listed in.
func (s *Store) SealPlaintextJobLeads(ctx context.Context) (sealed, failed int, err error) {
	lock, err := s.leadRowLock(ctx)
	if err != nil {
		return 0, 0, err
	}
	var after int64
	for {
		ids, err := s.plaintextJobLeadIDs(ctx, after)
		if err != nil {
			return sealed, failed, err
		}
		if len(ids) == 0 {
			return sealed, failed, nil
		}
		for _, id := range ids {
			after = id
			if err := s.sealOneJobLead(ctx, id, lock); err != nil {
				slog.Warn("job lead not sealed", "lead_id", id, "err", err)
				failed++
				continue
			}
			sealed++
		}
	}
}

func (s *Store) plaintextJobLeadIDs(ctx context.Context, after int64) ([]int64, error) {
	rows, err := s.DB.QueryContext(ctx,
		`SELECT id FROM job_leads WHERE id > $1 AND `+jobLeadHasPlaintext+` ORDER BY id LIMIT $2`,
		after, jobLeadSealBatch,
	)
	if err != nil {
		return nil, fmt.Errorf("list plaintext job leads: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan plaintext job lead: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list plaintext job leads: %w", err)
	}
	return ids, nil
}

func (s *Store) sealOneJobLead(ctx context.Context, id int64, lock string) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin lead seal: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	l, err := s.scanJobLead(tx.QueryRowContext(ctx,
		`SELECT `+jobLeadColumns+` FROM job_leads WHERE id = $1`+lock, id,
	).Scan)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	blob, err := s.sealJobLead(l)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE job_leads SET company = NULL, role = NULL, recruiter_name = NULL,
		        recruiter_tg_id = NULL, compensation = NULL, detail = '{}', data_encrypted = $1
		  WHERE id = $2`, blob, id,
	); err != nil {
		return fmt.Errorf("seal job lead %d: %w", id, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit lead seal: %w", err)
	}
	return nil
}

// SweepJobLeads deletes leads not updated within retention and returns how
// many. retention <= 0 keeps them. A finished job keeps its result_lead_id,
// which has no foreign key, as a dangling id: GetJobLead answers not found.
func (s *Store) SweepJobLeads(ctx context.Context, retention time.Duration) (int64, error) {
	if retention <= 0 {
		return 0, nil
	}
	cutoff := time.Now().UTC().Add(-retention)
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin lead sweep: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	// Explicit because SQLite runs without foreign_keys here, so the cascade
	// on agent_job_lead_results fires on Postgres only.
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM agent_job_lead_results
		  WHERE lead_id IN (SELECT id FROM job_leads WHERE updated_at < $1)`, cutoff,
	); err != nil {
		return 0, fmt.Errorf("sweep job lead results: %w", err)
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM job_leads WHERE updated_at < $1`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("sweep job leads: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("sweep job leads: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit lead sweep: %w", err)
	}
	return n, nil
}
