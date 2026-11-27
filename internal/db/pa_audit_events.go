// Copyright 2025 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package db

// pa_audit_events.go queues the audit records of Personal Assistant
// changes that are not tool calls (#1320 slice P2-S15a; threat model T12,
// S2-A8, S2-C9): a standing permission granted or revoked, an approval
// cancelled.
//
// The statement that makes the change writes the row in its transaction,
// so a committed change always has its event and a rolled back one has
// none. DrainPAAuditEvents moves rows into the per-user audit chain: the
// delete of the row and the chained insert commit together, so an event is
// appended once, and a failed append leaves the row for the next pass. A
// failure is an error with the row kept, never "nothing to append" (I9).
//
// A row holds ids, digests and closed labels (auditevent.Event). It is
// deleted with the principal's other state on account deletion; /forget
// and a consent withdrawal keep it, as they keep the audit chain.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"

	"github.com/mctlhq/mctl-telegram/internal/pa/auditevent"
)

// paAuditEventsSchema returns the DDL of pa_audit_events. tries counts
// failed appends, so that a row that cannot be appended does not keep the
// rows behind it from being tried.
func paAuditEventsSchema(pg bool) []string {
	intT, idT := "INTEGER", "INTEGER PRIMARY KEY AUTOINCREMENT"
	if pg {
		intT, idT = "BIGINT", "BIGSERIAL PRIMARY KEY"
	}
	return []string{
		`CREATE TABLE IF NOT EXISTS pa_audit_events (
			id ` + idT + `,
			principal ` + intT + ` NOT NULL,
			kind TEXT NOT NULL,
			subject TEXT NOT NULL,
			server TEXT NOT NULL,
			tool TEXT NOT NULL,
			connection_id TEXT NOT NULL,
			authority_revision ` + intT + ` NOT NULL,
			args_sha TEXT NOT NULL DEFAULT '',
			reason TEXT NOT NULL DEFAULT '',
			created_at_ms ` + intT + ` NOT NULL,
			tries ` + intT + ` NOT NULL DEFAULT 0
		)`,
		`CREATE INDEX IF NOT EXISTS idx_pa_audit_events_order ON pa_audit_events(tries, id)`,
		`CREATE INDEX IF NOT EXISTS idx_pa_audit_events_principal ON pa_audit_events(principal)`,
	}
}

func migratePAAuditEvents(ctx context.Context, dbConn migrateDB, pg bool) error {
	for _, s := range paAuditEventsSchema(pg) {
		if _, err := dbConn.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("migrate pa audit events: %w", err)
		}
	}
	return nil
}

const paAuditEventCols = `principal, kind, subject, server, tool, connection_id, authority_revision, args_sha, reason, created_at_ms`

// enqueuePAApprovalCancelled queues, in tx, the cancellation event of
// principal's approval id, read from its row.
func enqueuePAApprovalCancelled(ctx context.Context, tx *sql.Tx, principal int64, id, reason string, nowMS int64) error {
	if !auditevent.ValidReason(auditevent.ApprovalCancelled, reason) {
		return fmt.Errorf("pa audit event: %q is not a cancellation reason", reason)
	}
	res, err := tx.ExecContext(ctx,
		`INSERT INTO pa_audit_events(`+paAuditEventCols+`)
		 SELECT principal, $3, id, server, tool, connection_id, authority_revision, args_sha, $4, $5
		   FROM pa_approvals WHERE principal = $1 AND id = $2`,
		principal, id, string(auditevent.ApprovalCancelled), reason, nowMS)
	return paAuditEventQueued(res, err, auditevent.ApprovalCancelled, id)
}

func paAuditEventQueued(res sql.Result, err error, kind auditevent.Kind, id string) error {
	if err != nil {
		return fmt.Errorf("pa audit event %s: %w", kind, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("pa audit event %s: rows affected: %w", kind, err)
	}
	if n != 1 {
		return fmt.Errorf("pa audit event %s: %d rows queued for %s, want 1", kind, n, id)
	}
	return nil
}

// PAAuditDrain counts one DrainPAAuditEvents pass.
type PAAuditDrain struct {
	// Appended rows are in the audit chain and off the queue.
	Appended int
	// Failed rows are still queued: the append or the render failed.
	Failed int
	// Dropped rows belonged to a principal that has no users row, and so
	// no audit chain: the account was deleted between the change and the
	// pass.
	Dropped int
}

// DrainPAAuditEvents appends up to limit queued events to the audit
// chains of their principals, oldest and least tried first. render turns
// an event into the audit row (tool name, record, status, call path);
// the user id is set here. Each event is one transaction: the queue row is
// deleted, the chained row inserted, and both commit or neither does.
//
// An error is returned when the queue itself cannot be read. A single
// event that fails is counted, kept, and tried again by a later pass.
func (s *Store) DrainPAAuditEvents(ctx context.Context, limit int, render func(auditevent.Event) (ToolCall, error)) (PAAuditDrain, error) {
	var out PAAuditDrain
	if limit <= 0 || render == nil {
		return out, errors.New("drain pa audit events: no limit or no renderer")
	}
	type key struct {
		id    int64
		kind  string
		tries int64
	}
	rows, err := s.DB.QueryContext(ctx,
		`SELECT id, kind, tries FROM pa_audit_events ORDER BY tries, id LIMIT $1`, limit)
	if err != nil {
		return out, fmt.Errorf("drain pa audit events: list: %w", err)
	}
	var keys []key
	for rows.Next() {
		var k key
		if err := rows.Scan(&k.id, &k.kind, &k.tries); err != nil {
			_ = rows.Close()
			return out, fmt.Errorf("drain pa audit events: scan: %w", err)
		}
		keys = append(keys, k)
	}
	if err := rows.Close(); err != nil {
		return out, fmt.Errorf("drain pa audit events: close: %w", err)
	}
	if err := rows.Err(); err != nil {
		return out, fmt.Errorf("drain pa audit events: rows: %w", err)
	}
	for _, k := range keys {
		res, err := s.drainPAAuditEvent(ctx, k.id, render)
		switch {
		case err != nil:
			out.Failed++
			// The queue id is a local serial: it finds a stuck row and
			// carries nothing of the principal.
			slog.Error("pa audit event not appended; kept for the next pass",
				"queue_id", k.id, "tries", k.tries, "kind", k.kind, "err", err)
			if _, uerr := s.DB.ExecContext(ctx,
				`UPDATE pa_audit_events SET tries = tries + 1 WHERE id = $1`, k.id); uerr != nil {
				slog.Error("pa audit event: failed append not counted", "queue_id", k.id, "err", uerr)
			}
		case res == paAuditAppended:
			out.Appended++
		case res == paAuditDropped:
			out.Dropped++
			slog.Warn("pa audit event dropped: its principal has no user row", "kind", k.kind)
		}
	}
	return out, nil
}

const (
	paAuditGone = iota // another pass took the row
	paAuditAppended
	paAuditDropped
)

func (s *Store) drainPAAuditEvent(ctx context.Context, id int64, render func(auditevent.Event) (ToolCall, error)) (int, error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), auditWriteTimeout)
	defer cancel()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var (
		e auditevent.Event
		k string
	)
	err = tx.QueryRowContext(ctx,
		`DELETE FROM pa_audit_events WHERE id = $1 RETURNING `+paAuditEventCols, id).Scan(&e.Principal, &k, &e.Subject, &e.Server, &e.Tool, &e.ConnectionID,
		&e.AuthorityRevision, &e.ArgsSHA256, &e.Reason, &e.AtMS)
	if errors.Is(err, sql.ErrNoRows) {
		return paAuditGone, nil
	}
	if err != nil {
		return 0, fmt.Errorf("take: %w", err)
	}
	e.Kind = auditevent.Kind(k)
	userID, err := userIDByTelegramID(ctx, tx, e.Principal)
	if errors.Is(err, ErrUserNotFound) {
		// The provider of that answer is the users table read in this
		// transaction: no row is the absence signal, not a failed read.
		if err := tx.Commit(); err != nil {
			return 0, fmt.Errorf("drop: commit: %w", err)
		}
		return paAuditDropped, nil
	}
	if err != nil {
		return 0, fmt.Errorf("resolve principal: %w", err)
	}
	c, err := render(e)
	if err != nil {
		return 0, err
	}
	c.UserID = userID
	if err := logToolCallTx(ctx, tx, c); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit: %w", err)
	}
	return paAuditAppended, nil
}
