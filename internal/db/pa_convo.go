package db

// pa_convo.go is the Personal Assistant's consent and conversation state
// (issue #1313 slice b; threat model T5, T13). It implements convo.Store.
//
// Nothing here holds plaintext: fragment text is sealed by convo.Sealer with
// a per-principal key before it reaches the store, and the provenance mark
// stored next to it is bound into the ciphertext. Every lookup is keyed by
// principal (I10), and every read failure is an error wrapping
// convo.ErrUnreadable, never "no consent" or "no state" (I9).
//
// Timestamps are unix milliseconds, as in pa_connections.go.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/pa/convo"
	"github.com/mctlhq/mctl-telegram/internal/pa/jobs"
)

var _ convo.Store = (*Store)(nil)

// paConvoSchema returns the DDL for the slice (b) tables.
//
//   - pa_consents: one row per principal, separate from AssistantInstall
//     (T13). A withdrawn consent keeps its row in state 'withdrawn'.
//   - pa_conversations: expires_at_ms is created_at_ms + TTL and never
//     moves. closed_at_ms > 0 means /new closed it; it is never loaded
//     again. The partial unique index allows one open conversation per
//     principal. tainted (added by migratePAConvo) only ever rises.
//   - pa_fragments: sealed text with its kind and mark in clear. provenance
//     has no CHECK constraint on purpose: the Go layer refuses to write an
//     unknown mark, and an unmarked row that exists anyway (older state, a
//     manual edit) must be purgeable and refused on load rather than make
//     the whole migration fail.
//   - pa_callbacks: opaque callback_data ids, resolved only under
//     (principal, id) and consumed on use.
func paConvoSchema(pg bool) []string {
	intT, blobT := "INTEGER", "BLOB"
	if pg {
		intT, blobT = "BIGINT", "BYTEA"
	}
	return []string{
		`CREATE TABLE IF NOT EXISTS pa_consents (
			principal ` + intT + ` PRIMARY KEY,
			version TEXT NOT NULL,
			text_sha256 TEXT NOT NULL,
			state TEXT NOT NULL,
			updated_at_ms ` + intT + ` NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS pa_conversations (
			id TEXT PRIMARY KEY,
			principal ` + intT + ` NOT NULL,
			created_at_ms ` + intT + ` NOT NULL,
			expires_at_ms ` + intT + ` NOT NULL,
			closed_at_ms ` + intT + ` NOT NULL DEFAULT 0
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_pa_conversations_open ON pa_conversations(principal) WHERE closed_at_ms = 0`,
		`CREATE INDEX IF NOT EXISTS idx_pa_conversations_expiry ON pa_conversations(expires_at_ms)`,
		// Every conversation of a principal, closed ones included (/forget,
		// account deletion); idx_pa_conversations_open covers open ones only.
		`CREATE INDEX IF NOT EXISTS idx_pa_conversations_principal ON pa_conversations(principal)`,
		`CREATE TABLE IF NOT EXISTS pa_fragments (
			conversation_id TEXT NOT NULL,
			seq ` + intT + ` NOT NULL,
			principal ` + intT + ` NOT NULL,
			kind TEXT NOT NULL,
			provenance TEXT NOT NULL DEFAULT '',
			sealed ` + blobT + ` NOT NULL,
			created_at_ms ` + intT + ` NOT NULL,
			PRIMARY KEY (conversation_id, seq)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_pa_fragments_principal ON pa_fragments(principal)`,
		// One row per principal whose upsert is the per-principal update
		// lock: a concurrent upsert of the same key waits for the holder's
		// transaction on Postgres, and SQLite serialises writers anyway.
		`CREATE TABLE IF NOT EXISTS pa_principal_locks (
			principal ` + intT + ` PRIMARY KEY,
			locked_at_ms ` + intT + ` NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS pa_callbacks (
			principal ` + intT + ` NOT NULL,
			id TEXT NOT NULL,
			action TEXT NOT NULL,
			expires_at_ms ` + intT + ` NOT NULL,
			PRIMARY KEY (principal, id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_pa_callbacks_expiry ON pa_callbacks(expires_at_ms)`,
	}
}

func migratePAConvo(ctx context.Context, dbConn migrateDB, pg bool) error {
	for _, s := range paConvoSchema(pg) {
		if _, err := dbConn.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("migrate pa conversation state: %w", err)
		}
	}
	// purged_at_ms: when an account deletion last purged the principal
	// (purgePAPrincipals), 0 if never. It fences a Begin admitted before the
	// deletion (CreatePAConnection, #1338).
	if err := addColumnIfMissing(ctx, dbConn, pg, "pa_principal_locks", "purged_at_ms",
		"BIGINT NOT NULL DEFAULT 0", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	// tainted: 1 once external content entered the conversation (T5,
	// #1321). The default is 1, so every row that existed before the column
	// (whose history this build cannot prove clean) and any insert that
	// does not name the column is tainted; OpenPAConversation alone writes
	// a clean row, and only when it creates one.
	return addColumnIfMissing(ctx, dbConn, pg, "pa_conversations", "tainted",
		"INTEGER NOT NULL DEFAULT 1", "INTEGER NOT NULL DEFAULT 1")
}

func unreadable(op string, err error) error {
	return fmt.Errorf("%w: %s: %v", convo.ErrUnreadable, op, err)
}

// storeFault is unreadable for a failed read (query, begin, rows):
// nothing was observed about the row.
func storeFault(op string, err error) error {
	return fmt.Errorf("%w: %w: %s: %v", convo.ErrUnreadable, convo.ErrStoreFault, op, err)
}

// rowRead classifies an error from reading one row: a row that was read
// and does not scan is the row's fault, anything else the store's.
func rowRead(op string, err error) error {
	if isRowFault(err) {
		return unreadable(op, err)
	}
	return storeFault(op, err)
}

// GetPAConsent implements convo.Store.
func (s *Store) GetPAConsent(ctx context.Context, tx *sql.Tx, principal int64) (convo.ConsentRecord, error) {
	if tx == nil || principal <= 0 {
		return convo.ConsentRecord{}, fmt.Errorf("%w: consent lookup", convo.ErrInvalid)
	}
	var (
		rec   convo.ConsentRecord
		state string
		updMS int64
	)
	err := tx.QueryRowContext(ctx,
		`SELECT principal, version, text_sha256, state, updated_at_ms FROM pa_consents WHERE principal = $1`,
		principal).Scan(&rec.Principal, &rec.Version, &rec.TextSHA256, &state, &updMS)
	if errors.Is(err, sql.ErrNoRows) {
		return convo.ConsentRecord{}, convo.ErrNotFound
	}
	if err != nil {
		return convo.ConsentRecord{}, rowRead("consent", err)
	}
	rec.State = convo.ConsentState(state)
	if rec.Principal != principal || rec.Version == "" || rec.TextSHA256 == "" ||
		(rec.State != convo.ConsentAccepted && rec.State != convo.ConsentWithdrawn) {
		return convo.ConsentRecord{}, fmt.Errorf("%w: consent row has an invalid state or version", convo.ErrUnreadable)
	}
	rec.UpdatedAt = time.UnixMilli(updMS).UTC()
	return rec, nil
}

// AcceptPAConsent implements convo.Store.
func (s *Store) AcceptPAConsent(ctx context.Context, tx *sql.Tx, principal int64, version, textSHA256 string, now time.Time) error {
	if tx == nil || principal <= 0 || version == "" || textSHA256 == "" {
		return fmt.Errorf("%w: consent accept", convo.ErrInvalid)
	}
	_, err := tx.ExecContext(ctx,
		`INSERT INTO pa_consents(principal, version, text_sha256, state, updated_at_ms)
		 VALUES($1, $2, $3, $4, $5)
		 ON CONFLICT (principal) DO UPDATE SET version = excluded.version,
		   text_sha256 = excluded.text_sha256, state = excluded.state, updated_at_ms = excluded.updated_at_ms`,
		principal, version, textSHA256, string(convo.ConsentAccepted), now.UnixMilli())
	if err != nil {
		return fmt.Errorf("accept pa consent: %w", err)
	}
	return nil
}

// WithdrawPAConsent implements convo.Store. The consent row and the state
// deletion share the caller's transaction: either both happen or neither.
func (s *Store) WithdrawPAConsent(ctx context.Context, tx *sql.Tx, principal int64, now time.Time) error {
	if tx == nil || principal <= 0 {
		return fmt.Errorf("%w: consent withdraw", convo.ErrInvalid)
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE pa_consents SET state = $1, updated_at_ms = $2 WHERE principal = $3`,
		string(convo.ConsentWithdrawn), now.UnixMilli(), principal); err != nil {
		return fmt.Errorf("withdraw pa consent: %w", err)
	}
	if err := s.ForgetPAConversations(ctx, tx, principal); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM pa_callbacks WHERE principal = $1`, principal); err != nil {
		return fmt.Errorf("withdraw pa consent: callbacks: %w", err)
	}
	return nil
}

// OpenPAConversation implements convo.Store. An open conversation past its
// expiry is closed first, so it is never returned and a fresh one takes its
// place in the same transaction.
func (s *Store) OpenPAConversation(ctx context.Context, tx *sql.Tx, principal int64, newID string, now time.Time, ttl time.Duration) (convo.Conversation, error) {
	if tx == nil || principal <= 0 || newID == "" || ttl <= 0 {
		return convo.Conversation{}, fmt.Errorf("%w: open conversation", convo.ErrInvalid)
	}
	nowMS := now.UnixMilli()
	if _, err := tx.ExecContext(ctx,
		`UPDATE pa_conversations SET closed_at_ms = $1
		 WHERE principal = $2 AND closed_at_ms = 0 AND expires_at_ms <= $1`,
		nowMS, principal); err != nil {
		return convo.Conversation{}, fmt.Errorf("open pa conversation: close expired: %w", err)
	}
	// A new row starts clean. On a conflict the open row is kept as it
	// is, its taint included: nothing here lowers a flag.
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO pa_conversations(id, principal, created_at_ms, expires_at_ms, closed_at_ms, tainted)
		 VALUES($1, $2, $3, $4, 0, 0)
		 ON CONFLICT (principal) WHERE closed_at_ms = 0 DO NOTHING`,
		newID, principal, nowMS, now.Add(ttl).UnixMilli()); err != nil {
		return convo.Conversation{}, fmt.Errorf("open pa conversation: insert: %w", err)
	}
	var (
		c                 convo.Conversation
		createdMS, expyMS int64
	)
	err := tx.QueryRowContext(ctx,
		`SELECT id, principal, created_at_ms, expires_at_ms FROM pa_conversations
		 WHERE principal = $1 AND closed_at_ms = 0 AND expires_at_ms > $2`,
		principal, nowMS).Scan(&c.ID, &c.Principal, &createdMS, &expyMS)
	if err != nil {
		// Not even ErrNoRows is absence here: the insert above guarantees a
		// row, so not seeing one is a failed read.
		return convo.Conversation{}, unreadable("open conversation", err)
	}
	c.CreatedAt, c.ExpiresAt = time.UnixMilli(createdMS).UTC(), time.UnixMilli(expyMS).UTC()
	return c, nil
}

// LockPAPrincipal implements convo.Store.
func (s *Store) LockPAPrincipal(ctx context.Context, tx *sql.Tx, principal int64) error {
	if tx == nil || principal <= 0 {
		return fmt.Errorf("%w: lock principal", convo.ErrInvalid)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO pa_principal_locks(principal, locked_at_ms) VALUES($1, $2)
		 ON CONFLICT (principal) DO UPDATE SET locked_at_ms = excluded.locked_at_ms`,
		principal, time.Now().UnixMilli()); err != nil {
		return fmt.Errorf("lock pa principal: %w", err)
	}
	return nil
}

// ClosePAConversations implements convo.Store (/new). The open
// conversation's fragments are deleted in the same statement set, so /new
// leaves no text behind; the sweep later removes the closed row itself.
func (s *Store) ClosePAConversations(ctx context.Context, tx *sql.Tx, principal int64, now time.Time) error {
	if tx == nil || principal <= 0 {
		return fmt.Errorf("%w: close conversation", convo.ErrInvalid)
	}
	// Jobs of the closed conversation go with it, at once rather than at
	// their next gate check (#1313 slice d1). Each principal has one open
	// conversation, so these are all of the principal's live jobs.
	if err := cancelPAJobs(ctx, tx, principal, now.UnixMilli(),
		jobs.StatusPending, jobs.StatusHeld, jobs.StatusClaimed); err != nil {
		return fmt.Errorf("close pa conversation: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM pa_fragments WHERE principal = $1 AND conversation_id IN
			(SELECT id FROM pa_conversations WHERE principal = $1 AND closed_at_ms = 0)`,
		principal); err != nil {
		return fmt.Errorf("close pa conversation: fragments: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE pa_conversations SET closed_at_ms = $1 WHERE principal = $2 AND closed_at_ms = 0`,
		now.UnixMilli(), principal); err != nil {
		return fmt.Errorf("close pa conversation: %w", err)
	}
	return nil
}

// ForgetPAConversations implements convo.Store (/forget).
func (s *Store) ForgetPAConversations(ctx context.Context, tx *sql.Tx, principal int64) error {
	if tx == nil || principal <= 0 {
		return fmt.Errorf("%w: forget conversations", convo.ErrInvalid)
	}
	// Queued and running jobs go with the conversations they would read
	// (#1313 slice d1); a running job's reservation is held, not refunded.
	if err := cancelPAJobs(ctx, tx, principal, time.Now().UnixMilli(),
		jobs.StatusPending, jobs.StatusHeld, jobs.StatusClaimed); err != nil {
		return err
	}
	if err := deletePAOutboxNotices(ctx, tx, principal); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM pa_fragments WHERE principal = $1`, principal); err != nil {
		return fmt.Errorf("forget pa conversations: fragments: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM pa_conversations WHERE principal = $1`, principal); err != nil {
		return fmt.Errorf("forget pa conversations: %w", err)
	}
	return nil
}

// NextPAFragmentSeq implements convo.Store. The (conversation_id, seq)
// primary key refuses a racing writer that computed the same number.
func (s *Store) NextPAFragmentSeq(ctx context.Context, tx *sql.Tx, principal int64, conversationID string) (int64, error) {
	if tx == nil || principal <= 0 || conversationID == "" {
		return 0, fmt.Errorf("%w: fragment seq", convo.ErrInvalid)
	}
	var owner int64
	err := tx.QueryRowContext(ctx,
		`SELECT principal FROM pa_conversations WHERE id = $1 AND principal = $2`,
		conversationID, principal).Scan(&owner)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, convo.ErrNotFound
	}
	if err != nil {
		return 0, unreadable("fragment seq: conversation", err)
	}
	var next int64
	if err := tx.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(seq), 0) + 1 FROM pa_fragments WHERE conversation_id = $1`,
		conversationID).Scan(&next); err != nil {
		return 0, unreadable("fragment seq", err)
	}
	return next, nil
}

// AppendPAFragment implements convo.Store. It refuses an unknown mark or
// kind before touching the table, and a conversation that is not the
// principal's (the INSERT ... SELECT inserts nothing).
func (s *Store) AppendPAFragment(ctx context.Context, tx *sql.Tx, f convo.SealedFragment) error {
	if tx == nil || f.Principal <= 0 || f.ConversationID == "" || f.Seq <= 0 ||
		!f.Kind.Valid() || !f.Provenance.Known() || len(f.Sealed) == 0 {
		return fmt.Errorf("%w: fragment", convo.ErrInvalid)
	}
	res, err := tx.ExecContext(ctx,
		`INSERT INTO pa_fragments(conversation_id, seq, principal, kind, provenance, sealed, created_at_ms)
		 SELECT id, $1, principal, $2, $3, $4, $5 FROM pa_conversations
		 WHERE id = $6 AND principal = $7 AND closed_at_ms = 0`,
		f.Seq, string(f.Kind), string(f.Provenance), f.Sealed, f.CreatedAt.UnixMilli(), f.ConversationID, f.Principal)
	if err != nil {
		return fmt.Errorf("append pa fragment: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("append pa fragment: rows affected: %w", err)
	}
	if n != 1 {
		return convo.ErrNotFound
	}
	if !convo.Taints(f.Kind, f.Provenance) {
		return nil
	}
	// The flag rises in the fragment's transaction: external content is
	// never stored without it. An UPDATE that touches no row means the
	// conversation was not observed, and the fragment is refused with it.
	res, err = tx.ExecContext(ctx,
		`UPDATE pa_conversations SET tainted = 1 WHERE id = $1 AND principal = $2`,
		f.ConversationID, f.Principal)
	if err != nil {
		return fmt.Errorf("append pa fragment: taint: %w", err)
	}
	if n, err = res.RowsAffected(); err != nil {
		return fmt.Errorf("append pa fragment: taint: rows affected: %w", err)
	}
	if n != 1 {
		return fmt.Errorf("%w: append pa fragment: taint not recorded", convo.ErrUnreadable)
	}
	return nil
}

// ReadPAConversationTaint implements convo.Store. Only a row read with a
// stored 0 is clean; any other value, a missing row and every failed
// read are tainted (I9, S2-I10). The row is read whether or not it is
// still open: a closed or expired conversation keeps the flag it had.
func (s *Store) ReadPAConversationTaint(ctx context.Context, principal int64, conversationID string) (bool, error) {
	if principal <= 0 || conversationID == "" {
		return true, fmt.Errorf("%w: conversation taint", convo.ErrInvalid)
	}
	var tainted int64
	err := s.DB.QueryRowContext(ctx,
		`SELECT tainted FROM pa_conversations WHERE id = $1 AND principal = $2`,
		conversationID, principal).Scan(&tainted)
	if errors.Is(err, sql.ErrNoRows) {
		return true, convo.ErrNotFound
	}
	if err != nil {
		return true, rowRead("conversation taint", err)
	}
	return tainted != 0, nil
}

// LoadPAFragments implements convo.Store.
func (s *Store) LoadPAFragments(ctx context.Context, principal int64, conversationID string, now time.Time) ([]convo.SealedFragment, error) {
	if principal <= 0 || conversationID == "" {
		return nil, fmt.Errorf("%w: load fragments", convo.ErrInvalid)
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, storeFault("load fragments: begin", err)
	}
	defer func() { _ = tx.Rollback() }()
	var open int
	err = tx.QueryRowContext(ctx,
		`SELECT 1 FROM pa_conversations
		 WHERE id = $1 AND principal = $2 AND closed_at_ms = 0 AND expires_at_ms > $3`,
		conversationID, principal, now.UnixMilli()).Scan(&open)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, convo.ErrNotFound
	}
	if err != nil {
		return nil, storeFault("load fragments: conversation", err)
	}
	rows, err := tx.QueryContext(ctx,
		`SELECT conversation_id, seq, principal, kind, provenance, sealed, created_at_ms
		 FROM pa_fragments WHERE conversation_id = $1 AND principal = $2 ORDER BY seq`,
		conversationID, principal)
	if err != nil {
		return nil, storeFault("load fragments", err)
	}
	defer rows.Close()
	var out []convo.SealedFragment
	for rows.Next() {
		var (
			f          convo.SealedFragment
			kind, prov string
			createdMS  int64
		)
		if err := rows.Scan(&f.ConversationID, &f.Seq, &f.Principal, &kind, &prov, &f.Sealed, &createdMS); err != nil {
			return nil, rowRead("load fragments: scan", err)
		}
		f.Kind, f.Provenance = convo.Kind(kind), convo.Provenance(prov)
		f.CreatedAt = time.UnixMilli(createdMS).UTC()
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, storeFault("load fragments: rows", err)
	}
	return out, nil
}

// CreatePACallback implements convo.Store.
func (s *Store) CreatePACallback(ctx context.Context, tx *sql.Tx, principal int64, id, action string, expiresAt time.Time) error {
	if tx == nil || principal <= 0 || id == "" || action == "" {
		return fmt.Errorf("%w: callback", convo.ErrInvalid)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO pa_callbacks(principal, id, action, expires_at_ms) VALUES($1, $2, $3, $4)`,
		principal, id, action, expiresAt.UnixMilli()); err != nil {
		return fmt.Errorf("create pa callback: %w", err)
	}
	return nil
}

// ConsumePACallback implements convo.Store. The DELETE is keyed by
// (principal, id), so another principal's id matches nothing and stays.
func (s *Store) ConsumePACallback(ctx context.Context, tx *sql.Tx, principal int64, id string, now time.Time) (string, error) {
	if tx == nil || principal <= 0 || id == "" {
		return "", fmt.Errorf("%w: callback", convo.ErrInvalid)
	}
	var action string
	err := tx.QueryRowContext(ctx,
		`DELETE FROM pa_callbacks WHERE principal = $1 AND id = $2 AND expires_at_ms > $3 RETURNING action`,
		principal, id, now.UnixMilli()).Scan(&action)
	if errors.Is(err, sql.ErrNoRows) {
		return "", convo.ErrNotFound
	}
	if err != nil {
		return "", unreadable("consume callback", err)
	}
	return action, nil
}

// PACallbackExpiry returns when principal's callback id stops resolving.
// convo.ErrNotFound means there is no such id for principal: consumed,
// purged after it expired, deleted, or never issued. A failed read wraps
// convo.ErrStoreFault and says nothing about the id. The outbox reads it
// before sending a consent prompt, so a button that can no longer be
// pressed is not sent (#1352 follow-up).
func (s *Store) PACallbackExpiry(ctx context.Context, principal int64, id string) (time.Time, error) {
	if principal <= 0 || id == "" {
		return time.Time{}, fmt.Errorf("%w: callback", convo.ErrInvalid)
	}
	var expiresMS int64
	err := s.DB.QueryRowContext(ctx,
		`SELECT expires_at_ms FROM pa_callbacks WHERE principal = $1 AND id = $2`,
		principal, id).Scan(&expiresMS)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, convo.ErrNotFound
	}
	if err != nil {
		return time.Time{}, storeFault("callback expiry", err)
	}
	return time.UnixMilli(expiresMS).UTC(), nil
}

// PurgeUnmarkedPAState implements convo.Store: the "purge on enable" of T5.
// It removes every fragment this build cannot decode: one without a known
// provenance mark, or one of a kind it does not know.
func (s *Store) PurgeUnmarkedPAState(ctx context.Context) (int64, error) {
	args := []any{string(convo.ProvenanceUser), string(convo.ProvenanceExternal)}
	kinds := make([]string, 0, len(convo.Kinds()))
	for _, k := range convo.Kinds() {
		args = append(args, string(k))
		kinds = append(kinds, "$"+strconv.Itoa(len(args)))
	}
	res, err := s.DB.ExecContext(ctx,
		`DELETE FROM pa_fragments WHERE provenance IS NULL OR provenance NOT IN ($1, $2)
			OR kind IS NULL OR kind NOT IN (`+strings.Join(kinds, ", ")+`)`, args...)
	if err != nil {
		return 0, fmt.Errorf("purge unmarked pa state: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("purge unmarked pa state: rows affected: %w", err)
	}
	return n, nil
}

// SweepPAState implements convo.Store. One transaction, so a conversation
// and its fragments go together.
func (s *Store) SweepPAState(ctx context.Context, now, updatesBefore time.Time) (convo.SweepResult, error) {
	var r convo.SweepResult
	// Stale lock rows go first, in their own statement and transaction: a
	// handler takes its principal's lock row before touching conversations,
	// so a sweep that held conversation rows and then waited for a lock row
	// could deadlock with it. The sweep transaction below holds no lock row.
	// Lock rows carry no state; one unused for the dedup window goes.
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM pa_principal_locks WHERE locked_at_ms < $1`,
		updatesBefore.UnixMilli()); err != nil {
		return r, fmt.Errorf("sweep pa state: locks: %w", err)
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return r, fmt.Errorf("sweep pa state: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	nowMS := now.UnixMilli()
	steps := []struct {
		dst  *int64
		q    string
		args []any
	}{
		{&r.Fragments, `DELETE FROM pa_fragments WHERE conversation_id NOT IN (
			SELECT id FROM pa_conversations WHERE closed_at_ms = 0 AND expires_at_ms > $1)`, []any{nowMS}},
		{&r.Conversations, `DELETE FROM pa_conversations WHERE closed_at_ms > 0 OR expires_at_ms <= $1`, []any{nowMS}},
		{&r.Callbacks, `DELETE FROM pa_callbacks WHERE expires_at_ms <= $1`, []any{nowMS}},
		{&r.Updates, `DELETE FROM pa_updates WHERE received_at < $1`, []any{updatesBefore.UTC()}},
		// Run-loop rows (#1313 slice d1): failure counters past the dedup
		// window, finished jobs past it, and ledger rows past every budget
		// window (a month plus a margin). Discarded counts: SweepResult is
		// convo's and has no field for them.
		{new(int64), `DELETE FROM pa_update_failures WHERE updated_at_ms < $1`, []any{updatesBefore.UnixMilli()}},
		{new(int64), `DELETE FROM pa_jobs WHERE status IN ('done', 'cancelled', 'expired') AND updated_at_ms < $1`, []any{updatesBefore.UnixMilli()}},
		{new(int64), `DELETE FROM pa_usage WHERE status <> 'reserved' AND created_at_ms < $1`, []any{now.Add(-PAUsageRetention).UnixMilli()}},
		{new(int64), `DELETE FROM pa_rate WHERE window_start_ms < $1`, []any{updatesBefore.UnixMilli()}},
		// Outbox rows that will not be sent again (#1313 slice d2). A
		// pending or sending row is kept whatever its age.
		{new(int64), `DELETE FROM pa_outbox WHERE status NOT IN ('pending', 'sending') AND updated_at_ms < $1`, []any{updatesBefore.UnixMilli()}},
		// Linking secrets past PALinkSecretRetention after their expiry,
		// consumed or not (#1338). A row that has not expired is kept, so
		// a live secret is never deleted under its holder.
		{&r.LinkSecrets, `DELETE FROM pa_link_secrets WHERE expires_at_ms < $1`, []any{now.Add(-PALinkSecretRetention).UnixMilli()}},
	}
	for _, st := range steps {
		res, err := tx.ExecContext(ctx, st.q, st.args...)
		if err != nil {
			return convo.SweepResult{}, fmt.Errorf("sweep pa state: %w", err)
		}
		if *st.dst, err = res.RowsAffected(); err != nil {
			return convo.SweepResult{}, fmt.Errorf("sweep pa state: rows affected: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return convo.SweepResult{}, fmt.Errorf("sweep pa state: commit: %w", err)
	}
	return r, nil
}
