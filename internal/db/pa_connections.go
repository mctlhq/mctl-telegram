package db

// pa_connections.go is the Personal Assistant connection store (issue
// #1314, threat model T2/T3). It implements connection.Store; the state
// machine and the secret handling live in internal/pa/connection, and this
// file enforces the same rules again at the row: every write is a
// compare-and-set on (principal, id, state, authority_revision), and an
// illegal edge is refused before the row is touched.
//
// Timestamps are unix milliseconds (BIGINT) rather than the dialect's time
// type, so the refresh-lease comparison is plain integer arithmetic in both
// SQLite and Postgres.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
	"github.com/mctlhq/mctl-telegram/internal/pa/convo"
	"github.com/mctlhq/mctl-telegram/internal/pa/jobs"
)

var _ connection.Store = (*Store)(nil)

// paConnectionsSchema returns the DDL for pa_connections. No secret column
// holds plaintext: wrapped_dek is wrapped by the KEK named in kek_id, and
// sealed_code / sealed_tokens are sealed by that DEK. Entering expired,
// failed or revoked sets all three to NULL.
func paConnectionsSchema(pg bool) []string {
	intT, blobT := "INTEGER", "BLOB"
	if pg {
		intT, blobT = "BIGINT", "BYTEA"
	}
	return []string{
		`CREATE TABLE IF NOT EXISTS pa_connections (
			id TEXT PRIMARY KEY,
			principal ` + intT + ` NOT NULL,
			server TEXT NOT NULL,
			state TEXT NOT NULL,
			account_id TEXT NOT NULL DEFAULT '',
			granted_scope TEXT NOT NULL DEFAULT '',
			authority_revision ` + intT + ` NOT NULL,
			token_generation ` + intT + ` NOT NULL DEFAULT 0,
			kek_id TEXT NOT NULL,
			wrapped_dek ` + blobT + `,
			sealed_code ` + blobT + `,
			sealed_tokens ` + blobT + `,
			failure_reason TEXT NOT NULL DEFAULT '',
			refresh_lease_owner TEXT NOT NULL DEFAULT '',
			refresh_lease_until_ms ` + intT + ` NOT NULL DEFAULT 0,
			created_at_ms ` + intT + ` NOT NULL,
			updated_at_ms ` + intT + ` NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_pa_connections_principal ON pa_connections(principal, created_at_ms)`,
	}
}

func migratePAConnections(ctx context.Context, dbConn migrateDB, pg bool) error {
	for _, s := range paConnectionsSchema(pg) {
		if _, err := dbConn.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("migrate pa_connections: %w", err)
		}
	}
	// What the connection asked for (#1320 slice P2-S14c). Empty on every
	// row made before the column, and on every read-only connection: the
	// read set. A previous build ignores the column, and its inserts take
	// the default.
	if err := addColumnIfMissing(ctx, dbConn, pg, "pa_connections", "requested_scope",
		"TEXT NOT NULL DEFAULT ''", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return fmt.Errorf("migrate pa_connections: requested_scope: %w", err)
	}
	return nil
}

const paConnCols = `id, principal, server, state, account_id, granted_scope, requested_scope,
	authority_revision, token_generation, failure_reason, created_at_ms, updated_at_ms`

const paConnSealedCols = paConnCols + `, kek_id, wrapped_dek, sealed_code, sealed_tokens`

type paRowScanner interface {
	Scan(dest ...any) error
}

// scanPAConn reads one row. A state or server value this build does not
// know is unreadable, never "some state that is not active" (I9).
func scanPAConn(r paRowScanner, sealed *connection.Sealed) (connection.Connection, error) {
	var (
		c                connection.Connection
		server, state    string
		createdMS, updMS int64
	)
	dest := []any{&c.ID, &c.Principal, &server, &state, &c.AccountID, &c.GrantedScope, &c.RequestedScope,
		&c.AuthorityRevision, &c.TokenGeneration, &c.FailureReason, &createdMS, &updMS}
	if sealed != nil {
		dest = append(dest, &sealed.KEKID, &sealed.WrappedDEK, &sealed.SealedCode, &sealed.SealedTokens)
	}
	if err := r.Scan(dest...); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return connection.Connection{}, connection.ErrNotFound
		}
		return connection.Connection{}, fmt.Errorf("%w: scan: %v", connection.ErrUnreadable, err)
	}
	c.Server, c.State = connection.Server(server), connection.State(state)
	if !c.State.Valid() || !c.Server.Valid() || c.Principal <= 0 || c.AuthorityRevision <= 0 {
		return connection.Connection{}, fmt.Errorf("%w: row %s has an invalid state, server or counter", connection.ErrUnreadable, c.ID)
	}
	c.CreatedAt, c.UpdatedAt = time.UnixMilli(createdMS).UTC(), time.UnixMilli(updMS).UTC()
	return c, nil
}

type paQuerier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func getPAConn(ctx context.Context, q paQuerier, principal int64, id string, sealed *connection.Sealed) (connection.Connection, error) {
	cols := paConnCols
	if sealed != nil {
		cols = paConnSealedCols
	}
	return scanPAConn(q.QueryRowContext(ctx,
		`SELECT `+cols+` FROM pa_connections WHERE principal = $1 AND id = $2`, principal, id), sealed)
}

// paAdmissionState reads what admits a Begin for principal: its
// account-deletion mark (purgePAPrincipals; 0 when the principal has no lock
// row) and how many of its connections are pending. One statement, so the
// two are read together.
func paAdmissionState(ctx context.Context, q paQuerier, principal int64) (mark, pending int64, err error) {
	err = q.QueryRowContext(ctx, `SELECT
			COALESCE((SELECT purged_at_ms FROM pa_principal_locks WHERE principal = $1), 0),
			(SELECT COUNT(*) FROM pa_connections WHERE principal = $1 AND state IN ($2, $3, $4, $5))`,
		principal, string(connection.StatePendingLink), string(connection.StatePendingOAuth),
		string(connection.StatePendingReturn), string(connection.StatePendingConfirm),
	).Scan(&mark, &pending)
	if err != nil {
		return 0, 0, fmt.Errorf("%w: admission: %v", connection.ErrUnreadable, err)
	}
	return mark, pending, nil
}

// AdmitPAConnection implements connection.Store. Its cap check only spares
// a principal at the cap the KEK wrap; CreatePAConnection decides. It takes
// the principal lock to read the deletion mark, so the lock row exists from
// admission on: an account deletion keeps a row that exists and raises its
// mark (purgePAPrincipals), which is what fences this Begin. Like
// CreatePAConnection, it must not run inside a transaction that already
// holds the principal lock: it would wait for itself.
func (s *Store) AdmitPAConnection(ctx context.Context, principal int64) (connection.Admission, error) {
	if principal <= 0 {
		return connection.Admission{}, fmt.Errorf("%w: admission needs a principal", connection.ErrInvalidTransition)
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return connection.Admission{}, fmt.Errorf("%w: admission: begin: %v", connection.ErrUnreadable, err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO pa_principal_locks(principal, locked_at_ms) VALUES($1, $2)
		 ON CONFLICT (principal) DO UPDATE SET locked_at_ms = excluded.locked_at_ms`,
		principal, time.Now().UnixMilli()); err != nil {
		return connection.Admission{}, fmt.Errorf("admit pa connection: lock principal: %w", err)
	}
	mark, pending, err := paAdmissionState(ctx, tx, principal)
	if err != nil {
		return connection.Admission{}, err
	}
	if pending >= connection.MaxPendingConnections {
		return connection.Admission{}, connection.ErrTooManyPending
	}
	if err := tx.Commit(); err != nil {
		return connection.Admission{}, fmt.Errorf("admit pa connection: commit: %w", err)
	}
	return connection.Admission{PurgeMark: mark, ReadAt: time.Now().UTC()}, nil
}

// paCreateAfterRecount is a test seam: it runs inside CreatePAConnection's
// transaction after the cap and mark checks and before the insert, so a test
// can hold one Begin there while another runs. Always nil outside tests.
var paCreateAfterRecount func(c connection.Connection)

// CreatePAConnection inserts a new pending_link row. In one transaction it
// takes the principal's lock (the pa_principal_locks upsert that a webhook
// update, a job claim and an account deletion take too), then checks:
//
//   - the deletion mark is still the one admission read. purgePAPrincipals
//     raises it under the same lock in the deleting transaction, so a Begin
//     admitted before a deletion that commits first is refused
//     (ErrPrincipalDeleted), and one that commits first is purged with the
//     account. The mark only grows while its row exists, and the lock sweep
//     removes a row only after pa.UpdatesRetention unused, so a mark written
//     after admission is always greater than the one admission read;
//   - fewer than connection.MaxPendingConnections pending rows exist
//     (ErrTooManyPending). Counting under the lock is what makes the cap
//     hold for concurrent Begins: on Postgres the second waits for the first
//     to commit, and SQLite runs one writer at a time.
//
// The fence covers a deletion concurrent with a Begin. A Begin admitted
// after a deletion committed links normally: the principal is a Telegram
// id, so that is the same person registering again.
//
// It must not be called inside a transaction that already holds the
// principal lock (LockPAPrincipal): it takes the lock in its own
// transaction and would wait for itself until ctx ends.
func (s *Store) CreatePAConnection(ctx context.Context, c connection.Connection, sealed connection.Sealed, a connection.Admission) error {
	if c.ID == "" || c.Principal <= 0 || !c.Server.Valid() || c.State != connection.StatePendingLink ||
		c.AuthorityRevision != 1 || c.TokenGeneration != 0 || sealed.KEKID == "" || len(sealed.WrappedDEK) == 0 ||
		len(sealed.SealedCode) != 0 || len(sealed.SealedTokens) != 0 {
		return fmt.Errorf("%w: a new connection is pending_link at revision 1 with only a wrapped dek", connection.ErrInvalidTransition)
	}
	if a.ReadAt.IsZero() {
		return fmt.Errorf("%w: a new connection needs an admission", connection.ErrInvalidTransition)
	}
	now := time.Now().UTC().UnixMilli()
	if !c.CreatedAt.IsZero() {
		now = c.CreatedAt.UTC().UnixMilli()
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("create pa connection: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO pa_principal_locks(principal, locked_at_ms) VALUES($1, $2)
		 ON CONFLICT (principal) DO UPDATE SET locked_at_ms = excluded.locked_at_ms`,
		c.Principal, time.Now().UnixMilli()); err != nil {
		return fmt.Errorf("create pa connection: lock principal: %w", err)
	}
	mark, pending, err := paAdmissionState(ctx, tx, c.Principal)
	if err != nil {
		return err
	}
	if mark > a.PurgeMark {
		return connection.ErrPrincipalDeleted
	}
	if pending >= connection.MaxPendingConnections {
		return connection.ErrTooManyPending
	}
	if paCreateAfterRecount != nil {
		paCreateAfterRecount(c)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO pa_connections(id, principal, server, state, authority_revision, token_generation,
			kek_id, wrapped_dek, created_at_ms, updated_at_ms, requested_scope)
		 VALUES($1, $2, $3, $4, 1, 0, $5, $6, $7, $7, $8)`,
		c.ID, c.Principal, string(c.Server), string(c.State), sealed.KEKID, sealed.WrappedDEK, now, c.RequestedScope); err != nil {
		return fmt.Errorf("create pa connection: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("create pa connection: commit: %w", err)
	}
	return nil
}

// GetPAConnection reads the principal's row without secret material.
func (s *Store) GetPAConnection(ctx context.Context, principal int64, id string) (connection.Connection, error) {
	return getPAConn(ctx, s.DB, principal, id, nil)
}

// GetPAConnectionSealed reads the principal's row with its sealed material.
func (s *Store) GetPAConnectionSealed(ctx context.Context, principal int64, id string) (connection.Connection, connection.Sealed, error) {
	var sealed connection.Sealed
	c, err := getPAConn(ctx, s.DB, principal, id, &sealed)
	if err != nil {
		return connection.Connection{}, connection.Sealed{}, err
	}
	return c, sealed, nil
}

// ListPAConnections returns the principal's rows only. A failure on any row
// fails the whole read: a shorter list is not a valid answer.
func (s *Store) ListPAConnections(ctx context.Context, principal int64) ([]connection.Connection, error) {
	return listPAConns(ctx, s.DB, principal)
}

// ListPAConnectionsTx is ListPAConnections inside tx: the run loop's tool
// resolver reads the connections a claim binds in the claim's own
// transaction (#1318 slice C2).
func (s *Store) ListPAConnectionsTx(ctx context.Context, tx *sql.Tx, principal int64) ([]connection.Connection, error) {
	if tx == nil {
		return nil, fmt.Errorf("%w: list: no transaction", connection.ErrUnreadable)
	}
	return listPAConns(ctx, tx, principal)
}

type paRowsQuerier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func listPAConns(ctx context.Context, q paRowsQuerier, principal int64) ([]connection.Connection, error) {
	rows, err := q.QueryContext(ctx,
		`SELECT `+paConnCols+` FROM pa_connections WHERE principal = $1 ORDER BY created_at_ms, id`, principal)
	if err != nil {
		return nil, fmt.Errorf("%w: list: %v", connection.ErrUnreadable, err)
	}
	defer func() { _ = rows.Close() }()
	out := []connection.Connection{}
	for rows.Next() {
		c, err := scanPAConn(rows, nil)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: list: %v", connection.ErrUnreadable, err)
	}
	return out, nil
}

// missOrConflict tells a compare-and-set that matched no row apart: no row
// for (principal, id) is ErrNotFound, anything else lost the race.
func missOrConflict(ctx context.Context, q paQuerier, principal int64, id string) error {
	var one int
	err := q.QueryRowContext(ctx, `SELECT 1 FROM pa_connections WHERE principal = $1 AND id = $2`, principal, id).Scan(&one)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return connection.ErrNotFound
	case err != nil:
		return fmt.Errorf("%w: %v", connection.ErrUnreadable, err)
	}
	return connection.ErrConflict
}

// paActivateAfterConsent is a test seam: when set, ActivatePAConnection
// calls it during an activation, after the principal lock and the consent
// and disable reads and before the update, inside the transaction, so a
// test can race a /consent withdraw or an admin disable against exactly
// that window. Always nil outside tests.
var paActivateAfterConsent func(principal int64)

// paSupersedeAfterRead is a test seam: it runs between a superseded row's
// read and its update.
var paSupersedeAfterRead func(id string)

// TransitionPAConnection applies t (see connection.Transition). The
// activation edge is ActivatePAConnection, with every one of its checks:
// there is no way to activate a connection that skips the consent, disable
// or supersede step. Called here, the superseded rows are revoked locally
// only; Manager.Confirm, the production path, calls ActivatePAConnection
// itself so it can also revoke their tokens at the server.
//
// active -> expired also queues the connection's "link it again" notice in
// the same transaction (jobs.OutboxConnectionExpired), once per connection:
// a connection is never re-activated, so the row is keyed on that one
// transition, and a second replica or a restart cannot send it twice.
func (s *Store) TransitionPAConnection(ctx context.Context, principal int64, id string, t connection.Transition) (connection.Connection, error) {
	if err := t.Validate(); err != nil {
		return connection.Connection{}, err
	}
	if t.From == connection.StatePendingConfirm && t.To == connection.StateActive {
		c, _, err := s.ActivatePAConnection(ctx, principal, id, t)
		return c, err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return connection.Connection{}, fmt.Errorf("pa connection transition: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	c, err := transitionPAConnTx(ctx, tx, principal, id, t)
	if err != nil {
		return connection.Connection{}, err
	}
	if t.To == connection.StateExpired {
		if err := enqueuePAOutbox(ctx, tx, jobs.OutboxItem{
			Principal: principal, Kind: jobs.OutboxConnectionExpired, ConnectionID: id,
		}, transitionAtMS(t)); err != nil {
			return connection.Connection{}, fmt.Errorf("pa connection transition: expiry notice: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return connection.Connection{}, fmt.Errorf("pa connection transition: commit: %w", err)
	}
	return c, nil
}

// ActivatePAConnection applies the activation edge (see
// connection.Store).
//
// It first takes the principal's lock, the one every webhook update takes
// before it can withdraw consent or /forget (pa.Conversations.HandleUpdate),
// and in the same transaction reads the principal's consent and its admin
// disable. Without a current, accepted consent it refuses with
// connection.ErrNoConsent; a disabled principal, or one whose disable
// cannot be read, is connection.ErrPrincipalDisabled. Either changes
// nothing. A withdraw and an activation are therefore ordered: a withdraw
// that commits first refuses the activation, and one that starts later
// waits for it.
//
// Then, still in that transaction, every other active or expired
// connection of the principal on the same server is revoked (state
// revoked, revision bumped, secrets destroyed), and returned with the
// secret material it held for remote revocation. A failed read of those
// rows fails the activation: it is never "no other connection".
//
// Like CreatePAConnection it must not be called inside a transaction that
// holds the principal lock.
func (s *Store) ActivatePAConnection(ctx context.Context, principal int64, id string, t connection.Transition) (connection.Connection, []connection.Superseded, error) {
	if err := t.Validate(); err != nil {
		return connection.Connection{}, nil, err
	}
	if t.From != connection.StatePendingConfirm || t.To != connection.StateActive {
		return connection.Connection{}, nil, fmt.Errorf("%w: not the activation edge", connection.ErrInvalidTransition)
	}
	// Read before the transaction: on SQLite the pool has one connection,
	// which the transaction then holds. An unresolved dialect is not taken
	// for SQLite: on Postgres that would drop the supersede row lock.
	pg, resolved := s.resolveDialect(ctx)
	if !resolved {
		return connection.Connection{}, nil, fmt.Errorf("%w: activation: database dialect unknown", connection.ErrUnreadable)
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return connection.Connection{}, nil, fmt.Errorf("pa connection activation: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := s.activationAdmitted(ctx, tx, principal); err != nil {
		return connection.Connection{}, nil, err
	}
	c, err := transitionPAConnTx(ctx, tx, principal, id, t)
	if err != nil {
		return connection.Connection{}, nil, err
	}
	superseded, err := supersedePAConns(ctx, tx, c, transitionAtMS(t), pg)
	if err != nil {
		return connection.Connection{}, nil, err
	}
	if err := tx.Commit(); err != nil {
		return connection.Connection{}, nil, fmt.Errorf("pa connection activation: commit: %w", err)
	}
	return c, superseded, nil
}

func transitionAtMS(t connection.Transition) int64 {
	if !t.At.IsZero() {
		return t.At.UTC().UnixMilli()
	}
	return time.Now().UTC().UnixMilli()
}

// transitionPAConnTx is the compare-and-set of a transition in tx.
func transitionPAConnTx(ctx context.Context, tx *sql.Tx, principal int64, id string, t connection.Transition) (connection.Connection, error) {
	set := `state = $1, authority_revision = authority_revision + 1, updated_at_ms = $2,
		refresh_lease_owner = '', refresh_lease_until_ms = 0`
	args := []any{string(t.To), transitionAtMS(t), principal, id, string(t.From), t.ExpectRevision}
	switch {
	case t.To == connection.StatePendingReturn:
		set += `, sealed_code = $7`
		args = append(args, t.SealedCode)
	case t.To == connection.StatePendingConfirm:
		set += `, account_id = $7, granted_scope = $8, sealed_tokens = $9, sealed_code = NULL`
		args = append(args, t.AccountID, t.GrantedScope, t.SealedTokens)
	case t.To.WipesSecrets():
		set += `, wrapped_dek = NULL, sealed_code = NULL, sealed_tokens = NULL, failure_reason = $7`
		args = append(args, t.Reason)
	}
	res, err := tx.ExecContext(ctx, `UPDATE pa_connections SET `+set+`
		WHERE principal = $3 AND id = $4 AND state = $5 AND authority_revision = $6`, args...)
	if err != nil {
		return connection.Connection{}, fmt.Errorf("pa connection transition: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return connection.Connection{}, fmt.Errorf("pa connection transition: rows affected: %w", err)
	}
	if n != 1 {
		return connection.Connection{}, missOrConflict(ctx, tx, principal, id)
	}
	// Every transition bumps the revision, so every transition revokes the
	// standing permissions bound to the connection, in this transaction
	// (threat model T7, S2-A9).
	if err := revokePAPermissionsOfConnTx(ctx, tx, principal, id, transitionAtMS(t)); err != nil {
		return connection.Connection{}, err
	}
	// So does every approval bound to it that was not dispatched (T2
	// "/disconnect" step 4, S2-C9), with one notice when there was any.
	if err := cancelPAApprovalsOfConnTx(ctx, tx, principal, id, transitionAtMS(t)); err != nil {
		return connection.Connection{}, err
	}
	return getPAConn(ctx, tx, principal, id, nil)
}

// supersedePAConns revokes, in tx, every active or expired connection of
// c's principal on c's server other than c, and returns them as they were.
//
// The principal lock does not keep these rows still: a refresh flight's
// RotatePAConnectionTokens, and the transitions it and the dispatcher make
// (active -> expired on invalid_grant, revoked on reuse), write a row
// without taking it. So the rows themselves are locked before they are
// read. On Postgres that is SELECT ... FOR UPDATE: a rotation or
// transition that commits first is what the read sees (read committed
// re-checks the row); one that comes later waits for this transaction,
// then misses its CAS on the revoked row, and refresh revokes what it was
// issued. Without the lock, a rotation committing between the read and
// the update would have its fresh tokens wiped while Before held the old
// ones, orphaning the live pair at the server. On SQLite this transaction
// already holds the database write lock (the principal lock and the
// activation are writes), so no other writer commits in between.
func supersedePAConns(ctx context.Context, tx *sql.Tx, c connection.Connection, nowMS int64, pg bool) ([]connection.Superseded, error) {
	lock := ""
	if pg {
		lock = " FOR UPDATE"
	}
	rows, err := tx.QueryContext(ctx, `SELECT id FROM pa_connections
		WHERE principal = $1 AND server = $2 AND id <> $3 AND state IN ($4, $5) ORDER BY created_at_ms, id`+lock,
		c.Principal, string(c.Server), c.ID, string(connection.StateActive), string(connection.StateExpired))
	if err != nil {
		return nil, fmt.Errorf("%w: superseded connections: %v", connection.ErrUnreadable, err)
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("%w: superseded connections: %v", connection.ErrUnreadable, err)
		}
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("%w: superseded connections: %v", connection.ErrUnreadable, err)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: superseded connections: %v", connection.ErrUnreadable, err)
	}
	var out []connection.Superseded
	for _, id := range ids {
		var before connection.Sealed
		cur, err := getPAConn(ctx, tx, c.Principal, id, &before)
		if err != nil {
			return nil, err
		}
		if paSupersedeAfterRead != nil {
			paSupersedeAfterRead(id)
		}
		if _, err := transitionPAConnTx(ctx, tx, c.Principal, id, connection.Transition{
			From: cur.State, To: connection.StateRevoked, ExpectRevision: cur.AuthorityRevision,
			Reason: "superseded", At: time.UnixMilli(nowMS),
		}); err != nil {
			return nil, fmt.Errorf("pa connection activation: supersede: %w", err)
		}
		out = append(out, connection.Superseded{Connection: cur, Before: before})
	}
	return out, nil
}

// activationAdmitted takes principal's lock in tx and requires its current
// consent and that it is not disabled (see ActivatePAConnection).
func (s *Store) activationAdmitted(ctx context.Context, tx *sql.Tx, principal int64) error {
	if err := s.LockPAPrincipal(ctx, tx, principal); err != nil {
		return fmt.Errorf("pa connection activation: %w", err)
	}
	rec, err := s.GetPAConsent(ctx, tx, principal)
	switch {
	case errors.Is(err, convo.ErrNotFound):
		return connection.ErrNoConsent
	case err != nil:
		return fmt.Errorf("%w: consent unreadable: %w", connection.ErrNoConsent, err)
	case !convo.Satisfied(rec):
		return connection.ErrNoConsent
	}
	disabled, err := s.PAPrincipalDisabled(ctx, tx, principal)
	switch {
	case err != nil:
		return fmt.Errorf("%w: disable unreadable: %w", connection.ErrPrincipalDisabled, err)
	case disabled:
		return connection.ErrPrincipalDisabled
	}
	if paActivateAfterConsent != nil {
		paActivateAfterConsent(principal)
	}
	return nil
}

// paRevokeAfterRead is a test seam: when set, revokePAConnOnce calls it
// between its read and its compare-and-set update, inside the transaction,
// so a test can land a rotation in exactly that window. It is nil outside
// tests.
var paRevokeAfterRead func(ctx context.Context, tx *sql.Tx)

// RevokePAConnection revokes the row from any state (see connection.Store).
func (s *Store) RevokePAConnection(ctx context.Context, principal int64, id, reason string) (connection.Connection, connection.Sealed, bool, error) {
	for attempt := 0; attempt < 5; attempt++ {
		c, before, already, err := s.revokePAConnOnce(ctx, principal, id, reason)
		if errors.Is(err, connection.ErrConflict) {
			continue
		}
		return c, before, already, err
	}
	return connection.Connection{}, connection.Sealed{}, false, connection.ErrConflict
}

func (s *Store) revokePAConnOnce(ctx context.Context, principal int64, id, reason string) (connection.Connection, connection.Sealed, bool, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return connection.Connection{}, connection.Sealed{}, false, fmt.Errorf("pa connection revoke: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	// The CAS below also pins token_generation: a rotation committed between
	// this read and the update would otherwise leave `before` holding the
	// superseded tokens, and the caller would revoke those remotely while the
	// live ones were wiped locally and never revoked.
	var before connection.Sealed
	cur, err := getPAConn(ctx, tx, principal, id, &before)
	if err != nil {
		return connection.Connection{}, connection.Sealed{}, false, err
	}
	if cur.State == connection.StateRevoked {
		return cur, connection.Sealed{}, true, nil
	}
	if paRevokeAfterRead != nil {
		paRevokeAfterRead(ctx, tx)
	}
	res, err := tx.ExecContext(ctx, `UPDATE pa_connections
		SET state = $1, authority_revision = authority_revision + 1, updated_at_ms = $2,
			wrapped_dek = NULL, sealed_code = NULL, sealed_tokens = NULL, failure_reason = $3,
			refresh_lease_owner = '', refresh_lease_until_ms = 0
		WHERE principal = $4 AND id = $5 AND state = $6 AND authority_revision = $7
		  AND token_generation = $8`,
		string(connection.StateRevoked), time.Now().UTC().UnixMilli(), reason,
		principal, id, string(cur.State), cur.AuthorityRevision, cur.TokenGeneration)
	if err != nil {
		return connection.Connection{}, connection.Sealed{}, false, fmt.Errorf("pa connection revoke: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return connection.Connection{}, connection.Sealed{}, false, fmt.Errorf("pa connection revoke: rows affected: %w", err)
	}
	if n != 1 {
		return connection.Connection{}, connection.Sealed{}, false, connection.ErrConflict
	}
	nowMS := time.Now().UTC().UnixMilli()
	if err := revokePAPermissionsOfConnTx(ctx, tx, principal, id, nowMS); err != nil {
		return connection.Connection{}, connection.Sealed{}, false, err
	}
	// /disconnect step 4 (threat model T2, S2-C9): the approvals bound to
	// the connection that were not dispatched are cancelled in the
	// transaction that revokes it, and the principal is told once.
	if err := cancelPAApprovalsOfConnTx(ctx, tx, principal, id, nowMS); err != nil {
		return connection.Connection{}, connection.Sealed{}, false, err
	}
	c, err := getPAConn(ctx, tx, principal, id, nil)
	if err != nil {
		return connection.Connection{}, connection.Sealed{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return connection.Connection{}, connection.Sealed{}, false, fmt.Errorf("pa connection revoke: commit: %w", err)
	}
	return c, before, false, nil
}

// RevokePAConnectionAt implements connection.Store: the revocation of
// RevokePAConnection for the row version the caller read, with no retry. A
// row that moved on, or was already revoked, is ErrConflict; a missing row
// is ErrNotFound.
func (s *Store) RevokePAConnectionAt(ctx context.Context, principal int64, id string, revision, generation int64, reason string) (connection.Connection, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return connection.Connection{}, fmt.Errorf("pa connection revoke: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `UPDATE pa_connections
		SET state = $1, authority_revision = authority_revision + 1, updated_at_ms = $2,
			wrapped_dek = NULL, sealed_code = NULL, sealed_tokens = NULL, failure_reason = $3,
			refresh_lease_owner = '', refresh_lease_until_ms = 0
		WHERE principal = $4 AND id = $5 AND state <> $1 AND authority_revision = $6
		  AND token_generation = $7`,
		string(connection.StateRevoked), time.Now().UTC().UnixMilli(), reason,
		principal, id, revision, generation)
	if err != nil {
		return connection.Connection{}, fmt.Errorf("pa connection revoke: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return connection.Connection{}, fmt.Errorf("pa connection revoke: rows affected: %w", err)
	}
	if n != 1 {
		if _, err := getPAConn(ctx, tx, principal, id, nil); err != nil {
			return connection.Connection{}, err
		}
		return connection.Connection{}, connection.ErrConflict
	}
	nowMS := time.Now().UTC().UnixMilli()
	if err := revokePAPermissionsOfConnTx(ctx, tx, principal, id, nowMS); err != nil {
		return connection.Connection{}, err
	}
	if err := cancelPAApprovalsOfConnTx(ctx, tx, principal, id, nowMS); err != nil {
		return connection.Connection{}, err
	}
	c, err := getPAConn(ctx, tx, principal, id, nil)
	if err != nil {
		return connection.Connection{}, err
	}
	if err := tx.Commit(); err != nil {
		return connection.Connection{}, fmt.Errorf("pa connection revoke: commit: %w", err)
	}
	return c, nil
}

// ClaimPAConnectionRefresh takes the refresh lease (see connection.Store).
func (s *Store) ClaimPAConnectionRefresh(ctx context.Context, principal int64, id string, generation int64, owner string, now, until time.Time) (bool, error) {
	if owner == "" || !until.After(now) {
		return false, errors.New("pa connection: refresh lease needs an owner and a future expiry")
	}
	res, err := s.DB.ExecContext(ctx, `UPDATE pa_connections
		SET refresh_lease_owner = $1, refresh_lease_until_ms = $2
		WHERE principal = $3 AND id = $4 AND state = $5 AND token_generation = $6
		  AND refresh_lease_until_ms <= $7`,
		owner, until.UnixMilli(), principal, id, string(connection.StateActive), generation, now.UnixMilli())
	if err != nil {
		return false, fmt.Errorf("pa connection refresh lease: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("pa connection refresh lease: rows affected: %w", err)
	}
	return n == 1, nil
}

// ReleasePAConnectionRefresh drops owner's lease.
func (s *Store) ReleasePAConnectionRefresh(ctx context.Context, principal int64, id, owner string) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE pa_connections
		SET refresh_lease_owner = '', refresh_lease_until_ms = 0
		WHERE principal = $1 AND id = $2 AND refresh_lease_owner = $3`, principal, id, owner)
	if err != nil {
		return fmt.Errorf("pa connection refresh release: %w", err)
	}
	return nil
}

// RotatePAConnectionTokens applies r (see connection.Rotation).
func (s *Store) RotatePAConnectionTokens(ctx context.Context, principal int64, id string, r connection.Rotation) (connection.Connection, error) {
	if len(r.SealedTokens) == 0 || r.LeaseOwner == "" || r.GrantedScope == "" || r.Now.IsZero() {
		return connection.Connection{}, fmt.Errorf("%w: rotation needs tokens, a lease owner, the granted scope and the lease clock", connection.ErrInvalidTransition)
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return connection.Connection{}, fmt.Errorf("pa connection rotate: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `UPDATE pa_connections
		SET sealed_tokens = $1, token_generation = token_generation + 1, updated_at_ms = $2,
			refresh_lease_owner = '', refresh_lease_until_ms = 0
		WHERE principal = $3 AND id = $4 AND state = $5 AND authority_revision = $6
		  AND token_generation = $7 AND granted_scope = $8 AND refresh_lease_owner = $9
		  AND refresh_lease_until_ms > $10`,
		r.SealedTokens, time.Now().UTC().UnixMilli(), principal, id, string(connection.StateActive),
		r.ExpectRevision, r.ExpectGeneration, r.GrantedScope, r.LeaseOwner, r.Now.UnixMilli())
	if err != nil {
		return connection.Connection{}, fmt.Errorf("pa connection rotate: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return connection.Connection{}, fmt.Errorf("pa connection rotate: rows affected: %w", err)
	}
	if n != 1 {
		return connection.Connection{}, missOrConflict(ctx, tx, principal, id)
	}
	c, err := getPAConn(ctx, tx, principal, id, nil)
	if err != nil {
		return connection.Connection{}, err
	}
	if err := tx.Commit(); err != nil {
		return connection.Connection{}, fmt.Errorf("pa connection rotate: commit: %w", err)
	}
	return c, nil
}

// StalePAConnection identifies a pending connection for the stale sweep.
type StalePAConnection struct {
	Principal         int64
	ID                string
	AuthorityRevision int64
}

// StalePendingPAConnections lists up to limit connections still in a
// pending_* state whose last transition is at or before updatedBefore,
// oldest first. Linking never leaves a connection in one pending state for
// longer than that step's secret lives, so such a row was stranded (for
// example a store error after a secret was consumed). The linking sweeper
// fails it and revokes whatever tokens it holds.
func (s *Store) StalePendingPAConnections(ctx context.Context, updatedBefore time.Time, limit int) ([]StalePAConnection, error) {
	if limit <= 0 {
		return nil, errors.New("pa connection: stale listing needs a positive limit")
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT principal, id, authority_revision FROM pa_connections
		WHERE state IN ($1, $2, $3, $4) AND updated_at_ms <= $5
		ORDER BY updated_at_ms, id LIMIT $6`,
		string(connection.StatePendingLink), string(connection.StatePendingOAuth),
		string(connection.StatePendingReturn), string(connection.StatePendingConfirm),
		updatedBefore.UnixMilli(), limit)
	if err != nil {
		return nil, fmt.Errorf("pa connection: list stale: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []StalePAConnection{}
	for rows.Next() {
		var c StalePAConnection
		if err := rows.Scan(&c.Principal, &c.ID, &c.AuthorityRevision); err != nil {
			return nil, fmt.Errorf("pa connection: list stale: scan: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("pa connection: list stale: %w", err)
	}
	return out, nil
}
