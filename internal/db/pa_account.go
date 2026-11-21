package db

// pa_account.go removes a principal's Personal Assistant state when the
// account is deleted (#1338). Every PA table is keyed by the principal's
// Telegram id and none has a foreign key, so HardDeleteAccount calls
// purgePAPrincipals for each Telegram id the account carries.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/pa/jobs"
)

// ErrPAConnectionsNeedRevocation refuses an account deletion while a PA
// connection of the account still holds provider tokens. Deleting the row
// would wipe them locally and leave them live at the provider.
// DeleteAccountRevokingPA revokes them first and returns it, joined with the
// cause, for a connection whose revocation failed; HardDeleteAccount returns
// it for a connection that holds tokens when the purge runs.
var ErrPAConnectionsNeedRevocation = errors.New("delete account: a personal assistant connection still holds provider tokens")

// PAConnectionsNeedRevocationMessage is what the account deletion surfaces
// (web and MCP) tell the user when ErrPAConnectionsNeedRevocation refuses
// it. It names what to do; the cause stays in the server log.
const PAConnectionsNeedRevocationMessage = "the account was not deleted: a service linked to your personal assistant could not be disconnected. Disconnect or revoke your linked services first, then delete the account again"

// PATokenRevoker revokes, at the provider and then locally, every
// connection of a principal that holds provider tokens.
// (*connection.Manager).RevokeHeldTokens implements it.
type PATokenRevoker interface {
	RevokeHeldTokens(ctx context.Context, principal int64) error
}

// DeleteAccountRevokingPA is HardDeleteAccount for a server that runs the
// linking flow: before the deletion's transaction it revokes the provider
// tokens of every PA connection of the account's Telegram ids through r, so
// the purge finds none left to strand (#1338). A principal whose revocation
// fails, or whose Telegram ids cannot be read, refuses the whole deletion
// with ErrPAConnectionsNeedRevocation joined with the cause; nothing is
// deleted, the connection keeps its row and sealed tokens, and the user can
// retry. Connections already revoked on the way stay revoked.
//
// The revocation needs outbound calls, so it cannot run inside the
// deletion's transaction. A connection that gains tokens after it, before
// the purge, is caught by the purge's own check in the transaction
// (ErrPAConnectionsNeedRevocation again), and a Begin admitted before the
// purge cannot create a row after it (CreatePAConnection).
func (s *Store) DeleteAccountRevokingPA(ctx context.Context, userID int64, r PATokenRevoker) (int64, error) {
	if r == nil {
		return 0, errors.New("delete account: no pa token revoker")
	}
	tgIDs, err := s.accountTelegramIDs(ctx, userID)
	if err != nil {
		return 0, errors.Join(ErrPAConnectionsNeedRevocation, err)
	}
	for _, p := range slices.Sorted(slices.Values(tgIDs)) {
		if err := r.RevokeHeldTokens(ctx, p); err != nil {
			return 0, errors.Join(ErrPAConnectionsNeedRevocation, err)
		}
	}
	return s.HardDeleteAccount(ctx, userID)
}

// accountTelegramIDs is userTelegramIDs outside the deletion's transaction.
func (s *Store) accountTelegramIDs(ctx context.Context, userID int64) ([]int64, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("delete account: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	return userTelegramIDs(ctx, tx, userID)
}

// paPrincipalPurges are the deletes of purgePAPrincipals, in order. Each
// takes the principal as $1. Not purged:
//   - pa_principal_locks, when the row already existed: it stays, with its
//     purged_at_ms deletion mark raised, so a linking Begin admitted before
//     the deletion cannot create a connection after it (CreatePAConnection).
//     It carries the principal and two timestamps, and the PA lock sweep
//     deletes it once unused for pa.UpdatesRetention. A row the purge had
//     to create only to take the lock is deleted again before commit: no
//     Begin can be in flight for a principal without a lock row, because
//     admission writes one (AdmitPAConnection), so with the PA off (no
//     sweep running) an account deletion leaves no row behind;
//   - pa_usage and pa_rate, the spend ledger and the message rate window
//     behind the PA's caps: deleting them would let a delete-and-return
//     reset the caps. They carry the principal, amounts and counts, no
//     content, and the sweep deletes them (pa_usage after
//     PAUsageRetention, pa_rate after the dedup window);
//   - pa_updates and pa_update_failures, keyed by update id only, with no
//     principal or content.
var paPrincipalPurges = []struct{ table, q string }{
	{"pa_outbox", `DELETE FROM pa_outbox WHERE principal = $1`},
	{"pa_jobs", `DELETE FROM pa_jobs WHERE principal = $1`},
	{"pa_callbacks", `DELETE FROM pa_callbacks WHERE principal = $1`},
	{"pa_fragments", `DELETE FROM pa_fragments WHERE principal = $1`},
	{"pa_conversations", `DELETE FROM pa_conversations WHERE principal = $1`},
	{"pa_consents", `DELETE FROM pa_consents WHERE principal = $1`},
	{"pa_link_secrets", `DELETE FROM pa_link_secrets WHERE principal = $1`},
	// Only rows without provider tokens; see purgePAPrincipals.
	{"pa_connections", `DELETE FROM pa_connections WHERE principal = $1 AND sealed_tokens IS NULL`},
}

// purgePAPrincipals deletes the Personal Assistant state of every principal
// in tgIDs inside the account deletion's transaction. Any failed statement
// fails the deletion, which rolls back as a whole.
//
// Principals are taken in ascending order, so two deletions that share
// Telegram ids take their principal locks in one order and cannot deadlock
// on them. Per principal it first takes the principal lock, as a webhook
// update and a job claim do before touching the principal's state, so a
// concurrent update or claim of that principal runs wholly before or
// wholly after the purge.
//
// A connection that holds provider tokens is never deleted, and its
// presence refuses the deletion (ErrPAConnectionsNeedRevocation). The rule
// sits in the DELETE predicate itself rather than in a read before it, so
// no check-then-act window exists: on Postgres a row another transaction
// is writing is re-checked against the predicate once that write commits,
// and SQLite runs one writer at a time. A count after the delete, in the
// same transaction, then finds any token-holding row (one that held tokens
// all along or gained them meanwhile) and fails the deletion, which rolls
// back the whole purge. A failed count fails it too: tokens that could not
// be observed are not absent. A job claimed by a worker
// at that moment loses its row: the worker's next step under the lock
// (turn, tool call, finish) finds no job and stops, so it writes no reply.
// Its reservation, like every reserved pa_usage row of the principal, is
// held at the full amount, since a model call may have been made; the
// sweep would never delete a row left reserved. An outbox row being sent
// loses its row too: completion finds it gone (ErrOutboxStale) and the row
// is never retried; a part that already reached Telegram stays there.
//
// A Telegram id shared with another user loses that user's PA state too,
// the same accepted over-reach as the worker-token revocation: it is the
// same person.
func purgePAPrincipals(ctx context.Context, tx *sql.Tx, tgIDs []int64) error {
	for _, p := range slices.Sorted(slices.Values(tgIDs)) {
		now := time.Now().UnixMilli()
		created, err := lockPAPrincipalForPurge(ctx, tx, p, now)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE pa_usage SET status = $1, updated_at_ms = $2 WHERE principal = $3 AND status = $4`,
			jobs.UsageHeld, now, p, jobs.UsageReserved); err != nil {
			return fmt.Errorf("delete account: hold pa usage: %w", err)
		}
		for _, st := range paPrincipalPurges {
			if _, err := tx.ExecContext(ctx, st.q, p); err != nil {
				return fmt.Errorf("delete account: purge %s: %w", st.table, err)
			}
		}
		if paPurgeAfterDelete != nil {
			paPurgeAfterDelete(ctx, tx, p)
		}
		var holding int
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM pa_connections WHERE principal = $1 AND sealed_tokens IS NOT NULL`, p,
		).Scan(&holding); err != nil {
			return fmt.Errorf("delete account: read pa connections: %w", err)
		}
		if holding > 0 {
			// DeleteAccountRevokingPA revokes them before this transaction;
			// these gained tokens after that, or the caller did not revoke.
			return ErrPAConnectionsNeedRevocation
		}
		if created {
			if _, err := tx.ExecContext(ctx, `DELETE FROM pa_principal_locks WHERE principal = $1`, p); err != nil {
				return fmt.Errorf("delete account: release pa principal lock: %w", err)
			}
		}
	}
	return nil
}

// lockPAPrincipalForPurge takes principal's lock for the purge. On an
// existing row it raises the deletion mark in the same statement: the mark
// strictly grows, even for two deletions in the same millisecond, so a Begin
// admitted between them still sees it move. Without a row it inserts one
// only to hold the lock and reports created, and the purge deletes it
// again. An insert that loses to a concurrent admission (DO NOTHING waits
// for it on Postgres) goes back to the update, so an admitted Begin's row
// always gets the mark.
func lockPAPrincipalForPurge(ctx context.Context, tx *sql.Tx, principal, now int64) (created bool, err error) {
	for range 2 {
		res, err := tx.ExecContext(ctx,
			`UPDATE pa_principal_locks SET locked_at_ms = $2,
				purged_at_ms = CASE WHEN purged_at_ms >= $2 THEN purged_at_ms + 1 ELSE $2 END
			 WHERE principal = $1`, principal, now)
		if err != nil {
			return false, fmt.Errorf("delete account: lock pa principal: %w", err)
		}
		if n, err := res.RowsAffected(); err != nil {
			return false, fmt.Errorf("delete account: lock pa principal: %w", err)
		} else if n == 1 {
			return false, nil
		}
		res, err = tx.ExecContext(ctx,
			`INSERT INTO pa_principal_locks(principal, locked_at_ms) VALUES($1, $2) ON CONFLICT (principal) DO NOTHING`,
			principal, now)
		if err != nil {
			return false, fmt.Errorf("delete account: lock pa principal: %w", err)
		}
		if n, err := res.RowsAffected(); err != nil {
			return false, fmt.Errorf("delete account: lock pa principal: %w", err)
		} else if n == 1 {
			return true, nil
		}
	}
	return false, errors.New("delete account: lock pa principal: the lock row kept changing")
}

// paPurgeAfterDelete is a test seam: it runs inside purgePAPrincipals'
// transaction after a principal's deletes and before the token count, so a
// test can stand in for a row that gains tokens in that window. Always nil
// outside tests.
var paPurgeAfterDelete func(ctx context.Context, tx *sql.Tx, principal int64)
