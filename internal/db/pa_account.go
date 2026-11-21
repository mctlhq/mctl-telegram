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
	"time"

	"github.com/mctlhq/mctl-telegram/internal/pa/jobs"
)

// ErrPAConnectionsNeedRevocation refuses an account deletion while a PA
// connection of the account still holds provider tokens. Deleting the row
// would wipe them locally and leave them live at the provider; revoking
// them needs the connection Manager and an outbound call (#1314), which
// account deletion does not make yet. No environment runs the linking flow,
// so no such row exists today; wiring linking must add the revocation
// before this can be reached.
var ErrPAConnectionsNeedRevocation = errors.New("delete account: a personal assistant connection still holds provider tokens")

// paPrincipalPurges are the deletes of purgePAPrincipals, in order. Each
// takes the principal as $1. Not purged:
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
	{"pa_connections", `DELETE FROM pa_connections WHERE principal = $1`},
	{"pa_principal_locks", `DELETE FROM pa_principal_locks WHERE principal = $1`},
}

// purgePAPrincipals deletes the Personal Assistant state of every principal
// in tgIDs inside the account deletion's transaction. Any failed statement
// fails the deletion, which rolls back as a whole.
//
// Per principal it first refuses, with ErrPAConnectionsNeedRevocation, a
// connection that holds provider tokens (see that error). It then takes the
// principal lock, as a webhook update and a job claim do before touching
// the principal's state, so a concurrent update or claim of that principal
// runs wholly before or wholly after the purge. A job claimed by a worker
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
	for _, p := range tgIDs {
		var holding int
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM pa_connections WHERE principal = $1 AND sealed_tokens IS NOT NULL`, p,
		).Scan(&holding); err != nil {
			return fmt.Errorf("delete account: read pa connections: %w", err)
		}
		if holding > 0 {
			// TODO(#1314): revoke these tokens at the provider, then delete.
			return ErrPAConnectionsNeedRevocation
		}
		now := time.Now().UnixMilli()
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO pa_principal_locks(principal, locked_at_ms) VALUES($1, $2)
			 ON CONFLICT (principal) DO UPDATE SET locked_at_ms = excluded.locked_at_ms`, p, now); err != nil {
			return fmt.Errorf("delete account: lock pa principal: %w", err)
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
	}
	return nil
}
