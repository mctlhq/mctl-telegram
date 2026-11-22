package db

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
	"github.com/mctlhq/mctl-telegram/internal/pa/jobs"
)

// The connection expiry notice and the activation supersede (#1318 slice
// C2b), at the store.

func paExpiryNotices(t *testing.T, s *Store, principal int64) []string {
	t.Helper()
	rows, err := s.PAOutboxRows(context.Background(), principal)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, r := range rows {
		if r.Kind == jobs.OutboxConnectionExpired {
			if !r.Valid() {
				t.Fatalf("expiry row %+v does not validate", r)
			}
			ids = append(ids, r.ConnectionID)
		}
	}
	return ids
}

func activatePAConn(t *testing.T, s *Store, principal int64, id string) connection.Connection {
	t.Helper()
	c, err := s.TransitionPAConnection(context.Background(), principal, id, connection.Transition{
		From: connection.StatePendingConfirm, To: connection.StateActive, ExpectRevision: 4})
	if err != nil {
		t.Fatalf("activate %s: %v", id, err)
	}
	return c
}

func expirePAConn(t *testing.T, s *Store, principal int64, c connection.Connection) {
	t.Helper()
	if _, err := s.TransitionPAConnection(context.Background(), principal, c.ID, connection.Transition{
		From: connection.StateActive, To: connection.StateExpired, ExpectRevision: c.AuthorityRevision, Reason: "invalid_grant"}); err != nil {
		t.Fatalf("expire %s: %v", c.ID, err)
	}
}

// Each active -> expired transition queues exactly one notice for its
// connection, in its transaction; another state change queues none, and a
// second enqueue of the same transition is a no-op by the key.
func TestTransitionPAConnection_ExpiryQueuesOneNoticePerConnection(t *testing.T) {
	paLinkDialects(t, func(t *testing.T, s *Store) {
		ctx := context.Background()
		p := paLinkPrincipal(t, s)
		acceptConsent(t, s, p)
		t.Cleanup(func() {
			_, _ = s.DB.Exec(`DELETE FROM pa_outbox WHERE principal = $1`, p)
			_, _ = s.DB.Exec(`DELETE FROM pa_connections WHERE principal = $1`, p)
		})
		a := activatePAConn(t, s, p, seedPAConnectionWithTokens(t, s, p))
		if n := paExpiryNotices(t, s, p); len(n) != 0 {
			t.Fatalf("notices after activation: %v", n)
		}
		expirePAConn(t, s, p, a)
		if got := paExpiryNotices(t, s, p); !slices.Equal(got, []string{a.ID}) {
			t.Fatalf("notices %v, want one for %s", got, a.ID)
		}
		// The same transition queued again (a retried commit, another
		// replica): still one row.
		tx, err := s.DB.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := enqueuePAOutbox(ctx, tx, jobs.OutboxItem{Principal: p, Kind: jobs.OutboxConnectionExpired, ConnectionID: a.ID}, 1); err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		// A reconnect supersedes the expired row (revoked: no notice), and
		// the new connection expiring is its own notice.
		b := activatePAConn(t, s, p, seedPAConnectionWithTokens(t, s, p))
		got, err := s.GetPAConnection(ctx, p, a.ID)
		if err != nil || got.State != connection.StateRevoked {
			t.Fatalf("expired row after a reconnect: %s (%v), want revoked", got.State, err)
		}
		expirePAConn(t, s, p, b)
		if got := paExpiryNotices(t, s, p); !slices.Equal(got, []string{a.ID, b.ID}) {
			t.Fatalf("notices %v, want exactly one each for %s and %s", got, a.ID, b.ID)
		}
	})
}

// An activation leaves the principal one active-or-expired connection per
// server, and returns the superseded rows with their sealed material.
func TestActivatePAConnection_SupersedesSameServer(t *testing.T) {
	paLinkDialects(t, func(t *testing.T, s *Store) {
		ctx := context.Background()
		p := paLinkPrincipal(t, s)
		acceptConsent(t, s, p)
		t.Cleanup(func() { _, _ = s.DB.Exec(`DELETE FROM pa_connections WHERE principal = $1`, p) })
		first := activatePAConn(t, s, p, seedPAConnectionWithTokens(t, s, p))
		second := seedPAConnectionWithTokens(t, s, p)
		c, sup, err := s.ActivatePAConnection(ctx, p, second, connection.Transition{
			From: connection.StatePendingConfirm, To: connection.StateActive, ExpectRevision: 4})
		if err != nil {
			t.Fatal(err)
		}
		if c.State != connection.StateActive || len(sup) != 1 || sup[0].Connection.ID != first.ID ||
			sup[0].Connection.State != connection.StateActive || string(sup[0].Before.SealedTokens) != "tokens" {
			t.Fatalf("activation %+v superseded %+v", c, sup)
		}
		got, _, err := s.GetPAConnectionSealed(ctx, p, first.ID)
		if err != nil || got.State != connection.StateRevoked || got.AuthorityRevision <= first.AuthorityRevision {
			t.Fatalf("superseded row: %+v (%v), want revoked with a new revision", got, err)
		}
		_, sealed, _ := s.GetPAConnectionSealed(ctx, p, first.ID)
		if len(sealed.SealedTokens) != 0 || len(sealed.WrappedDEK) != 0 {
			t.Fatal("superseded row kept its secrets")
		}
	})
}

// Activation refuses a disabled principal in its transaction and changes
// nothing.
func TestActivatePAConnection_DisabledRefused(t *testing.T) {
	paLinkDialects(t, func(t *testing.T, s *Store) {
		ctx := context.Background()
		p := paLinkPrincipal(t, s)
		acceptConsent(t, s, p)
		t.Cleanup(func() {
			_, _ = s.DB.Exec(`DELETE FROM pa_connections WHERE principal = $1`, p)
			_ = s.ClearPAPrincipalDisabled(context.Background(), p)
		})
		live := activatePAConn(t, s, p, seedPAConnectionWithTokens(t, s, p))
		id := seedPAConnectionWithTokens(t, s, p)
		if err := s.SetPAPrincipalDisabled(ctx, p, 4242001, "test", time.Now()); err != nil {
			t.Fatal(err)
		}
		_, _, err := s.ActivatePAConnection(ctx, p, id, connection.Transition{
			From: connection.StatePendingConfirm, To: connection.StateActive, ExpectRevision: 4})
		if !errors.Is(err, connection.ErrPrincipalDisabled) {
			t.Fatalf("err %v, want ErrPrincipalDisabled", err)
		}
		if got, _ := s.GetPAConnection(ctx, p, id); got.State != connection.StatePendingConfirm {
			t.Fatalf("refused activation moved the row to %s", got.State)
		}
		if got, _ := s.GetPAConnection(ctx, p, live.ID); got.State != connection.StateActive {
			t.Fatalf("refused activation superseded the live row: %s", got.State)
		}
	})
}

// paOutboxIndexNames lists pa_outbox's index names.
func paOutboxIndexNames(t *testing.T, s *Store, pg bool) []string {
	t.Helper()
	q := `SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'pa_outbox'`
	if pg {
		q = `SELECT indexname FROM pg_indexes WHERE tablename = 'pa_outbox'`
	}
	rows, err := s.DB.Query(q)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		out = append(out, n)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// A database from before the connection-level kind is migrated in place:
// the column is added, the update key is replaced by one that leaves
// connection rows out, and a conversation-level row keeps its key.
// Postgres is only re-migrated (its database is shared with other test
// packages, so its table is not rewound); SQLite is rewound to the old
// shape first.
func TestMigratePAOutbox_ConnectionLevel(t *testing.T) {
	paLinkDialects(t, func(t *testing.T, s *Store) {
		ctx := context.Background()
		pg := s.isPostgres(ctx)
		if !pg {
			for _, q := range []string{
				`DROP INDEX idx_pa_outbox_update_v2`,
				`DROP INDEX idx_pa_outbox_connection`,
				`ALTER TABLE pa_outbox DROP COLUMN connection_id`,
				`CREATE UNIQUE INDEX idx_pa_outbox_update ON pa_outbox(principal, update_id, kind) WHERE job_id IS NULL`,
			} {
				if _, err := s.DB.Exec(q); err != nil {
					t.Fatalf("%s: %v", q, err)
				}
			}
		}
		if err := Migrate(ctx, s.DB); err != nil {
			t.Fatalf("migrate: %v", err)
		}
		idx := paOutboxIndexNames(t, s, pg)
		if slices.Contains(idx, "idx_pa_outbox_update") || !slices.Contains(idx, "idx_pa_outbox_update_v2") ||
			!slices.Contains(idx, "idx_pa_outbox_connection") {
			t.Fatalf("indexes %v", idx)
		}
		p := paLinkPrincipal(t, s)
		t.Cleanup(func() { _, _ = s.DB.Exec(`DELETE FROM pa_outbox WHERE principal = $1`, p) })
		// A conversation-level row and two connection rows of the same
		// principal (both with update id 0) each keep their own key; a
		// connection row queued twice is still one row. (A second
		// conversation-level row for the same update is an error by
		// design, ErrReplyExists, so it is queued once.)
		for _, it := range []jobs.OutboxItem{
			{Principal: p, Kind: jobs.OutboxForgotten, UpdateID: 7},
			{Principal: p, Kind: jobs.OutboxConnectionExpired, ConnectionID: "pac_a"},
			{Principal: p, Kind: jobs.OutboxConnectionExpired, ConnectionID: "pac_b"},
			{Principal: p, Kind: jobs.OutboxConnectionExpired, ConnectionID: "pac_a"},
			{Principal: p, Kind: jobs.OutboxConnectionExpired, ConnectionID: "pac_b"},
		} {
			tx, err := s.DB.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := enqueuePAOutbox(ctx, tx, it, 1); err != nil {
				_ = tx.Rollback()
				t.Fatalf("enqueue %+v: %v", it, err)
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
		}
		rows, err := s.PAOutboxRows(ctx, p)
		if err != nil || len(rows) != 3 {
			t.Fatalf("rows %+v (%v), want one per key", rows, err)
		}
	})
}

// A refresh rotation racing the supersede of its connection (#1318 C2b
// review): the superseded row is locked before it is read, so a rotation
// that starts after the read cannot commit before the revoke. It misses
// its CAS once the activation commits (the refresh then revokes what it
// was issued), and the tokens the activation returns for revocation are
// the ones the row really held.
func TestActivatePAConnection_SupersedeLocksRotation(t *testing.T) {
	paLinkDialects(t, func(t *testing.T, s *Store) {
		ctx := context.Background()
		p := paLinkPrincipal(t, s)
		acceptConsent(t, s, p)
		t.Cleanup(func() { _, _ = s.DB.Exec(`DELETE FROM pa_connections WHERE principal = $1`, p) })
		old := activatePAConn(t, s, p, seedPAConnectionWithTokens(t, s, p))
		now := time.Now().UTC()
		ok, err := s.ClaimPAConnectionRefresh(ctx, p, old.ID, old.TokenGeneration, "replica-b", now, now.Add(time.Minute))
		if err != nil || !ok {
			t.Fatalf("lease: %v %v", ok, err)
		}
		rotated := make(chan error, 1)
		prev := paSupersedeAfterRead
		t.Cleanup(func() { paSupersedeAfterRead = prev })
		paSupersedeAfterRead = func(id string) {
			if id != old.ID {
				return
			}
			go func() {
				_, err := s.RotatePAConnectionTokens(context.Background(), p, old.ID, connection.Rotation{
					ExpectRevision: old.AuthorityRevision, ExpectGeneration: old.TokenGeneration,
					GrantedScope: old.GrantedScope, LeaseOwner: "replica-b",
					SealedTokens: []byte("rotated"), Now: time.Now().UTC(),
				})
				rotated <- err
			}()
			// Give an unlocked rotation every chance to commit first.
			select {
			case err := <-rotated:
				rotated <- err
			case <-time.After(500 * time.Millisecond):
			}
		}
		_, sup, err := s.ActivatePAConnection(ctx, p, seedPAConnectionWithTokens(t, s, p), connection.Transition{
			From: connection.StatePendingConfirm, To: connection.StateActive, ExpectRevision: 4})
		if err != nil {
			t.Fatalf("activation: %v", err)
		}
		var rerr error
		select {
		case rerr = <-rotated:
		case <-time.After(30 * time.Second):
			t.Fatal("the rotation never finished")
		}
		if rerr == nil {
			t.Fatal("a rotation committed on a connection being superseded: its tokens are orphaned")
		}
		if len(sup) != 1 || string(sup[0].Before.SealedTokens) != "tokens" {
			t.Fatalf("superseded %+v, want the stored tokens", sup)
		}
		got, sealed, err := s.GetPAConnectionSealed(ctx, p, old.ID)
		if err != nil || got.State != connection.StateRevoked || len(sealed.SealedTokens) != 0 {
			t.Fatalf("superseded row %s with %d sealed bytes (%v), want revoked and wiped", got.State, len(sealed.SealedTokens), err)
		}
	})
}

// An activation that cannot tell the dialect does not run: on Postgres,
// guessing SQLite would drop the supersede row lock.
func TestActivatePAConnection_UnknownDialectRefused(t *testing.T) {
	paLinkDialects(t, func(t *testing.T, s *Store) {
		ctx := context.Background()
		p := paLinkPrincipal(t, s)
		acceptConsent(t, s, p)
		t.Cleanup(func() { _, _ = s.DB.Exec(`DELETE FROM pa_connections WHERE principal = $1`, p) })
		id := seedPAConnectionWithTokens(t, s, p)
		s.pgMu.Lock()
		s.pgResolved = false
		s.pgMu.Unlock()
		s.probeFail = func() error { return errors.New("driver: bad connection") }
		_, _, err := s.ActivatePAConnection(ctx, p, id, connection.Transition{
			From: connection.StatePendingConfirm, To: connection.StateActive, ExpectRevision: 4})
		s.probeFail = nil
		if !errors.Is(err, connection.ErrUnreadable) {
			t.Fatalf("err %v, want ErrUnreadable", err)
		}
		if got, _ := s.GetPAConnection(ctx, p, id); got.State != connection.StatePendingConfirm {
			t.Fatalf("activated with an unknown dialect: %s", got.State)
		}
	})
}

// Rolling back past C2b (#1397 review): the previous build's Migrate
// recreates idx_pa_outbox_update over (principal, update_id, kind) WHERE
// job_id IS NULL. Two connection notices of one principal, written by this
// build or left over from before connection rows took -id, must not fail
// it, or that build crash-loops at start.
func TestPAOutbox_ConnectionRowsSurviveRollbackIndex(t *testing.T) {
	const oldIndex = `CREATE UNIQUE INDEX IF NOT EXISTS idx_pa_outbox_update ON pa_outbox(principal, update_id, kind)
	   WHERE job_id IS NULL`
	paLinkDialects(t, func(t *testing.T, s *Store) {
		ctx := context.Background()
		p := paLinkPrincipal(t, s)
		acceptConsent(t, s, p)
		t.Cleanup(func() {
			_, _ = s.DB.Exec(`DROP INDEX IF EXISTS idx_pa_outbox_update`)
			_, _ = s.DB.Exec(`DELETE FROM pa_outbox WHERE principal = $1`, p)
			_, _ = s.DB.Exec(`DELETE FROM pa_connections WHERE principal = $1`, p)
		})
		a := activatePAConn(t, s, p, seedPAConnectionWithTokens(t, s, p))
		expirePAConn(t, s, p, a)
		b := activatePAConn(t, s, p, seedPAConnectionWithTokens(t, s, p))
		expirePAConn(t, s, p, b)
		if got := paExpiryNotices(t, s, p); len(got) != 2 {
			t.Fatalf("notices %v, want two", got)
		}
		if _, err := s.DB.ExecContext(ctx, oldIndex); err != nil {
			t.Fatalf("previous build's update index on two connection notices: %v", err)
		}
		if _, err := s.DB.ExecContext(ctx, `DROP INDEX idx_pa_outbox_update`); err != nil {
			t.Fatal(err)
		}

		// Rows from before -id: Migrate repairs them.
		if _, err := s.DB.ExecContext(ctx, `UPDATE pa_outbox SET update_id = 0 WHERE principal = $1`, p); err != nil {
			t.Fatal(err)
		}
		if err := migratePAOutbox(ctx, s.DB, s.isPostgres(ctx)); err != nil {
			t.Fatalf("migrate: %v", err)
		}
		if _, err := s.DB.ExecContext(ctx, oldIndex); err != nil {
			t.Fatalf("previous build's update index after migrate: %v", err)
		}
	})
}
