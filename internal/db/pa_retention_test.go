package db

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
)

// Retention and account deletion of the Personal Assistant linking state
// (#1338). They run on SQLite always and on Postgres when TEST_DATABASE_URL
// is set.

// TestPALinkSecretRetention_Bounds pins the retention window. Longer keeps a
// spent secret's principal, server and masked account past any reader's
// need; shorter than an hour could delete an expired, unconsumed row before
// the linking sweep has had a pass to fail its connection.
func TestPALinkSecretRetention_Bounds(t *testing.T) {
	if PALinkSecretRetention > 24*time.Hour {
		t.Errorf("PALinkSecretRetention = %s, want at most 24h", PALinkSecretRetention)
	}
	if PALinkSecretRetention < time.Hour {
		t.Errorf("PALinkSecretRetention = %s, want at least 1h", PALinkSecretRetention)
	}
}

// seedPALinkSecret creates a secret of principal expiring at expires and, if
// consumed, consumes it a minute before that.
func seedPALinkSecret(t *testing.T, s *Store, principal int64, expires time.Time, consumed bool) string {
	t.Helper()
	ctx := context.Background()
	h := paHash(fmt.Sprintf("ret-%d-%s", principal, randomSuffix(t)))
	created := expires.Add(-10 * time.Minute)
	if err := s.CreatePALinkSecret(ctx, PALinkSecret{Hash: h, Kind: PALinkConfirm, Principal: principal, Server: "tg",
		ConnectionID: "pac_ret", Revision: 4, AccountHint: "A***123", ExpiresAt: expires}, created); err != nil {
		t.Fatalf("create secret: %v", err)
	}
	if consumed {
		if _, err := s.ConsumePALinkSecret(ctx, PALinkConfirm, h, expires.Add(-time.Minute), nil); err != nil {
			t.Fatalf("consume secret: %v", err)
		}
	}
	return h
}

func paLinkSecretExists(t *testing.T, s *Store, hash string) bool {
	t.Helper()
	var n int
	if err := s.DB.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM pa_link_secrets WHERE hash = $1`, hash).Scan(&n); err != nil {
		t.Fatalf("count secret: %v", err)
	}
	return n == 1
}

func TestSweepPAState_DeletesLinkSecretsPastRetention(t *testing.T) {
	paLinkDialects(t, func(t *testing.T, s *Store) {
		ctx := context.Background()
		p := paLinkPrincipal(t, s)
		now := time.Now()
		past := now.Add(-PALinkSecretRetention - time.Minute)
		within := now.Add(-PALinkSecretRetention + time.Minute)
		cases := []struct {
			name     string
			expires  time.Time
			consumed bool
			keep     bool
		}{
			{"expired unused past retention", past, false, false},
			{"consumed, expired past retention", past, true, false},
			{"expired unused within retention", within, false, true},
			{"consumed, expired within retention", within, true, true},
			{"consumed, not yet expired", now.Add(5 * time.Minute), true, true},
			{"live", now.Add(5 * time.Minute), false, true},
		}
		hashes := make([]string, len(cases))
		for i, c := range cases {
			hashes[i] = seedPALinkSecret(t, s, p, c.expires, c.consumed)
		}
		r, err := s.SweepPAState(ctx, now, now.Add(-48*time.Hour))
		if err != nil {
			t.Fatalf("sweep: %v", err)
		}
		// The SQLite database is this test's own; Postgres is shared with
		// earlier runs, whose stale rows this sweep may delete too.
		pg, err := s.postgresDialect(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if r.LinkSecrets < 2 || (!pg && r.LinkSecrets != 2) {
			t.Errorf("SweepResult.LinkSecrets = %d, want 2 (at least 2 on Postgres)", r.LinkSecrets)
		}
		for i, c := range cases {
			if got := paLinkSecretExists(t, s, hashes[i]); got != c.keep {
				t.Errorf("%s: row kept = %v, want %v", c.name, got, c.keep)
			}
		}
	})
}

// seedPAConnection creates a pending connection of principal.
func seedPAConnection(t *testing.T, s *Store, principal int64) string {
	t.Helper()
	id := fmt.Sprintf("pac_del_%d_%s", principal, randomSuffix(t))
	if err := s.CreatePAConnection(context.Background(), connection.Connection{
		ID: id, Principal: principal, Server: connection.ServerTG, State: connection.StatePendingLink, AuthorityRevision: 1,
	}, connection.Sealed{KEKID: "test", WrappedDEK: []byte("wrapped")}); err != nil {
		t.Fatalf("create connection: %v", err)
	}
	t.Cleanup(func() { _, _ = s.DB.Exec(`DELETE FROM pa_connections WHERE id = $1`, id) })
	return id
}

// seedPAPrincipalState writes one row of principal into every PA table
// account deletion purges or keeps, shaped as a principal mid-run: an open
// conversation, a claimed job with a reserved charge, and an outbox row
// being sent.
func seedPAPrincipalState(t *testing.T, s *Store, principal int64) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UnixMilli()
	conv := fmt.Sprintf("pcv_%d_%s", principal, randomSuffix(t))
	t.Cleanup(func() {
		for _, tb := range []string{"pa_consents", "pa_conversations", "pa_fragments", "pa_principal_locks",
			"pa_callbacks", "pa_jobs", "pa_usage", "pa_rate", "pa_outbox"} {
			_, _ = s.DB.Exec(`DELETE FROM `+tb+` WHERE principal = $1`, principal)
		}
	})
	stmts := []struct {
		q    string
		args []any
	}{
		{`INSERT INTO pa_consents(principal, version, text_sha256, state, updated_at_ms) VALUES($1, 'v1', 'sha', 'accepted', $2)`, []any{principal, now}},
		{`INSERT INTO pa_conversations(id, principal, created_at_ms, expires_at_ms, closed_at_ms) VALUES($1, $2, $3, $4, 0)`, []any{conv, principal, now, now + 3_600_000}},
		{`INSERT INTO pa_fragments(conversation_id, seq, principal, kind, provenance, sealed, created_at_ms) VALUES($1, 1, $2, 'user', 'mark', $3, $4)`, []any{conv, principal, []byte("sealed"), now}},
		{`INSERT INTO pa_principal_locks(principal, locked_at_ms) VALUES($1, $2)`, []any{principal, now}},
		{`INSERT INTO pa_callbacks(principal, id, action, expires_at_ms) VALUES($1, 'cb1', 'confirm', $2)`, []any{principal, now + 600_000}},
		{`INSERT INTO pa_jobs(principal, conversation_id, update_id, consent_version, status, lease_until_ms, created_at_ms, updated_at_ms)
			VALUES($1, $2, 1, 'v1', 'claimed', $3, $4, $4)`, []any{principal, conv, now + 60_000, now}},
		{`INSERT INTO pa_usage(job_id, attempt, principal, reserved_usd, status, created_at_ms, updated_at_ms)
			VALUES((SELECT id FROM pa_jobs WHERE principal = $1), 1, $1, 0.5, 'reserved', $2, $2)`, []any{principal, now}},
		{`INSERT INTO pa_rate(principal, window_start_ms, count) VALUES($1, $2, 3)`, []any{principal, now}},
		{`INSERT INTO pa_outbox(principal, job_id, kind, status, attempts, next_at_ms, lease_until_ms, created_at_ms, updated_at_ms)
			VALUES($1, (SELECT id FROM pa_jobs WHERE principal = $1), 'reply', 'sending', 1, $2, $3, $2, $2)`, []any{principal, now, now + 60_000}},
	}
	for _, st := range stmts {
		if _, err := s.DB.ExecContext(ctx, st.q, st.args...); err != nil {
			t.Fatalf("seed %q: %v", st.q[:40], err)
		}
	}
	seedPAConnection(t, s, principal)
	seedPAConnection(t, s, principal)
	seedPALinkSecret(t, s, principal, time.Now().Add(5*time.Minute), false)
	seedPALinkSecret(t, s, principal, time.Now().Add(5*time.Minute), true)
}

// paRowsIn counts principal's rows in table.
func paRowsIn(t *testing.T, s *Store, table string, principal int64) int {
	t.Helper()
	var n int
	if err := s.DB.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM `+table+` WHERE principal = $1`, principal).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

func paUsageStatus(t *testing.T, s *Store, principal int64) string {
	t.Helper()
	var st string
	if err := s.DB.QueryRowContext(context.Background(),
		`SELECT status FROM pa_usage WHERE principal = $1`, principal).Scan(&st); err != nil {
		t.Fatalf("read pa_usage: %v", err)
	}
	return st
}

// paSeededRows is how many rows seedPAPrincipalState writes per table.
var paSeededRows = map[string]int{
	"pa_outbox": 1, "pa_jobs": 1, "pa_callbacks": 1, "pa_fragments": 1, "pa_conversations": 1,
	"pa_consents": 1, "pa_link_secrets": 2, "pa_connections": 2, "pa_principal_locks": 1,
	"pa_usage": 1, "pa_rate": 1,
}

func TestHardDeleteAccount_PurgesPAState(t *testing.T) {
	deletionDialects(t, func(t *testing.T, s *Store, base int64) {
		ctx := context.Background()
		aliceLogin, aliceSession, bobID := base+21, base+22, base+23
		alice, err := s.EnsureUserByTelegramID(ctx, aliceLogin, "alice", "Alice")
		if err != nil {
			t.Fatalf("ensure alice: %v", err)
		}
		bob, err := s.EnsureUserByTelegramID(ctx, bobID, "bob", "Bob")
		if err != nil {
			t.Fatalf("ensure bob: %v", err)
		}
		// The session's Telegram id differs from the login id on purpose:
		// the PA state of both goes.
		seedAccountForTelegramID(t, s, alice, aliceSession, nil)
		seedAccountForTelegramID(t, s, bob, bobID, nil)
		for _, p := range []int64{aliceLogin, aliceSession, bobID} {
			seedPAPrincipalState(t, s, p)
		}

		if _, err := s.HardDeleteAccount(ctx, alice); err != nil {
			t.Fatalf("delete alice: %v", err)
		}
		// Listed here, not taken from paPrincipalPurges, so dropping a table
		// from that list fails this test.
		purged := []string{"pa_outbox", "pa_jobs", "pa_callbacks", "pa_fragments", "pa_conversations",
			"pa_consents", "pa_link_secrets", "pa_connections", "pa_principal_locks"}
		for _, p := range []int64{aliceLogin, aliceSession} {
			for _, table := range purged {
				if n := paRowsIn(t, s, table, p); n != 0 {
					t.Errorf("principal %d: %d rows left in %s, want 0", p, n, table)
				}
			}
			// The cap ledgers stay; a reservation of the claimed job is held
			// at its full amount, never left reserved.
			if n := paRowsIn(t, s, "pa_rate", p); n != 1 {
				t.Errorf("principal %d: %d pa_rate rows, want 1 (kept)", p, n)
			}
			if st := paUsageStatus(t, s, p); st != "held" {
				t.Errorf("principal %d: pa_usage status %q, want held", p, st)
			}
		}
		for table, want := range paSeededRows {
			if n := paRowsIn(t, s, table, bobID); n != want {
				t.Errorf("bob after alice's delete: %d rows in %s, want %d", n, table, want)
			}
		}
		if st := paUsageStatus(t, s, bobID); st != "reserved" {
			t.Errorf("bob's pa_usage status %q after alice's delete, want reserved", st)
		}
	})
}

// TestPAPrincipalPurges_CoverEveryPrincipalTable fails when a PA table with
// a principal column is neither purged on account deletion nor deliberately
// kept (see paPrincipalPurges).
func TestPAPrincipalPurges_CoverEveryPrincipalTable(t *testing.T) {
	s := newTestStore(t)
	kept := map[string]bool{"pa_usage": true, "pa_rate": true}
	purged := map[string]bool{}
	for _, st := range paPrincipalPurges {
		purged[st.table] = true
	}
	rows, err := s.DB.Query(`SELECT m.name FROM sqlite_master m, pragma_table_info(m.name) c
		WHERE m.type = 'table' AND m.name LIKE 'pa\_%' ESCAPE '\' AND c.name = 'principal'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	seen := 0
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		seen++
		if !purged[name] && !kept[name] {
			t.Errorf("%s has a principal column but account deletion neither purges nor keeps it", name)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if seen < len(purged)+len(kept) {
		t.Errorf("found %d principal tables, want at least %d: the schema query is broken", seen, len(purged)+len(kept))
	}
}

// A connection that still holds provider tokens refuses the deletion: its
// tokens would stay live at the provider (TODO #1314). The deletion rolls
// back and the connection is untouched. No such row exists in any
// environment, since linking is not wired.
func TestHardDeleteAccount_RefusesConnectionHoldingTokens(t *testing.T) {
	for _, active := range []bool{false, true} {
		name := "pending_confirm"
		if active {
			name = "active"
		}
		t.Run(name, func(t *testing.T) {
			deletionDialects(t, func(t *testing.T, s *Store, base int64) {
				ctx := context.Background()
				tgID := base + 25
				if active {
					tgID = base + 26
				}
				uid, err := s.EnsureUserByTelegramID(ctx, tgID, "dana", "Dana")
				if err != nil {
					t.Fatalf("ensure: %v", err)
				}
				seedAccountForTelegramID(t, s, uid, tgID, nil)
				id := seedPAConnection(t, s, tgID)
				steps := []connection.Transition{
					{From: connection.StatePendingLink, To: connection.StatePendingOAuth, ExpectRevision: 1},
					{From: connection.StatePendingOAuth, To: connection.StatePendingReturn, ExpectRevision: 2, SealedCode: []byte("code")},
					{From: connection.StatePendingReturn, To: connection.StatePendingConfirm, ExpectRevision: 3,
						AccountID: "acct", GrantedScope: "telegram:dialogs:read", SealedTokens: []byte("tokens")},
				}
				if active {
					steps = append(steps, connection.Transition{From: connection.StatePendingConfirm, To: connection.StateActive, ExpectRevision: 4})
				}
				for _, tr := range steps {
					if _, err := s.TransitionPAConnection(ctx, tgID, id, tr); err != nil {
						t.Fatalf("%s -> %s: %v", tr.From, tr.To, err)
					}
				}

				if _, err := s.HardDeleteAccount(ctx, uid); !errors.Is(err, ErrPAConnectionsNeedRevocation) {
					t.Fatalf("delete with a token-holding connection: %v, want ErrPAConnectionsNeedRevocation", err)
				}
				var accounts int
				if err := s.DB.QueryRowContext(ctx,
					`SELECT COUNT(*) FROM telegram_accounts WHERE user_id = $1`, uid).Scan(&accounts); err != nil {
					t.Fatalf("count accounts: %v", err)
				}
				if accounts != 1 {
					t.Errorf("telegram_accounts rows = %d after a refused delete, want 1", accounts)
				}
				if _, sealed, err := s.GetPAConnectionSealed(ctx, tgID, id); err != nil || len(sealed.SealedTokens) == 0 {
					t.Errorf("connection after a refused delete: err %v, tokens %d bytes, want it untouched", err, len(sealed.SealedTokens))
				}
				// Once the connection is revoked (tokens wiped), the delete
				// goes through.
				if _, _, _, err := s.RevokePAConnection(ctx, tgID, id, "test"); err != nil {
					t.Fatalf("revoke: %v", err)
				}
				if _, err := s.HardDeleteAccount(ctx, uid); err != nil {
					t.Fatalf("delete after revocation: %v", err)
				}
				if n := paRowsIn(t, s, "pa_connections", tgID); n != 0 {
					t.Errorf("%d connections left after the delete, want 0", n)
				}
			})
		})
	}
}

// An account without PA rows deletes as it did before: its account rows go
// and the count is unchanged.
func TestHardDeleteAccount_WithoutPALinkingState(t *testing.T) {
	deletionDialects(t, func(t *testing.T, s *Store, base int64) {
		ctx := context.Background()
		tgID := base + 24
		uid, err := s.EnsureUserByTelegramID(ctx, tgID, "carol", "Carol")
		if err != nil {
			t.Fatalf("ensure: %v", err)
		}
		seedAccountForTelegramID(t, s, uid, tgID, nil)
		rows, err := s.HardDeleteAccount(ctx, uid)
		if err != nil {
			t.Fatalf("delete: %v", err)
		}
		if rows != 1 {
			t.Errorf("rows removed = %d, want 1", rows)
		}
		var accounts int
		if err := s.DB.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM telegram_accounts WHERE user_id = $1`, uid).Scan(&accounts); err != nil {
			t.Fatalf("count accounts: %v", err)
		}
		if accounts != 0 {
			t.Errorf("telegram_accounts rows = %d after the delete, want 0", accounts)
		}
	})
}

// isolatedDialects runs body on a SQLite database and a Postgres schema of
// its own, so a test may break a table without touching any other test.
func isolatedDialects(t *testing.T, body func(t *testing.T, s *Store)) {
	t.Run("sqlite", func(t *testing.T) {
		ctx := context.Background()
		conn, err := Open(ctx, "file:pa_iso_"+randomSuffix(t)+"?mode=memory&cache=shared", 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		if err := MigrateCached(ctx, conn); err != nil {
			t.Fatal(err)
		}
		body(t, &Store{DB: conn})
	})
	t.Run("postgres", func(t *testing.T) { body(t, newFreshSchemaPostgresStore(t)) })
}

// A failed PA statement fails the account deletion, and the deletion rolls
// back as a whole: the account and every PA row are still there, unchanged.
func TestHardDeleteAccount_PALinkingPurgeFailureRollsBack(t *testing.T) {
	tables := []string{"pa_usage"}
	for _, st := range paPrincipalPurges {
		tables = append(tables, st.table)
	}
	for _, table := range tables {
		t.Run(table, func(t *testing.T) {
			isolatedDialects(t, func(t *testing.T, s *Store) {
				ctx := context.Background()
				const tgID = int64(4646)
				uid, err := s.EnsureUserByTelegramID(ctx, tgID, "dana", "Dana")
				if err != nil {
					t.Fatalf("ensure: %v", err)
				}
				seedAccountForTelegramID(t, s, uid, tgID, nil)
				seedPAPrincipalState(t, s, tgID)
				if _, err := s.DB.ExecContext(ctx, `ALTER TABLE `+table+` RENAME TO `+table+`_broken`); err != nil {
					t.Fatalf("break %s: %v", table, err)
				}

				if _, err := s.HardDeleteAccount(ctx, uid); err == nil {
					t.Fatalf("delete succeeded although deleting from %s failed", table)
				}
				if _, err := s.DB.ExecContext(ctx, `ALTER TABLE `+table+`_broken RENAME TO `+table); err != nil {
					t.Fatalf("restore %s: %v", table, err)
				}
				var accounts int
				if err := s.DB.QueryRowContext(ctx,
					`SELECT COUNT(*) FROM telegram_accounts WHERE user_id = $1`, uid).Scan(&accounts); err != nil {
					t.Fatalf("count accounts: %v", err)
				}
				if accounts != 1 {
					t.Errorf("telegram_accounts rows = %d after a failed delete, want 1", accounts)
				}
				for tb, want := range paSeededRows {
					if n := paRowsIn(t, s, tb, tgID); n != want {
						t.Errorf("%d rows in %s after a failed delete, want %d", n, tb, want)
					}
				}
				if st := paUsageStatus(t, s, tgID); st != "reserved" {
					t.Errorf("pa_usage status %q after a failed delete, want reserved", st)
				}
			})
		})
	}
}

// A guard that cannot read the connections refuses the deletion: tokens it
// could not observe are not absent tokens.
func TestHardDeleteAccount_UnreadableConnectionsRefuse(t *testing.T) {
	isolatedDialects(t, func(t *testing.T, s *Store) {
		ctx := context.Background()
		const tgID = int64(4646)
		uid, err := s.EnsureUserByTelegramID(ctx, tgID, "dana", "Dana")
		if err != nil {
			t.Fatalf("ensure: %v", err)
		}
		seedAccountForTelegramID(t, s, uid, tgID, nil)
		// The guard reads sealed_tokens; the purge's DELETE does not, so
		// only the guard breaks.
		if _, err := s.DB.ExecContext(ctx, `ALTER TABLE pa_connections DROP COLUMN sealed_tokens`); err != nil {
			t.Fatalf("drop column: %v", err)
		}
		if _, err := s.HardDeleteAccount(ctx, uid); err == nil {
			t.Fatal("delete succeeded although the token guard could not read pa_connections")
		}
		var accounts int
		if err := s.DB.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM telegram_accounts WHERE user_id = $1`, uid).Scan(&accounts); err != nil {
			t.Fatalf("count accounts: %v", err)
		}
		if accounts != 1 {
			t.Errorf("telegram_accounts rows = %d after a refused delete, want 1", accounts)
		}
	})
}

// The account-deletion and retention predicates have an index each (#1338):
// deletion runs under the users-row lock, and the sweep runs hourly.
func TestPAPurgeIndexes(t *testing.T) {
	want := []string{"idx_pa_link_secrets_principal", "idx_pa_link_secrets_expires",
		"idx_pa_conversations_principal", "idx_pa_jobs_principal"}
	isolatedDialects(t, func(t *testing.T, s *Store) {
		pg, err := s.postgresDialect(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		q := `SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = $1`
		if pg {
			q = `SELECT COUNT(*) FROM pg_indexes WHERE schemaname = current_schema() AND indexname = $1`
		}
		for _, name := range want {
			var n int
			if err := s.DB.QueryRow(q, name).Scan(&n); err != nil {
				t.Fatalf("look up %s: %v", name, err)
			}
			if n != 1 {
				t.Errorf("index %s missing", name)
			}
		}
	})
}
