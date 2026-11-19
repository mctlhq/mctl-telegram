package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"
)

// Store tests of the Personal Assistant linking secrets and the PA users row
// (#1314). They run on SQLite always and on Postgres when TEST_DATABASE_URL
// is set.

func paLinkDialects(t *testing.T, fn func(t *testing.T, s *Store)) {
	t.Helper()
	t.Run("sqlite", func(t *testing.T) {
		ctx := context.Background()
		conn, err := Open(ctx, "file:pa_link_"+randomSuffix(t)+"?mode=memory&cache=shared", 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		if err := MigrateCached(ctx, conn); err != nil {
			t.Fatal(err)
		}
		fn(t, &Store{DB: conn})
	})
	t.Run("postgres", func(t *testing.T) {
		dsn := os.Getenv("TEST_DATABASE_URL")
		if dsn == "" {
			t.Skip("TEST_DATABASE_URL not set")
		}
		fn(t, newPostgresTestStore(t, dsn))
	})
}

func paHash(v string) string {
	h := sha256.Sum256([]byte(v))
	return hex.EncodeToString(h[:])
}

// paLinkPrincipal is a synthetic principal unique per test (not a real
// Telegram id); its rows are removed at cleanup.
func paLinkPrincipal(t *testing.T, s *Store) int64 {
	t.Helper()
	b := sha256.Sum256([]byte(randomSuffix(t)))
	p := int64(9_300_000_000) + int64(b[0])<<16 | int64(b[1])<<8 | int64(b[2])
	t.Cleanup(func() {
		_, _ = s.DB.Exec(`DELETE FROM pa_link_secrets WHERE principal = $1`, p)
		_, _ = s.DB.Exec(`DELETE FROM user_acquisition WHERE user_id IN (SELECT id FROM users WHERE telegram_login_id = $1)`, p)
		_, _ = s.DB.Exec(`DELETE FROM users WHERE telegram_login_id = $1`, p)
	})
	return p
}

func TestPALinkSecret_ConsumeOnceAndRefusals(t *testing.T) {
	paLinkDialects(t, func(t *testing.T, s *Store) {
		ctx := context.Background()
		p := paLinkPrincipal(t, s)
		now := time.Now()
		h := paHash("link-" + randomSuffix(t))
		if err := s.CreatePALinkSecret(ctx, PALinkSecret{Hash: h, Kind: PALinkState, Principal: p, Server: "tg",
			ConnectionID: "pac_x", Revision: 2, Verifier: "v", RedirectURI: "https://x/cb", ExpiresAt: now.Add(time.Minute)}, now); err != nil {
			t.Fatal(err)
		}
		// Another kind does not see it.
		if _, err := s.ConsumePALinkSecret(ctx, PALinkCompletion, h, now, nil); !errors.Is(err, ErrPALinkUnknown) {
			t.Fatalf("other kind: %v", err)
		}
		// A failing check leaves it unconsumed.
		errNo := errors.New("not yours")
		if _, err := s.ConsumePALinkSecret(ctx, PALinkState, h, now, func(PALinkSecret) error { return errNo }); !errors.Is(err, errNo) {
			t.Fatalf("check: %v", err)
		}
		got, err := s.ConsumePALinkSecret(ctx, PALinkState, h, now, nil)
		if err != nil || got.Verifier != "v" || got.Revision != 2 || got.ConnectionID != "pac_x" {
			t.Fatalf("consume: %+v %v", got, err)
		}
		if _, err := s.ConsumePALinkSecret(ctx, PALinkState, h, now, nil); !errors.Is(err, ErrPALinkConsumed) {
			t.Fatalf("reuse: %v", err)
		}
		var verifier string
		if err := s.DB.QueryRow(`SELECT verifier FROM pa_link_secrets WHERE hash = $1`, h).Scan(&verifier); err != nil || verifier != "" {
			t.Fatalf("verifier kept after consume: %q %v", verifier, err)
		}
	})
}

func TestPALinkSecret_ExpiryAndSweep(t *testing.T) {
	paLinkDialects(t, func(t *testing.T, s *Store) {
		ctx := context.Background()
		p := paLinkPrincipal(t, s)
		now := time.Now()
		h := paHash("confirm-" + randomSuffix(t))
		if err := s.CreatePALinkSecret(ctx, PALinkSecret{Hash: h, Kind: PALinkConfirm, Principal: p, Server: "tg",
			ConnectionID: "pac_y", Revision: 4, ExpiresAt: now.Add(time.Minute)}, now); err != nil {
			t.Fatal(err)
		}
		later := now.Add(time.Minute)
		got, err := s.ConsumePALinkSecret(ctx, PALinkConfirm, h, later, nil)
		if !errors.Is(err, ErrPALinkExpired) || got.ConnectionID != "pac_y" || got.Principal != p {
			t.Fatalf("expired: %+v %v", got, err)
		}
		if err := s.RetirePALinkSecret(ctx, PALinkConfirm, h, now); err != nil {
			t.Fatal(err)
		}
		listed, err := s.ExpiredPALinkSecrets(ctx, PALinkConfirm, later, 1000)
		if err != nil || !containsHash(listed, h) {
			t.Fatalf("retired before expiry, or not listed: %v", err)
		}
		if err := s.RetirePALinkSecret(ctx, PALinkConfirm, h, later); err != nil {
			t.Fatal(err)
		}
		listed, err = s.ExpiredPALinkSecrets(ctx, PALinkConfirm, later, 1000)
		if err != nil || containsHash(listed, h) {
			t.Fatalf("listed after retire: %v", err)
		}
	})
}

func containsHash(ls []PALinkSecret, h string) bool {
	for _, l := range ls {
		if l.Hash == h {
			return true
		}
	}
	return false
}

// Two concurrent consumers of one secret: exactly one succeeds.
func TestPALinkSecret_ConcurrentConsumeOnce(t *testing.T) {
	paLinkDialects(t, func(t *testing.T, s *Store) {
		ctx := context.Background()
		p := paLinkPrincipal(t, s)
		now := time.Now()
		h := paHash("race-" + randomSuffix(t))
		if err := s.CreatePALinkSecret(ctx, PALinkSecret{Hash: h, Kind: PALinkCompletion, Principal: p, Server: "tg",
			ExpiresAt: now.Add(time.Minute)}, now); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		var mu sync.Mutex
		ok := 0
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := s.ConsumePALinkSecret(ctx, PALinkCompletion, h, now, nil); err == nil {
					mu.Lock()
					ok++
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		if ok != 1 {
			t.Fatalf("successful consumes = %d, want 1", ok)
		}
	})
}

// PA users row (owner decision 2026-11-19): EnsurePAUser creates a "pa"
// row once; a tg-mcp sign-in promotes it and writes its acquisition; PA-only
// rows are neither counted publicly nor broadcast to.
func TestEnsurePAUser_MarkedPromotedAndExcluded(t *testing.T) {
	paLinkDialects(t, func(t *testing.T, s *Store) {
		ctx := context.Background()
		p := paLinkPrincipal(t, s)
		provider := func(id int64) string {
			var v string
			if err := s.DB.QueryRow(`SELECT provider FROM users WHERE id = $1`, id).Scan(&v); err != nil {
				t.Fatal(err)
			}
			return v
		}
		before, err := s.PublicStatsQuery(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		id, err := s.EnsurePAUser(ctx, p)
		if err != nil || provider(id) != PAProvider {
			t.Fatalf("EnsurePAUser: %d %v", id, err)
		}
		if again, err := s.EnsurePAUser(ctx, p); err != nil || again != id {
			t.Fatalf("second EnsurePAUser: %d %v", again, err)
		}
		mid, err := s.PublicStatsQuery(ctx, nil)
		if err != nil || mid.AccountsTotal != before.AccountsTotal {
			t.Fatalf("a PA-only row is counted: %d -> %d (%v)", before.AccountsTotal, mid.AccountsTotal, err)
		}
		if f, err := s.GetBroadcastRecipientFacts(ctx, id, time.Now()); err != nil || f != nil {
			t.Fatalf("a PA-only row is a broadcast recipient: %+v %v", f, err)
		}

		got, err := s.EnsureUserByTelegramCapture(ctx, TelegramIdentityCapture{TelegramID: p, FirstName: "Alice",
			Source: "telegram_oidc", Acquisition: &Acquisition{State: AcquisitionDirect}})
		if err != nil || got != id {
			t.Fatalf("capture: %d %v", got, err)
		}
		if provider(id) != "tg-mcp" {
			t.Fatalf("provider after sign-in = %q, want tg-mcp", provider(id))
		}
		if _, ok := acqRow(t, s, id); !ok {
			t.Fatal("no acquisition row after the first tg-mcp sign-in of a PA-first user")
		}
		after, err := s.PublicStatsQuery(ctx, nil)
		if err != nil || after.AccountsTotal != before.AccountsTotal+1 {
			t.Fatalf("promoted row not counted: %d -> %d (%v)", before.AccountsTotal, after.AccountsTotal, err)
		}
		if f, err := s.GetBroadcastRecipientFacts(ctx, id, time.Now()); err != nil || f == nil {
			t.Fatalf("promoted row is not a broadcast candidate: %v", err)
		}
	})
}

// EnsurePAUser must not split an existing identity. A user known only
// through telegram_accounts (no users.telegram_login_id) is returned as it
// is; no second row is created, so every other caller's lookup of that
// Telegram id still resolves to the same single user.
func TestEnsurePAUser_ExistingTelegramAccountUnchanged(t *testing.T) {
	paLinkDialects(t, func(t *testing.T, s *Store) {
		ctx := context.Background()
		p := paLinkPrincipal(t, s)
		owner, err := s.EnsureUser(ctx, "pa-legacy-"+randomSuffix(t), "", "mctl-api")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_, _ = s.DB.Exec(`DELETE FROM telegram_accounts WHERE user_id = $1`, owner)
			_, _ = s.DB.Exec(`DELETE FROM users WHERE id = $1`, owner)
		})
		if _, err := s.DB.ExecContext(ctx,
			`INSERT INTO telegram_accounts(user_id, telegram_user_id, session_encrypted) VALUES($1,$2,$3)`,
			owner, p, []byte("blob")); err != nil {
			t.Fatal(err)
		}
		got, err := s.EnsurePAUser(ctx, p)
		if err != nil || got != owner {
			t.Fatalf("EnsurePAUser = %d, %v; want the existing user %d", got, err, owner)
		}
		var n int
		if err := s.DB.QueryRow(`SELECT COUNT(*) FROM users WHERE telegram_login_id = $1 OR github_login = $2`,
			p, "tg:"+strconv.FormatInt(p, 10)).Scan(&n); err != nil || n != 0 {
			t.Fatalf("a second users row was created: %d %v", n, err)
		}
		if again, err := s.UserIDByTelegramID(ctx, p); err != nil || again != owner {
			t.Fatalf("mapping changed: %d %v", again, err)
		}
	})
}

// A PA row is promoted by the other sign-in path too (localjwt, worker
// tokens, k8ssa, provision_local_account).
func TestEnsurePAUser_PromotedByEnsureUserByTelegramID(t *testing.T) {
	paLinkDialects(t, func(t *testing.T, s *Store) {
		ctx := context.Background()
		p := paLinkPrincipal(t, s)
		id, err := s.EnsurePAUser(ctx, p)
		if err != nil {
			t.Fatal(err)
		}
		got, err := s.EnsureUserByTelegramID(ctx, p, "", "Alice")
		if err != nil || got != id {
			t.Fatalf("EnsureUserByTelegramID = %d, %v; want %d", got, err, id)
		}
		var provider string
		if err := s.DB.QueryRow(`SELECT provider FROM users WHERE id = $1`, id).Scan(&provider); err != nil || provider != "tg-mcp" {
			t.Fatalf("provider %q %v, want tg-mcp", provider, err)
		}
	})
}

// A legacy tg-mcp row that carries the synthetic login but was never
// backfilled with telegram_login_id is this principal's row: EnsurePAUser
// backfills and returns it, and leaves its provider alone.
func TestEnsurePAUser_LegacySyntheticLoginBackfilled(t *testing.T) {
	paLinkDialects(t, func(t *testing.T, s *Store) {
		ctx := context.Background()
		p := paLinkPrincipal(t, s)
		login := "tg:" + strconv.FormatInt(p, 10)
		legacy, err := s.EnsureUser(ctx, login, "", "tg-mcp")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _, _ = s.DB.Exec(`DELETE FROM users WHERE id = $1`, legacy) })
		got, err := s.EnsurePAUser(ctx, p)
		if err != nil || got != legacy {
			t.Fatalf("EnsurePAUser = %d, %v; want the legacy row %d", got, err, legacy)
		}
		var provider string
		var tg sql.NullInt64
		if err := s.DB.QueryRow(`SELECT provider, telegram_login_id FROM users WHERE id = $1`, legacy).Scan(&provider, &tg); err != nil {
			t.Fatal(err)
		}
		if provider != "tg-mcp" || !tg.Valid || tg.Int64 != p {
			t.Fatalf("legacy row: provider %q, telegram_login_id %v", provider, tg)
		}
	})
}

// A lookup that cannot decide is never "no user": EnsurePAUser returns the
// error and inserts nothing, both when the Telegram id already maps to two
// users and when the lookup itself fails.
func TestEnsurePAUser_LookupFailureInsertsNothing(t *testing.T) {
	countRows := func(t *testing.T, s *Store, p int64) int {
		t.Helper()
		var n int
		if err := s.DB.QueryRow(`SELECT COUNT(*) FROM users WHERE telegram_login_id = $1 OR github_login = $2`,
			p, "tg:"+strconv.FormatInt(p, 10)).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	t.Run("ambiguous", func(t *testing.T) {
		paLinkDialects(t, func(t *testing.T, s *Store) {
			ctx := context.Background()
			p := paLinkPrincipal(t, s)
			for i := 0; i < 2; i++ {
				owner, err := s.EnsureUser(ctx, "pa-ambiguous-"+randomSuffix(t), "", "mctl-api")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					_, _ = s.DB.Exec(`DELETE FROM telegram_accounts WHERE user_id = $1`, owner)
					_, _ = s.DB.Exec(`DELETE FROM users WHERE id = $1`, owner)
				})
				if _, err := s.DB.ExecContext(ctx,
					`INSERT INTO telegram_accounts(user_id, telegram_user_id, session_encrypted) VALUES($1,$2,$3)`,
					owner, p, []byte("blob")); err != nil {
					t.Fatal(err)
				}
			}
			if id, err := s.EnsurePAUser(ctx, p); !errors.Is(err, ErrTelegramIdentityAmbiguous) {
				t.Fatalf("EnsurePAUser = %d, %v; want ErrTelegramIdentityAmbiguous", id, err)
			}
			if n := countRows(t, s, p); n != 0 {
				t.Fatalf("%d users rows inserted for an ambiguous id", n)
			}
		})
	})
	t.Run("lookup error", func(t *testing.T) {
		// SQLite only: the lookup's telegram_accounts table is renamed away
		// on a private in-memory database, so the lookup fails while an
		// INSERT into users would still succeed.
		ctx := context.Background()
		conn, err := Open(ctx, "file:pa_link_err_"+randomSuffix(t)+"?mode=memory&cache=shared", 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		if err := MigrateCached(ctx, conn); err != nil {
			t.Fatal(err)
		}
		s := &Store{DB: conn}
		if _, err := conn.ExecContext(ctx, `ALTER TABLE telegram_accounts RENAME TO telegram_accounts_gone`); err != nil {
			t.Fatal(err)
		}
		// The failure is made transient: once the first lookup has failed,
		// the table comes back, so only the failed first lookup itself can
		// stop the insert.
		paEnsureAfterResolve = func(ctx context.Context, tx *sql.Tx) {
			if _, err := tx.ExecContext(ctx, `ALTER TABLE telegram_accounts_gone RENAME TO telegram_accounts`); err != nil {
				t.Errorf("restore table: %v", err)
			}
		}
		t.Cleanup(func() { paEnsureAfterResolve = nil })
		const p int64 = 9_300_000_777
		if id, err := s.EnsurePAUser(ctx, p); err == nil || errors.Is(err, ErrUserNotFound) {
			t.Fatalf("EnsurePAUser = %d, %v; want the lookup error", id, err)
		}
		if n := countRows(t, s, p); n != 0 {
			t.Fatalf("%d users rows inserted after a failed lookup", n)
		}
	})
}
