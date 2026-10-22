package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/crypto"
)

func liveRefreshTokens(t *testing.T, s *Store, uid int64) int {
	t.Helper()
	var live int
	if err := s.DB.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM oauth_refresh_tokens WHERE user_id = $1 AND revoked_at IS NULL`, uid).Scan(&live); err != nil {
		t.Fatalf("count live refresh tokens: %v", err)
	}
	return live
}

// A code issued before the account was deleted must not mint a refresh
// family after it (#796); one issued after the delete, by a user who signed
// in again, still may.
func TestSaveRefreshTokenForGrant_RefusesGrantIssuedBeforeDelete(t *testing.T) {
	deletionDialects(t, func(t *testing.T, s *Store, base int64) {
		ctx := context.Background()
		tgID := base + 1
		uid, err := s.EnsureUserByTelegramID(ctx, tgID, "alice", "Alice")
		if err != nil {
			t.Fatalf("ensure: %v", err)
		}
		mk := func() RefreshToken {
			return RefreshToken{FamilyID: fmt.Sprintf("grant-fam-%d-%d", tgID, time.Now().UnixNano()), UserID: uid,
				ClientID: "claude.ai", TelegramID: tgID, Scope: "telegram:dialogs:read", ExpiresAt: time.Now().Add(time.Hour)}
		}
		plain := func(tag string) string { return fmt.Sprintf("grant-%s-%d-%d", tag, tgID, time.Now().UnixNano()) }

		// Control: an account that was never deleted accepts the grant.
		if err := s.SaveRefreshTokenForGrant(ctx, plain("never-deleted"), mk(), time.Now().Add(-time.Minute)); err != nil {
			t.Fatalf("save for a never-deleted account: %v", err)
		}

		codeIssued := time.Now().UTC().Add(-time.Second)
		if _, err := s.HardDeleteAccount(ctx, uid); err != nil {
			t.Fatalf("delete: %v", err)
		}
		err = s.SaveRefreshTokenForGrant(ctx, plain("before"), mk(), codeIssued)
		if !errors.Is(err, ErrAccountDeletedSinceGrant) {
			t.Fatalf("save for a code issued before the delete: err = %v, want ErrAccountDeletedSinceGrant", err)
		}
		if n := liveRefreshTokens(t, s, uid); n != 0 {
			t.Fatalf("live refresh tokens after a refused grant = %d, want 0", n)
		}

		if err := s.SaveRefreshTokenForGrant(ctx, plain("after"), mk(), time.Now().UTC().Add(time.Second)); err != nil {
			t.Fatalf("save for a code issued after the delete: %v", err)
		}
		if n := liveRefreshTokens(t, s, uid); n != 1 {
			t.Fatalf("live refresh tokens after a post-delete grant = %d, want 1", n)
		}
	})
}

// An inconclusive dialect probe must fail the call rather than read as "not
// Postgres", which would drop the users-row lock on a live Postgres.
func TestCredentialWrites_FailOnInconclusiveDialectProbe(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	withSessionCrypt(t, s)
	uid, err := s.EnsureUserByTelegramID(ctx, 4646, "alice", "Alice")
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	mk := func(fam string) RefreshToken {
		return RefreshToken{FamilyID: fam, UserID: uid, ClientID: "claude.ai", TelegramID: 4646,
			Scope: "telegram:dialogs:read", ExpiresAt: time.Now().Add(time.Hour)}
	}
	if err := s.SaveRefreshToken(ctx, "probe-old", mk("probe-fam")); err != nil {
		t.Fatalf("seed refresh token: %v", err)
	}
	s.pgMu.Lock()
	s.pgResolved = false
	s.probeFail = func() error { return errors.New("driver: bad connection") }
	s.pgMu.Unlock()

	if err := s.SaveRefreshTokenForGrant(ctx, "probe-grant", mk("probe-grant-fam"), time.Now()); err == nil {
		t.Error("SaveRefreshTokenForGrant succeeded on an inconclusive dialect probe")
	}
	if err := s.RotateRefreshToken(ctx, "probe-old", "probe-new", mk("probe-fam")); err == nil {
		t.Error("RotateRefreshToken succeeded on an inconclusive dialect probe")
	}
	if _, err := s.HardDeleteAccount(ctx, uid); err == nil {
		t.Error("HardDeleteAccount succeeded on an inconclusive dialect probe")
	}
	// Both session saves lock the users row first on Postgres, so the plain
	// CLI-login save and the enable-flow save cannot deadlock (#824).
	if err := s.SaveSession(ctx, uid, []byte("mtproto-session"), 4646, "Alice", "alice"); err == nil {
		t.Error("SaveSession succeeded on an inconclusive dialect probe")
	}
	if err := s.SaveSessionForSignIn(ctx, uid, []byte("mtproto-session"), 4646, "Alice", "alice", time.Now()); err == nil {
		t.Error("SaveSessionForSignIn succeeded on an inconclusive dialect probe")
	}
	var sessions int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM telegram_accounts WHERE user_id = $1`, uid).Scan(&sessions); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if sessions != 0 {
		t.Errorf("%d telegram_accounts rows after refused session saves", sessions)
	}

	var total, live int
	if err := s.DB.QueryRowContext(ctx,
		`SELECT COUNT(*), SUM(CASE WHEN revoked_at IS NULL THEN 1 ELSE 0 END) FROM oauth_refresh_tokens WHERE user_id = $1`,
		uid).Scan(&total, &live); err != nil {
		t.Fatalf("count refresh tokens: %v", err)
	}
	if total != 1 || live != 1 {
		t.Errorf("refresh tokens total=%d live=%d after refused writes, want only the seeded live one", total, live)
	}
	var deleted int
	if err := s.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM users WHERE id = $1 AND account_deleted_at IS NOT NULL`, uid).Scan(&deleted); err != nil {
		t.Fatalf("read deletion marker: %v", err)
	}
	if deleted != 0 {
		t.Error("a refused delete set account_deleted_at")
	}

	// Once the probe resolves again the same calls go through.
	s.pgMu.Lock()
	s.probeFail = nil
	s.pgMu.Unlock()
	if err := s.SaveRefreshTokenForGrant(ctx, "probe-grant", mk("probe-grant-fam"), time.Now()); err != nil {
		t.Errorf("save after the probe recovered: %v", err)
	}
}

// NewStore resolves the dialect from the driver, so the credential writes
// never depend on the probe for a store opened by Open.
func TestNewStore_ResolvesDialectFromDriver(t *testing.T) {
	deletionDialects(t, func(t *testing.T, s *Store, _ int64) {
		fresh := NewStore(s.DB, nil)
		fresh.probeFail = func() error { return errors.New("driver: bad connection") }
		pg, err := fresh.postgresDialect(context.Background())
		if err != nil {
			t.Fatalf("dialect of a store opened by Open: %v", err)
		}
		// The subtest, not the driver, says which database this is: deriving
		// it from the driver type would repeat NewStore's own assertion.
		wantPg := strings.HasSuffix(t.Name(), "/postgres")
		if pg != wantPg {
			t.Fatalf("postgresDialect = %v, want %v", pg, wantPg)
		}
	})
}

// The code exchange and the delete race on Postgres: whichever commits first,
// no refresh token issued for a pre-delete code may be left live.
func TestSaveRefreshTokenForGrant_PostgresConcurrentDelete(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	s := newPostgresTestStore(t, dsn)
	ctx := context.Background()

	run := time.Now().UnixNano()
	for round := 0; round < 10; round++ {
		tgID := int64(860000000 + round)
		uid, err := s.EnsureUserByTelegramID(ctx, tgID, "alice", "Alice")
		if err != nil {
			t.Fatalf("round %d ensure: %v", round, err)
		}
		// The users row is reused across runs: clear an earlier run's marker
		// and tokens so the code below counts as issued before this delete.
		if _, err := s.DB.ExecContext(ctx, `UPDATE users SET account_deleted_at = NULL WHERE id = $1`, uid); err != nil {
			t.Fatalf("round %d reset marker: %v", round, err)
		}
		if _, err := s.DB.ExecContext(ctx, `DELETE FROM oauth_refresh_tokens WHERE user_id = $1`, uid); err != nil {
			t.Fatalf("round %d clear rows: %v", round, err)
		}
		codeIssued := time.Now().UTC().Add(-time.Second)
		rt := RefreshToken{FamilyID: fmt.Sprintf("grant-race-fam-%d-%d", run, round), UserID: uid, ClientID: "claude.ai",
			TelegramID: tgID, Scope: "telegram:dialogs:read", ExpiresAt: time.Now().Add(time.Hour)}

		var wg sync.WaitGroup
		start := make(chan struct{})
		var saveErr, delErr error
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			saveErr = s.SaveRefreshTokenForGrant(ctx, fmt.Sprintf("grant-race-%d-%d", run, round), rt, codeIssued)
		}()
		go func() {
			defer wg.Done()
			<-start
			_, delErr = s.HardDeleteAccount(ctx, uid)
		}()
		close(start)
		wg.Wait()

		if delErr != nil {
			t.Fatalf("round %d delete: %v", round, delErr)
		}
		if saveErr != nil && !errors.Is(saveErr, ErrAccountDeletedSinceGrant) {
			t.Fatalf("round %d save: %v", round, saveErr)
		}
		if n := liveRefreshTokens(t, s, uid); n != 0 {
			t.Fatalf("round %d: %d live refresh tokens after the delete (save err = %v)", round, n, saveErr)
		}
	}
}

// A delete that starts after the exchange read the deletion marker, but
// before it inserted the token, must wait for the insert and then revoke the
// new family. Without the share lock the delete finishes in between and the
// token it never saw stays live.
func TestSaveRefreshTokenForGrant_PostgresDeleteBetweenCheckAndInsert(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	s := newPostgresTestStore(t, dsn)
	ctx := context.Background()
	tgID := int64(870000000)
	uid, err := s.EnsureUserByTelegramID(ctx, tgID, "alice", "Alice")
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE users SET account_deleted_at = NULL WHERE id = $1`, uid); err != nil {
		t.Fatalf("reset marker: %v", err)
	}
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM oauth_refresh_tokens WHERE user_id = $1`, uid); err != nil {
		t.Fatalf("clear rows: %v", err)
	}

	delDone := make(chan error, 1)
	s.grantSaveHook = func() {
		go func() { _, err := s.HardDeleteAccount(ctx, uid); delDone <- err }()
		// Give the delete time to finish if nothing holds it back.
		select {
		case err := <-delDone:
			delDone <- err
		case <-time.After(500 * time.Millisecond):
		}
	}
	defer func() { s.grantSaveHook = nil }()

	run := time.Now().UnixNano()
	rt := RefreshToken{FamilyID: fmt.Sprintf("grant-gap-fam-%d", run), UserID: uid, ClientID: "claude.ai",
		TelegramID: tgID, Scope: "telegram:dialogs:read", ExpiresAt: time.Now().Add(time.Hour)}
	if err := s.SaveRefreshTokenForGrant(ctx, fmt.Sprintf("grant-gap-%d", run), rt, time.Now().UTC().Add(-time.Second)); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := <-delDone; err != nil {
		t.Fatalf("delete: %v", err)
	}
	if n := liveRefreshTokens(t, s, uid); n != 0 {
		t.Fatalf("%d live refresh tokens after a delete that ran between the check and the insert", n)
	}
}

func testOAuthCode(tgID int64, createdAt time.Time) OAuthCode {
	return OAuthCode{Code: fmt.Sprintf("code-%d-%d", tgID, time.Now().UnixNano()), ClientID: "claude.ai",
		RedirectURI: "https://claude.ai/cb", CodeChallenge: "challenge", ChallengeMethod: "S256",
		TelegramID: tgID, Scope: "telegram:dialogs:read", CreatedAt: createdAt}
}

func storedOAuthCodes(t *testing.T, s *Store, tgID int64) int {
	t.Helper()
	var n int
	if err := s.DB.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM oauth_auth_codes WHERE telegram_id = $1`, tgID).Scan(&n); err != nil {
		t.Fatalf("count auth codes: %v", err)
	}
	return n
}

// A sign-in that started before the account was deleted gets no code (#817);
// one started after the delete, by a user signing in again, still does.
func TestInsertOAuthCode_RefusesSignInStartedBeforeDelete(t *testing.T) {
	deletionDialects(t, func(t *testing.T, s *Store, base int64) {
		ctx := context.Background()
		// SQLite has no oauth_auth_codes table: there the server keeps codes
		// in memory and checks with AccountDeletedSince alone.
		codeTable := strings.HasSuffix(t.Name(), "/postgres")
		tgID := base + 1
		uid, err := s.EnsureUserByTelegramID(ctx, tgID, "alice", "Alice")
		if err != nil {
			t.Fatalf("ensure: %v", err)
		}

		// Control: an account that was never deleted gets its code.
		early := time.Now().UTC().Add(-time.Minute)
		if ok, err := s.AccountDeletedSince(ctx, uid, early); err != nil || ok {
			t.Fatalf("AccountDeletedSince(never deleted) = %v, %v; want false", ok, err)
		}
		if codeTable {
			if err := s.InsertOAuthCode(ctx, testOAuthCode(tgID, time.Now().UTC()), uid, early); err != nil {
				t.Fatalf("insert for a never-deleted account: %v", err)
			}
		}

		signInStarted := time.Now().UTC().Add(-time.Second)
		if _, err := s.HardDeleteAccount(ctx, uid); err != nil {
			t.Fatalf("delete: %v", err)
		}
		if ok, err := s.AccountDeletedSince(ctx, uid, signInStarted); err != nil || !ok {
			t.Fatalf("AccountDeletedSince(started before delete) = %v, %v; want true", ok, err)
		}
		after := time.Now().UTC().Add(time.Second)
		if ok, err := s.AccountDeletedSince(ctx, uid, after); err != nil || ok {
			t.Fatalf("AccountDeletedSince(started after delete) = %v, %v; want false", ok, err)
		}
		// Could not read is never "not deleted".
		if _, err := s.AccountDeletedSince(ctx, uid+1000000, after); err == nil {
			t.Error("AccountDeletedSince for a missing users row succeeded")
		}
		if _, err := s.AccountDeletedSince(ctx, uid, time.Time{}); err == nil {
			t.Error("AccountDeletedSince with no time succeeded")
		}
		if !codeTable {
			return
		}

		before := storedOAuthCodes(t, s, tgID)
		err = s.InsertOAuthCode(ctx, testOAuthCode(tgID, time.Now().UTC()), uid, signInStarted)
		if !errors.Is(err, ErrAccountDeletedSinceGrant) {
			t.Fatalf("insert for a sign-in started before the delete: err = %v, want ErrAccountDeletedSinceGrant", err)
		}
		if n := storedOAuthCodes(t, s, tgID); n != before {
			t.Fatalf("auth codes after a refused insert = %d, want %d", n, before)
		}
		if err := s.InsertOAuthCode(ctx, testOAuthCode(tgID, after), uid, after); err != nil {
			t.Fatalf("insert for a sign-in started after the delete: %v", err)
		}
		if err := s.InsertOAuthCode(ctx, testOAuthCode(tgID, after), uid, time.Time{}); err == nil {
			t.Error("insert with no sign-in start succeeded")
		}
		if err := s.InsertOAuthCode(ctx, testOAuthCode(tgID, after), uid+1000000, after); err == nil {
			t.Error("insert for a missing users row succeeded")
		}
	})
}

// A code stamped after the delete wrote its marker, but before the delete
// committed, is the #817 gap: without the users-row lock on the code insert
// it lands mid-delete, post-dates the marker, and its exchange mints a family
// the delete never saw. With the lock the insert waits for the commit and is
// then refused, because the sign-in started before the delete.
func TestInsertOAuthCode_PostgresCodeIssuedDuringDelete(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	s := newPostgresTestStore(t, dsn)
	ctx := context.Background()
	tgID := int64(880000000)
	uid, err := s.EnsureUserByTelegramID(ctx, tgID, "alice", "Alice")
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE users SET account_deleted_at = NULL WHERE id = $1`, uid); err != nil {
		t.Fatalf("reset marker: %v", err)
	}
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM oauth_refresh_tokens WHERE user_id = $1`, uid); err != nil {
		t.Fatalf("clear rows: %v", err)
	}

	signInStarted := time.Now().UTC().Add(-time.Second)
	var code OAuthCode
	insDone := make(chan error, 1)
	s.deleteMarkerHook = func() {
		code = testOAuthCode(tgID, time.Now().UTC())
		go func() { insDone <- s.InsertOAuthCode(ctx, code, uid, signInStarted) }()
		// Give the insert time to finish if nothing holds it back.
		select {
		case err := <-insDone:
			insDone <- err
		case <-time.After(500 * time.Millisecond):
		}
	}
	defer func() { s.deleteMarkerHook = nil }()

	if _, err := s.HardDeleteAccount(ctx, uid); err != nil {
		t.Fatalf("delete: %v", err)
	}
	insErr := <-insDone
	if insErr == nil {
		// The contract is that no code is stored (asserted below). This
		// block only localises a failure: when the insert slipped through,
		// it shows whether the code also mints a live family, which is the
		// #817 hole itself, instead of a bare error mismatch.
		run := time.Now().UnixNano()
		rt := RefreshToken{FamilyID: fmt.Sprintf("code-gap-fam-%d", run), UserID: uid, ClientID: "claude.ai",
			TelegramID: tgID, Scope: "telegram:dialogs:read", ExpiresAt: time.Now().Add(time.Hour)}
		_ = s.SaveRefreshTokenForGrant(ctx, fmt.Sprintf("code-gap-%d", run), rt, code.CreatedAt)
		if n := liveRefreshTokens(t, s, uid); n != 0 {
			t.Fatalf("a code issued during the delete minted %d live refresh tokens", n)
		}
	}
	if !errors.Is(insErr, ErrAccountDeletedSinceGrant) {
		t.Fatalf("insert during the delete: err = %v, want ErrAccountDeletedSinceGrant", insErr)
	}
}

// Delete clears the username; signing in again fills it back only when
// Telegram supplies one (#817). The localjwt issuer sends an empty claim
// (issuer.go), and that must leave the field NULL rather than restore it.
func TestHardDeleteAccount_ReSignInRefillsUsername(t *testing.T) {
	deletionDialects(t, func(t *testing.T, s *Store, base int64) {
		ctx := context.Background()
		username := func(uid int64) sql.NullString {
			t.Helper()
			var name sql.NullString
			if err := s.DB.QueryRowContext(ctx, `SELECT telegram_username FROM users WHERE id = $1`, uid).Scan(&name); err != nil {
				t.Fatalf("read username: %v", err)
			}
			return name
		}
		for _, tc := range []struct {
			name, signInUser, signInDisplay string
			want                            sql.NullString
		}{
			{"named", "alice", "Alice", sql.NullString{String: "alice", Valid: true}},
			{"empty claim", "", "", sql.NullString{}},
		} {
			tgID := base + 10
			if tc.signInUser == "" {
				tgID = base + 11
			}
			uid, err := s.EnsureUserByTelegramID(ctx, tgID, "alice", "Alice")
			if err != nil {
				t.Fatalf("%s: ensure: %v", tc.name, err)
			}
			if _, err := s.HardDeleteAccount(ctx, uid); err != nil {
				t.Fatalf("%s: delete: %v", tc.name, err)
			}
			if got := username(uid); got.Valid {
				t.Fatalf("%s: username = %q after the delete, want NULL", tc.name, got.String)
			}
			again, err := s.EnsureUserByTelegramID(ctx, tgID, tc.signInUser, tc.signInDisplay)
			if err != nil {
				t.Fatalf("%s: sign in again: %v", tc.name, err)
			}
			if again != uid {
				t.Fatalf("%s: sign-in again resolved user %d, want %d", tc.name, again, uid)
			}
			if got := username(uid); got != tc.want {
				t.Errorf("%s: username after signing in again = %+v, want %+v", tc.name, got, tc.want)
			}
		}
	})
}

// withSessionCrypt gives a deletionDialects store the (keyless, plaintext)
// crypt that session writes need.
func withSessionCrypt(t *testing.T, s *Store) {
	t.Helper()
	if s.Crypt != nil {
		return
	}
	c, err := crypto.New(nil)
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}
	s.Crypt = c
}

func activeSessionRows(t *testing.T, s *Store, uid int64) int {
	t.Helper()
	var n int
	if err := s.DB.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM telegram_accounts WHERE user_id = $1 AND revoked_at IS NULL`, uid).Scan(&n); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	return n
}

// A login whose sign-in started before the account was deleted must not
// leave its session behind (#821): the refusal also drops the row the gotd
// store wrote. A sign-in started after the delete saves as usual.
func TestSaveSessionForSignIn_RefusesSignInStartedBeforeDelete(t *testing.T) {
	deletionDialects(t, func(t *testing.T, s *Store, base int64) {
		ctx := context.Background()
		withSessionCrypt(t, s)
		tgID := base + 20
		uid, err := s.EnsureUserByTelegramID(ctx, tgID, "alice", "Alice")
		if err != nil {
			t.Fatalf("ensure: %v", err)
		}
		save := func(start time.Time) error {
			// The gotd SessionStore writes the bytes before SaveSession runs.
			if err := s.UpdateSessionBlob(ctx, uid, []byte("mtproto-session")); err != nil {
				t.Fatalf("write session bytes: %v", err)
			}
			return s.SaveSessionForSignIn(ctx, uid, []byte("mtproto-session"), tgID, "Alice", "alice", start)
		}

		// Control: an account that was never deleted keeps its session.
		if err := save(time.Now().UTC().Add(-time.Minute)); err != nil {
			t.Fatalf("save for a never-deleted account: %v", err)
		}
		if n := activeSessionRows(t, s, uid); n != 1 {
			t.Fatalf("active sessions after a normal save = %d, want 1", n)
		}

		signInStarted := time.Now().UTC().Add(-time.Second)
		if _, err := s.HardDeleteAccount(ctx, uid); err != nil {
			t.Fatalf("delete: %v", err)
		}
		if err := save(signInStarted); !errors.Is(err, ErrAccountDeletedSinceGrant) {
			t.Fatalf("save for a sign-in started before the delete: err = %v, want ErrAccountDeletedSinceGrant", err)
		}
		var rows int
		if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM telegram_accounts WHERE user_id = $1`, uid).Scan(&rows); err != nil {
			t.Fatalf("count rows: %v", err)
		}
		if rows != 0 {
			t.Fatalf("%d telegram_accounts rows left after a refused save, want 0", rows)
		}

		if err := save(time.Now().UTC().Add(time.Second)); err != nil {
			t.Fatalf("save for a sign-in started after the delete: %v", err)
		}
		if n := activeSessionRows(t, s, uid); n != 1 {
			t.Fatalf("active sessions after a post-delete save = %d, want 1", n)
		}
		if err := s.SaveSessionForSignIn(ctx, uid, []byte("x"), tgID, "", "", time.Time{}); err == nil {
			t.Error("save with no sign-in start succeeded")
		}
	})
}

// A local (Local Bridge) row is not the refused login's to drop: only hosted
// rows go, and the caller's stray-blob repair handles a local row's bytes.
func TestSaveSessionForSignIn_RefusalKeepsLocalRows(t *testing.T) {
	deletionDialects(t, func(t *testing.T, s *Store, base int64) {
		ctx := context.Background()
		withSessionCrypt(t, s)
		tgID := base + 21
		uid, err := s.EnsureUserByTelegramID(ctx, tgID, "bob", "Bob")
		if err != nil {
			t.Fatalf("ensure: %v", err)
		}
		signInStarted := time.Now().UTC().Add(-time.Second)
		if _, err := s.HardDeleteAccount(ctx, uid); err != nil {
			t.Fatalf("delete: %v", err)
		}
		if _, err := s.DB.ExecContext(ctx,
			`INSERT INTO telegram_accounts(user_id, telegram_user_id, mode) VALUES($1, $2, $3)`,
			uid, tgID, ModeLocal); err != nil {
			t.Fatalf("seed local row: %v", err)
		}
		if err := s.SaveSessionForSignIn(ctx, uid, []byte("mtproto-session"), tgID, "Bob", "bob", signInStarted); !errors.Is(err, ErrAccountDeletedSinceGrant) {
			t.Fatalf("save: err = %v, want ErrAccountDeletedSinceGrant", err)
		}
		var local int
		if err := s.DB.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM telegram_accounts WHERE user_id = $1 AND mode = $2`, uid, ModeLocal).Scan(&local); err != nil {
			t.Fatalf("count local rows: %v", err)
		}
		if local != 1 {
			t.Fatalf("local rows after a refused save = %d, want 1", local)
		}
	})
}

// The #821 race on Postgres: the login writes its session bytes after the
// delete removed the rows but before it committed, so the delete never sees
// them. SaveSessionForSignIn then waits on the users-row lock, sees the
// marker and drops the row. Without the lock it saves mid-delete and the
// session outlives the delete.
func TestSaveSessionForSignIn_PostgresLoginDuringDelete(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	s := newPostgresTestStore(t, dsn)
	withSessionCrypt(t, s)
	ctx := context.Background()
	tgID := int64(890000000)
	uid, err := s.EnsureUserByTelegramID(ctx, tgID, "alice", "Alice")
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE users SET account_deleted_at = NULL WHERE id = $1`, uid); err != nil {
		t.Fatalf("reset marker: %v", err)
	}
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM telegram_accounts WHERE user_id = $1`, uid); err != nil {
		t.Fatalf("clear rows: %v", err)
	}

	signInStarted := time.Now().UTC().Add(-time.Second)
	saveDone := make(chan error, 1)
	s.deleteMarkerHook = func() {
		go func() {
			if err := s.UpdateSessionBlob(ctx, uid, []byte("mtproto-session")); err != nil {
				saveDone <- fmt.Errorf("write session bytes: %w", err)
				return
			}
			saveDone <- s.SaveSessionForSignIn(ctx, uid, []byte("mtproto-session"), tgID, "Alice", "alice", signInStarted)
		}()
		// Give the save time to finish if nothing holds it back.
		select {
		case err := <-saveDone:
			saveDone <- err
		case <-time.After(500 * time.Millisecond):
		}
	}
	defer func() { s.deleteMarkerHook = nil }()

	if _, err := s.HardDeleteAccount(ctx, uid); err != nil {
		t.Fatalf("delete: %v", err)
	}
	saveErr := <-saveDone
	var rows int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM telegram_accounts WHERE user_id = $1`, uid).Scan(&rows); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if rows != 0 {
		t.Fatalf("%d telegram_accounts rows survive a delete the login raced (save err = %v)", rows, saveErr)
	}
	if !errors.Is(saveErr, ErrAccountDeletedSinceGrant) {
		t.Fatalf("save during the delete: err = %v, want ErrAccountDeletedSinceGrant", saveErr)
	}
}

// TestSaveSessionForSignIn_PostgresDeleteDuringLogin is the mirror of
// TestSaveSessionForSignIn_PostgresLoginDuringDelete: the save holds the
// users-row lock first and a delete queues behind it while the save goes on
// to insert its row and update the users row. Both must finish, and the
// delete, committing second, must remove the row the save wrote.
func TestSaveSessionForSignIn_PostgresDeleteDuringLogin(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	s := newPostgresTestStore(t, dsn)
	withSessionCrypt(t, s)
	ctx := context.Background()
	tgID := int64(890000000)
	uid, err := s.EnsureUserByTelegramID(ctx, tgID, "alice", "Alice")
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE users SET account_deleted_at = NULL, onboarding_completed_at = NULL WHERE id = $1`, uid); err != nil {
		t.Fatalf("reset user: %v", err)
	}
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM telegram_accounts WHERE user_id = $1`, uid); err != nil {
		t.Fatalf("clear rows: %v", err)
	}

	signInStarted := time.Now().UTC().Add(-time.Second)
	deleteDone := make(chan error, 1)
	s.sessionSaveHook = func(tx *sql.Tx) {
		go func() {
			_, err := s.HardDeleteAccount(ctx, uid)
			deleteDone <- err
		}()
		// Return once the delete is queued on the users-row lock.
		if err := waitBlockedBy(ctx, s, tx); err != nil {
			t.Errorf("delete never queued on the users-row lock: %v", err)
		}
	}
	defer func() { s.sessionSaveHook = nil }()

	saveErr := s.SaveSessionForSignIn(ctx, uid, []byte("mtproto-session"), tgID, "Alice", "alice", signInStarted)
	deleteErr := <-deleteDone
	if saveErr != nil {
		t.Fatalf("save ahead of the delete: %v", saveErr)
	}
	if deleteErr != nil {
		t.Fatalf("delete queued behind the save: %v", deleteErr)
	}
	var rows int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM telegram_accounts WHERE user_id = $1`, uid).Scan(&rows); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if rows != 0 {
		t.Fatalf("%d telegram_accounts rows survive the delete that followed the save", rows)
	}
}

// waitBlockedBy returns once some backend waits on a lock held by tx. It
// matches waiters through pg_blocking_pids of tx's own backend rather than
// any lock wait in the database: internal/oauth shares TEST_DATABASE_URL and
// runs in parallel, so one of its waiters must not end the poll early.
func waitBlockedBy(ctx context.Context, s *Store, tx *sql.Tx) error {
	var holder int
	if err := tx.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&holder); err != nil {
		return fmt.Errorf("read holder pid: %w", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var waiting int
		if err := s.DB.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid))`, holder,
		).Scan(&waiting); err != nil {
			return fmt.Errorf("poll lock waiters: %w", err)
		}
		if waiting > 0 {
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return errors.New("timed out")
}

// TestSaveSession_PostgresLockOrderAgreesWithSignIn runs a plain SaveSession
// (the CLI login) while a SaveSessionForSignIn of the same user holds the
// users-row lock. Both must lock users before telegram_accounts: if the plain
// save revoked the active row first and only then updated users, the sign-in
// would wait on that row while the plain save waits on users, and Postgres
// would abort one of them with a deadlock (40P01).
func TestSaveSession_PostgresLockOrderAgreesWithSignIn(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	s := newPostgresTestStore(t, dsn)
	withSessionCrypt(t, s)
	ctx := context.Background()
	tgID := int64(890000001)
	uid, err := s.EnsureUserByTelegramID(ctx, tgID, "bob", "Bob")
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE users SET account_deleted_at = NULL WHERE id = $1`, uid); err != nil {
		t.Fatalf("reset marker: %v", err)
	}
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM telegram_accounts WHERE user_id = $1`, uid); err != nil {
		t.Fatalf("clear rows: %v", err)
	}
	// An active row for the plain save's revoke to lock.
	if err := s.SaveSession(ctx, uid, []byte("mtproto-session"), tgID, "Bob", "bob"); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	signInStarted := time.Now().UTC().Add(-time.Second)
	plainDone := make(chan error, 1)
	s.sessionSaveHook = func(tx *sql.Tx) {
		go func() {
			plainDone <- s.SaveSession(ctx, uid, []byte("mtproto-session"), tgID, "Bob", "bob")
		}()
		// Return once the plain save waits on this transaction: on its
		// users-row lock, or, with the old order, on its onboarding stamp
		// after it already revoked the active row.
		if err := waitBlockedBy(ctx, s, tx); err != nil {
			t.Errorf("plain save never queued behind the sign-in: %v", err)
		}
	}
	defer func() { s.sessionSaveHook = nil }()

	signInErr := s.SaveSessionForSignIn(ctx, uid, []byte("mtproto-session"), tgID, "Bob", "bob", signInStarted)
	plainErr := <-plainDone
	if signInErr != nil {
		t.Fatalf("sign-in save: %v", signInErr)
	}
	if plainErr != nil {
		t.Fatalf("plain save queued behind the sign-in: %v", plainErr)
	}
	var active int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM telegram_accounts WHERE user_id = $1 AND revoked_at IS NULL`, uid).Scan(&active); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if active != 1 {
		t.Fatalf("%d active telegram_accounts rows, want 1", active)
	}
}
