package db

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	_ "modernc.org/sqlite"

	"github.com/mctlhq/mctl-telegram/internal/metrics"
)

// TestListIdentities checks the roster: fresh widget-authenticated users appear
// with a populated CreatedAt and an empty (unset) raw access_tier.
func TestListIdentities(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	if _, err := st.EnsureUserByTelegramID(ctx, 111, "alice", "Alice"); err != nil {
		t.Fatalf("ensure 111: %v", err)
	}
	if _, err := st.EnsureUserByTelegramID(ctx, 222, "bob", "Bob"); err != nil {
		t.Fatalf("ensure 222: %v", err)
	}
	rows, err := st.ListIdentities(ctx)
	if err != nil {
		t.Fatalf("ListIdentities: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("ListIdentities len = %d, want 2", len(rows))
	}
	for _, r := range rows {
		if r.CreatedAt.IsZero() {
			t.Errorf("identity %d has zero CreatedAt", r.TelegramID)
		}
		if r.AccessTier != "" {
			t.Errorf("fresh identity %d should have empty access_tier, got %q", r.TelegramID, r.AccessTier)
		}
	}
}

// seedAccount inserts a telegram_accounts row with explicit lifecycle
// timestamps. A nil pointer leaves that column NULL.
func seedAccount(t *testing.T, s *Store, userID int64, lastUsed, expiresAt, revokedAt *time.Time) {
	t.Helper()
	if _, err := s.DB.ExecContext(context.Background(),
		`INSERT INTO telegram_accounts(user_id, session_encrypted, last_used_at, expires_at, revoked_at)
		 VALUES($1,$2,$3,$4,$5)`,
		userID, []byte("blob"), lastUsed, expiresAt, revokedAt,
	); err != nil {
		t.Fatalf("seed account: %v", err)
	}
}

func TestSweepIdleSessions(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUser(ctx, "idle-user", "", "test")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	now := time.Now().UTC()
	old := now.Add(-40 * 24 * time.Hour) // older than the 30d idle TTL
	fresh := now.Add(-24 * time.Hour)    // well within the idle TTL
	revoked := now.Add(-time.Hour)

	seedAccount(t, s, uid, &old, nil, nil)      // active + idle  -> swept
	seedAccount(t, s, uid, &fresh, nil, nil)    // active + fresh -> kept
	seedAccount(t, s, uid, &old, nil, &revoked) // already revoked -> ignored

	n, err := s.SweepIdleSessions(ctx)
	if err != nil {
		t.Fatalf("SweepIdleSessions: %v", err)
	}
	if n != 1 {
		t.Fatalf("SweepIdleSessions revoked %d rows, want 1", n)
	}
	// The fresh row must still be active.
	var active int
	if err := s.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM telegram_accounts WHERE user_id=$1 AND revoked_at IS NULL`, uid,
	).Scan(&active); err != nil {
		t.Fatalf("count active: %v", err)
	}
	if active != 1 {
		t.Fatalf("after idle sweep %d rows still active, want 1", active)
	}
}

func TestSweepAbsoluteSessions(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUser(ctx, "abs-user", "", "test")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	now := time.Now().UTC()
	past := now.Add(-time.Hour)            // expires_at in the past
	future := now.Add(30 * 24 * time.Hour) // expires_at well in the future
	revoked := now.Add(-time.Hour)

	seedAccount(t, s, uid, &now, &past, nil)      // active + expired -> swept
	seedAccount(t, s, uid, &now, &future, nil)    // active + valid   -> kept
	seedAccount(t, s, uid, &now, nil, nil)        // active + no expiry -> kept
	seedAccount(t, s, uid, &now, &past, &revoked) // already revoked  -> ignored

	n, err := s.SweepAbsoluteSessions(ctx)
	if err != nil {
		t.Fatalf("SweepAbsoluteSessions: %v", err)
	}
	if n != 1 {
		t.Fatalf("SweepAbsoluteSessions revoked %d rows, want 1", n)
	}
}

func TestCountActiveSessions(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUser(ctx, "count-user", "", "test")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	now := time.Now().UTC()
	recent := now.Add(-10 * time.Minute) // used within the last hour
	stale := now.Add(-2 * time.Hour)     // used more than an hour ago
	revoked := now.Add(-time.Minute)

	seedAccount(t, s, uid, &recent, nil, nil)      // active + recent     -> counted
	seedAccount(t, s, uid, nil, nil, nil)          // active + never used -> counted
	seedAccount(t, s, uid, &stale, nil, nil)       // active + stale      -> not counted
	seedAccount(t, s, uid, &recent, nil, &revoked) // revoked             -> not counted

	n, err := s.CountActiveSessions(ctx)
	if err != nil {
		t.Fatalf("CountActiveSessions: %v", err)
	}
	if n != 2 {
		t.Fatalf("CountActiveSessions = %d, want 2 (recent + never-used)", n)
	}
}

// TestHardDeleteAccount_DeleteMetricCountsOnlyActiveRows pins the fix for the
// review finding: mctl_sessions_revoked_total{reason="delete"} must count only
// the rows that were still active at delete time, not already-revoked rows.
func TestHardDeleteAccount_DeleteMetricCountsOnlyActiveRows(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t).WithMetrics(metrics.New())
	uid, err := s.EnsureUser(ctx, "del-user", "", "test")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	now := time.Now().UTC()
	revoked := now.Add(-time.Hour)
	seedAccount(t, s, uid, &now, nil, nil)      // active
	seedAccount(t, s, uid, &now, nil, nil)      // active
	seedAccount(t, s, uid, &now, nil, &revoked) // already revoked

	removed, err := s.HardDeleteAccount(ctx, uid)
	if err != nil {
		t.Fatalf("HardDeleteAccount: %v", err)
	}
	if removed != 3 {
		t.Fatalf("HardDeleteAccount removed %d rows, want 3", removed)
	}
	got := testutil.ToFloat64(s.metrics.SessionsRevokedTotal.WithLabelValues("delete"))
	if got != 2 {
		t.Fatalf("delete revocation metric = %v, want 2 (only the active rows)", got)
	}
}

// newTestStore opens an in-memory SQLite DB, applies the migration, and
// returns a Store wired with a nil crypto (Seal/Open passthrough). Session
// blobs in these tests are arbitrary bytes — we never decrypt them.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	ctx := context.Background()
	conn, err := Open(ctx, "file::memory:?cache=shared", 0, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := Migrate(ctx, conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return &Store{DB: conn, Crypt: nil}
}

func TestRevokeActiveSession_FlipsOnceAndIsIdempotent(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUser(ctx, "alice", "", "test")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, session_encrypted) VALUES($1, $2)`,
		uid, []byte("blob"),
	); err != nil {
		t.Fatalf("seed account: %v", err)
	}

	had, err := s.RevokeActiveSession(ctx, uid, "disconnect")
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if !had {
		t.Fatal("first revoke should report had=true")
	}

	had2, err := s.RevokeActiveSession(ctx, uid, "disconnect")
	if err != nil {
		t.Fatalf("revoke 2: %v", err)
	}
	if had2 {
		t.Fatal("second revoke should report had=false (idempotent)")
	}
}

func TestRevokeActiveSession_NoSession(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUser(ctx, "bob", "", "test")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}

	had, err := s.RevokeActiveSession(ctx, uid, "disconnect")
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if had {
		t.Fatal("revoke with no session should report had=false, no error")
	}
}

func TestHardDeleteAccount_RemovesAllRows(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUser(ctx, "carol", "", "test")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	// Two rows: one active, one revoked. HardDelete should kill both.
	for _, revoked := range []bool{false, false} {
		_, err := s.DB.ExecContext(ctx,
			`INSERT INTO telegram_accounts(user_id, session_encrypted) VALUES($1, $2)`,
			uid, []byte("blob"),
		)
		if err != nil {
			t.Fatalf("seed: %v", err)
		}
		_ = revoked
	}
	if _, err := s.DB.ExecContext(ctx,
		`UPDATE telegram_accounts SET revoked_at = CURRENT_TIMESTAMP WHERE id = (SELECT MIN(id) FROM telegram_accounts WHERE user_id = $1)`,
		uid,
	); err != nil {
		t.Fatalf("revoke seed: %v", err)
	}

	rows, err := s.HardDeleteAccount(ctx, uid)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if rows != 2 {
		t.Fatalf("expected 2 rows removed, got %d", rows)
	}

	var count int
	if err := s.DB.QueryRowContext(ctx,
		`SELECT count(*) FROM telegram_accounts WHERE user_id = $1`, uid,
	).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected 0 remaining rows, got %d", count)
	}
}

func TestGetActiveAccount_NoSession(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUser(ctx, "dave", "", "test")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	info, err := s.GetActiveAccount(ctx, uid)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if info == nil {
		t.Fatal("expected non-nil AccountInfo")
	}
	if info.Connected {
		t.Fatal("expected Connected=false when no session")
	}
}

func TestGetActiveAccount_ReturnsFields(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUser(ctx, "eve", "", "test")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, display_name, username, session_encrypted, send_enabled) VALUES($1,$2,$3,$4,$5)`,
		uid, "Eve E.", "eve_e", []byte("blob"), true,
	); err != nil {
		t.Fatalf("seed: %v", err)
	}
	info, err := s.GetActiveAccount(ctx, uid)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !info.Connected || info.DisplayName != "Eve E." || info.Username != "eve_e" || !info.SendEnabled {
		t.Fatalf("unexpected: %+v", info)
	}
	if info.ConnectedAt.IsZero() {
		t.Fatal("expected ConnectedAt populated")
	}
}

func TestIsSendEnabled_DefaultFalseAndRespectsFlag(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUser(ctx, "frank", "", "test")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}

	// No account at all → false, no error.
	enabled, err := s.IsSendEnabled(ctx, uid)
	if err != nil {
		t.Fatalf("no session: %v", err)
	}
	if enabled {
		t.Fatal("expected false when no session")
	}

	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, session_encrypted, send_enabled) VALUES($1, $2, $3)`,
		uid, []byte("blob"), false,
	); err != nil {
		t.Fatalf("seed: %v", err)
	}
	enabled, err = s.IsSendEnabled(ctx, uid)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if enabled {
		t.Fatal("expected false from seeded send_enabled=false")
	}

	if _, err := s.DB.ExecContext(ctx,
		`UPDATE telegram_accounts SET send_enabled = $1 WHERE user_id = $2`,
		true, uid,
	); err != nil {
		t.Fatalf("flip: %v", err)
	}
	enabled, err = s.IsSendEnabled(ctx, uid)
	if err != nil {
		t.Fatalf("read 2: %v", err)
	}
	if !enabled {
		t.Fatal("expected true after flip")
	}
}

// TestListIdentities_PartialSessionNotCounted checks that a mid-login session
// row (telegram_user_id NULL, as inserted by UpdateSessionBlob) is NOT
// reported as has_session — only a finalised SaveSession row counts.
func TestListIdentities_PartialSessionNotCounted(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	now := time.Now().UTC()

	partialUID, _ := s.EnsureUserByTelegramID(ctx, 111, "partial", "Partial")
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, session_encrypted, last_used_at, expires_at) VALUES($1,$2,$3,$4)`,
		partialUID, []byte("blob"), now, now.Add(90*24*time.Hour),
	); err != nil {
		t.Fatalf("seed partial: %v", err)
	}
	finalUID, _ := s.EnsureUserByTelegramID(ctx, 222, "final", "Final")
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, telegram_user_id, session_encrypted, last_used_at, expires_at) VALUES($1,$2,$3,$4,$5)`,
		finalUID, 222, []byte("blob"), now, now.Add(90*24*time.Hour),
	); err != nil {
		t.Fatalf("seed final: %v", err)
	}

	rows, err := s.ListIdentities(ctx)
	if err != nil {
		t.Fatalf("ListIdentities: %v", err)
	}
	got := map[int64]bool{}
	for _, r := range rows {
		got[r.TelegramID] = r.HasSession
	}
	if got[111] {
		t.Error("partial session (telegram_user_id NULL) must not count as has_session")
	}
	if !got[222] {
		t.Error("finalised session must count as has_session")
	}
}

// TestUserIDByTelegramID covers the read-only lookup: a hit returns the row
// id, a miss returns ErrUserNotFound without creating a row.
func TestUserIDByTelegramID(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	want, _ := s.EnsureUserByTelegramID(ctx, 777, "g", "G")

	got, err := s.UserIDByTelegramID(ctx, 777)
	if err != nil {
		t.Fatalf("lookup hit: %v", err)
	}
	if got != want {
		t.Fatalf("UserIDByTelegramID = %d, want %d", got, want)
	}

	if _, err := s.UserIDByTelegramID(ctx, 999); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("miss: expected ErrUserNotFound, got %v", err)
	}
	// The miss must NOT have created a row.
	if _, err := s.UserIDByTelegramID(ctx, 999); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("miss is not idempotent — a row was created: %v", err)
	}

	connectedOnly, err := s.EnsureUser(ctx, "connected-only", "", "local-dev")
	if err != nil {
		t.Fatalf("ensure connected-only user: %v", err)
	}
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, telegram_user_id, session_encrypted)
		 VALUES($1,$2,$3)`,
		connectedOnly, 888, []byte{0},
	); err != nil {
		t.Fatalf("seed connected account: %v", err)
	}
	if got, err := s.UserIDByTelegramID(ctx, 888); err != nil || got != connectedOnly {
		t.Fatalf("connected-account lookup = %d, %v; want %d", got, err, connectedOnly)
	}

	other, err := s.EnsureUserByTelegramID(ctx, 888, "other", "Other")
	if err != nil {
		t.Fatalf("ensure ambiguous login user: %v", err)
	}
	if other == connectedOnly {
		t.Fatal("ambiguity setup reused connected-only user")
	}
	if _, err := s.UserIDByTelegramID(ctx, 888); !errors.Is(err, ErrTelegramIdentityAmbiguous) {
		t.Fatalf("ambiguous lookup err = %v, want ErrTelegramIdentityAmbiguous", err)
	}
}

func TestToggleSendEnabled_AtomicFlip(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUser(ctx, "toggle-user", "", "test")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}

	// No active session → returns false, no error.
	val, err := s.ToggleSendEnabled(ctx, uid)
	if err != nil {
		t.Fatalf("no session: %v", err)
	}
	if val {
		t.Fatal("expected false when no active session")
	}

	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, session_encrypted, send_enabled) VALUES($1, $2, $3)`,
		uid, []byte("blob"), false,
	); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// false → true.
	val, err = s.ToggleSendEnabled(ctx, uid)
	if err != nil {
		t.Fatalf("first toggle: %v", err)
	}
	if !val {
		t.Fatal("expected true after first toggle")
	}

	// true → false.
	val, err = s.ToggleSendEnabled(ctx, uid)
	if err != nil {
		t.Fatalf("second toggle: %v", err)
	}
	if val {
		t.Fatal("expected false after second toggle")
	}
}

// TestListIdentities_ConnectedVia verifies that the connected_via field is
// populated from oauth_refresh_tokens.client_name (denormalized at issue time)
// and is not affected by oauth_client_registrations TTL sweeps.
func TestListIdentities_ConnectedVia(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	now := time.Now().UTC()

	uid, err := s.EnsureUserByTelegramID(ctx, 100, "alice", "Alice")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}

	// Active token with client_name set — should appear in connected_via.
	if err := s.SaveRefreshToken(ctx, "tok-active", RefreshToken{
		FamilyID:   "fam1",
		UserID:     uid,
		ClientID:   "client-claude",
		ClientName: "Claude",
		TelegramID: 100,
		ExpiresAt:  now.Add(30 * 24 * time.Hour),
	}); err != nil {
		t.Fatalf("save active token: %v", err)
	}

	// Expired token — must NOT appear.
	if err := s.SaveRefreshToken(ctx, "tok-expired", RefreshToken{
		FamilyID:   "fam2",
		UserID:     uid,
		ClientID:   "client-old",
		ClientName: "OldClient",
		TelegramID: 100,
		ExpiresAt:  now.Add(-time.Hour),
	}); err != nil {
		t.Fatalf("save expired token: %v", err)
	}

	// Token with empty client_name — must NOT appear (P3 filter).
	if err := s.SaveRefreshToken(ctx, "tok-noname", RefreshToken{
		FamilyID:   "fam3",
		UserID:     uid,
		ClientID:   "client-legacy",
		ClientName: "",
		TelegramID: 100,
		ExpiresAt:  now.Add(30 * 24 * time.Hour),
	}); err != nil {
		t.Fatalf("save no-name token: %v", err)
	}

	// Revoked token — must NOT appear.
	if err := s.SaveRefreshToken(ctx, "tok-revoked", RefreshToken{
		FamilyID:   "fam4",
		UserID:     uid,
		ClientID:   "client-revoked",
		ClientName: "RevokedClient",
		TelegramID: 100,
		ExpiresAt:  now.Add(30 * 24 * time.Hour),
	}); err != nil {
		t.Fatalf("save revoked token: %v", err)
	}
	if _, err := s.RevokeRefreshTokenFamily(ctx, "fam4"); err != nil {
		t.Fatalf("revoke token: %v", err)
	}

	rows, err := s.ListIdentities(ctx)
	if err != nil {
		t.Fatalf("ListIdentities: %v", err)
	}
	var alice *IdentityRow
	for i := range rows {
		if rows[i].TelegramID == 100 {
			alice = &rows[i]
		}
	}
	if alice == nil {
		t.Fatal("alice not found in identities")
	}
	if len(alice.ConnectedVia) != 1 || alice.ConnectedVia[0] != "Claude" {
		t.Errorf("ConnectedVia = %v, want [Claude]", alice.ConnectedVia)
	}
}
