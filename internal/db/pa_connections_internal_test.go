package db

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
	"github.com/mctlhq/mctl-telegram/internal/pa/convo"
)

// TestPAConnection_RevokePinsTokenGeneration covers the token_generation
// predicate of the revoke compare-and-set (#1332 follow-up). A rotation that
// commits between the revoke's read and its update must not leave the
// caller holding the superseded tokens: those would be revoked remotely
// while the live ones were wiped locally and never revoked.
//
// It needs a second connection that can commit while the revoke
// transaction holds its read, which SQLite's shared-cache locking refuses,
// so it runs on Postgres only (CI sets TEST_DATABASE_URL).
func TestPAConnection_RevokePinsTokenGeneration(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	s := newPostgresTestStore(t, dsn)
	ctx := context.Background()
	const principal = int64(9_100_000_001)
	id := "pac_revoke_gen_" + randomSuffix(t)
	t.Cleanup(func() { _, _ = s.DB.Exec(`DELETE FROM pa_connections WHERE id = $1`, id) })
	acceptConsent(t, s, principal)

	if err := s.CreatePAConnection(ctx, connection.Connection{
		ID: id, Principal: principal, Server: connection.ServerTG, State: connection.StatePendingLink, AuthorityRevision: 1,
	}, connection.Sealed{KEKID: "test", WrappedDEK: []byte("wrapped")}, mustAdmitPA(t, s, principal)); err != nil {
		t.Fatal(err)
	}
	steps := []connection.Transition{
		{From: connection.StatePendingLink, To: connection.StatePendingOAuth, ExpectRevision: 1},
		{From: connection.StatePendingOAuth, To: connection.StatePendingReturn, ExpectRevision: 2, SealedCode: []byte("code")},
		{From: connection.StatePendingReturn, To: connection.StatePendingConfirm, ExpectRevision: 3,
			AccountID: "acct", GrantedScope: "telegram:dialogs:read telegram:messages:read", SealedTokens: []byte("tokens-gen-0")},
		{From: connection.StatePendingConfirm, To: connection.StateActive, ExpectRevision: 4},
	}
	for _, tr := range steps {
		if _, err := s.TransitionPAConnection(ctx, principal, id, tr); err != nil {
			t.Fatalf("%s -> %s: %v", tr.From, tr.To, err)
		}
	}

	fired := false
	paRevokeAfterRead = func(ctx context.Context, _ *sql.Tx) {
		if fired {
			return
		}
		fired = true
		// A rotation from another replica commits in the window.
		if _, err := s.DB.ExecContext(ctx, `UPDATE pa_connections
			SET sealed_tokens = $1, token_generation = token_generation + 1
			WHERE id = $2`, []byte("tokens-gen-1"), id); err != nil {
			t.Errorf("rotation in the window: %v", err)
		}
	}
	t.Cleanup(func() { paRevokeAfterRead = nil })

	c, before, already, err := s.RevokePAConnection(ctx, principal, id, "disconnect")
	if err != nil || already {
		t.Fatalf("revoke: already=%v err=%v", already, err)
	}
	if !fired {
		t.Fatal("the test seam never fired")
	}
	if c.State != connection.StateRevoked {
		t.Fatalf("state %s, want revoked", c.State)
	}
	if !bytes.Equal(before.SealedTokens, []byte("tokens-gen-1")) {
		t.Fatalf("revoke returned %q, want the tokens live at the moment of revocation (tokens-gen-1)", before.SealedTokens)
	}
}

func randomSuffix(t *testing.T) string {
	t.Helper()
	b := make([]byte, 8)
	if _, err := cryptorand.Read(b); err != nil {
		t.Fatal(err)
	}
	const hexd = "0123456789abcdef"
	out := make([]byte, 0, 16)
	for _, x := range b {
		out = append(out, hexd[x>>4], hexd[x&15])
	}
	return string(out)
}

// TestPALinkSecret_ConsumeCASPinsUnconsumed covers the consumed_at_ms = 0
// predicate of the consume compare-and-set: a second consumer that commits
// between this consumer's read and its update must win alone. Postgres only,
// for the same reason as the revoke test above.
func TestPALinkSecret_ConsumeCASPinsUnconsumed(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	s := newPostgresTestStore(t, dsn)
	ctx := context.Background()
	now := time.Now()
	h := paHash("cas-" + randomSuffix(t))
	t.Cleanup(func() { _, _ = s.DB.Exec(`DELETE FROM pa_link_secrets WHERE hash = $1`, h) })
	if err := s.CreatePALinkSecret(ctx, PALinkSecret{Hash: h, Kind: PALinkCompletion, Principal: 9_300_000_001,
		Server: "tg", ExpiresAt: now.Add(time.Minute)}, now); err != nil {
		t.Fatal(err)
	}
	fired := false
	paConsumeAfterRead = func(ctx context.Context, _ string) {
		if fired {
			return
		}
		fired = true
		// Another replica consumes the secret in the window.
		if _, err := s.DB.ExecContext(ctx, `UPDATE pa_link_secrets SET consumed_at_ms = $1 WHERE hash = $2`,
			now.UnixMilli(), h); err != nil {
			t.Errorf("consume in the window: %v", err)
		}
	}
	t.Cleanup(func() { paConsumeAfterRead = nil })
	if _, err := s.ConsumePALinkSecret(ctx, PALinkCompletion, h, now, nil); !errors.Is(err, ErrPALinkConsumed) {
		t.Fatalf("err %v, want ErrPALinkConsumed: a secret was consumed twice", err)
	}
	if !fired {
		t.Fatal("the test seam never fired")
	}
}

// acceptConsent records principal's current data-flow consent, which
// activation (pending_confirm -> active) requires under the principal lock.
func acceptConsent(t *testing.T, s *Store, principal int64) {
	t.Helper()
	ctx := context.Background()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AcceptPAConsent(ctx, tx, principal, convo.ConsentVersion, convo.ConsentTextSHA256(), time.Now()); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.DB.Exec(`DELETE FROM pa_consents WHERE principal = $1`, principal) })
}
