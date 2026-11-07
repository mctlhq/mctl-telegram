package db

import (
	"context"
	"testing"
	"time"
)

// TestListActiveClientGrants lists only the caller's live grants, one entry
// per client with its sign-in count, newest first (mctl-telegram#749).
func TestListActiveClientGrants(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	now := time.Now().UTC()
	alice, err := s.EnsureUserByTelegramID(ctx, 100, "alice", "Alice")
	if err != nil {
		t.Fatalf("ensure alice: %v", err)
	}
	bob, err := s.EnsureUserByTelegramID(ctx, 200, "bob", "Bob")
	if err != nil {
		t.Fatalf("ensure bob: %v", err)
	}
	save := func(tok, fam string, uid int64, client, name string, expires time.Time, created time.Time) {
		t.Helper()
		if err := s.SaveRefreshToken(ctx, tok, RefreshToken{
			FamilyID: fam, UserID: uid, ClientID: client, ClientName: name,
			TelegramID: 100, ExpiresAt: expires,
		}); err != nil {
			t.Fatalf("save %s: %v", tok, err)
		}
		if _, err := s.DB.ExecContext(ctx,
			`UPDATE oauth_refresh_tokens SET created_at = $1 WHERE family_id = $2 AND client_id = $3 AND user_id = $4 AND created_at <> $1`,
			created, fam, client, uid); err != nil {
			t.Fatalf("set created_at: %v", err)
		}
	}
	later := now.Add(30 * 24 * time.Hour)
	save("c1", "fam-c1", alice, "claude.ai", "Claude", later, now.Add(-3*time.Hour))
	save("c2", "fam-c2", alice, "claude.ai", "Claude", later, now.Add(-1*time.Hour))
	save("g1", "fam-g1", alice, "chatgpt", "ChatGPT", later, now.Add(-2*time.Hour))
	save("x1", "fam-x1", alice, "expired-client", "Old", now.Add(-time.Minute), now.Add(-4*time.Hour))
	save("r1", "fam-r1", alice, "revoked-client", "Gone", later, now.Add(-5*time.Hour))
	if _, err := s.RevokeRefreshTokenFamily(ctx, "fam-r1", "explicit_revoke"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	save("b1", "fam-b1", bob, "bob-client", "BobApp", later, now.Add(-time.Minute))

	got, err := s.ListActiveClientGrants(ctx, alice, now)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("grants = %+v, want claude.ai and chatgpt only", got)
	}
	if got[0].ClientID != "claude.ai" || got[0].ClientName != "Claude" || got[0].Families != 2 {
		t.Fatalf("first grant = %+v, want claude.ai with 2 sign-ins", got[0])
	}
	if got[1].ClientID != "chatgpt" || got[1].Families != 1 {
		t.Fatalf("second grant = %+v, want chatgpt with 1 sign-in", got[1])
	}
	if got[0].LastIssuedAt.Before(got[1].LastIssuedAt) {
		t.Fatalf("not newest first: %+v", got)
	}

	none, err := s.ListActiveClientGrants(ctx, 999999, now)
	if err != nil || none == nil || len(none) != 0 {
		t.Fatalf("no grants = %v, %v; want an empty, non-nil slice", none, err)
	}
}

// A failed read is an error, never an empty list.
func TestListActiveClientGrants_FailedReadIsAnError(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	if _, err := s.DB.ExecContext(ctx, `DROP TABLE oauth_refresh_tokens`); err != nil {
		t.Fatalf("drop: %v", err)
	}
	if got, err := s.ListActiveClientGrants(ctx, 1, time.Now()); err == nil {
		t.Fatalf("got %v with no error after a failed read", got)
	}
}
