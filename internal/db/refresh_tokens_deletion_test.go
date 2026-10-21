package db

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestHardDeleteAccount_RevokesRefreshTokens(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	alice, err := s.EnsureUserByTelegramID(ctx, 4242, "alice", "Alice")
	if err != nil {
		t.Fatalf("ensure alice: %v", err)
	}
	bob, err := s.EnsureUserByTelegramID(ctx, 4343, "bob", "Bob")
	if err != nil {
		t.Fatalf("ensure bob: %v", err)
	}
	seedAccount(t, s, alice, nil, nil, nil)

	mk := func(fam string, uid int64) RefreshToken {
		return RefreshToken{FamilyID: fam, UserID: uid, ClientID: "claude.ai",
			TelegramID: 1, Scope: "telegram:dialogs:read", ExpiresAt: time.Now().Add(time.Hour)}
	}
	for _, c := range []struct {
		pt  string
		fam string
		uid int64
	}{{"a-1", "fa", alice}, {"a-2", "fb", alice}, {"b-1", "fc", bob}} {
		if err := s.SaveRefreshToken(ctx, c.pt, mk(c.fam, c.uid)); err != nil {
			t.Fatalf("save %s: %v", c.pt, err)
		}
	}
	// a-old was rotated earlier and must keep its original reason.
	if err := s.SaveRefreshToken(ctx, "a-old", mk("fa", alice)); err != nil {
		t.Fatalf("save a-old: %v", err)
	}
	if err := s.RotateRefreshToken(ctx, "a-old", "a-new", mk("fa", alice)); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	if _, err := s.HardDeleteAccount(ctx, alice); err != nil {
		t.Fatalf("delete: %v", err)
	}

	reason := func(pt string) (string, bool) {
		rt, err := s.LookupRefreshToken(ctx, pt)
		if err != nil {
			t.Fatalf("lookup %s: %v", pt, err)
		}
		return rt.RevokedReason, rt.Revoked()
	}
	for _, pt := range []string{"a-1", "a-2", "a-new"} {
		if r, rev := reason(pt); !rev || r != "account_deleted" {
			t.Errorf("%s: revoked=%v reason=%q, want account_deleted", pt, rev, r)
		}
	}
	if r, rev := reason("a-old"); !rev || r != "rotated" {
		t.Errorf("a-old: revoked=%v reason=%q, want rotated", rev, r)
	}
	if _, rev := reason("b-1"); rev {
		t.Error("other user's token must not be revoked")
	}
	if err := s.RotateRefreshToken(ctx, "a-1", "a-x", mk("fa", alice)); !errors.Is(err, ErrRefreshTokenNotFound) {
		t.Errorf("rotate after delete: err = %v, want ErrRefreshTokenNotFound", err)
	}
}
