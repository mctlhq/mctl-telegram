package db

import (
	"context"
	"errors"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func TestRefreshToken_SaveAndLookup(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUserByTelegramID(ctx, 4242, "alice", "Alice")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	rt := RefreshToken{
		FamilyID:         "fam-1",
		UserID:           uid,
		ClientID:         "claude.ai",
		TelegramID:       4242,
		TelegramUsername: "alice",
		Scope:            "telegram:dialogs:read",
		ExpiresAt:        time.Now().Add(time.Hour),
	}
	if err := s.SaveRefreshToken(ctx, "token-plaintext-1", rt); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := s.LookupRefreshToken(ctx, "token-plaintext-1")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if got.FamilyID != "fam-1" || got.UserID != uid || got.ClientID != "claude.ai" {
		t.Errorf("lookup returned wrong row: %+v", got)
	}
	if got.TelegramID != 4242 || got.TelegramUsername != "alice" {
		t.Errorf("telegram identity wrong: %+v", got)
	}
	if got.Revoked() {
		t.Error("fresh token reported as revoked")
	}
	if got.Expired(time.Now()) {
		t.Error("fresh token reported as expired")
	}
	if _, err := s.LookupRefreshToken(ctx, "no-such-token"); !errors.Is(err, ErrRefreshTokenNotFound) {
		t.Errorf("lookup of unknown token: err = %v, want ErrRefreshTokenNotFound", err)
	}
}

func TestRefreshToken_Rotate(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUserByTelegramID(ctx, 5, "bob", "Bob")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	base := RefreshToken{FamilyID: "fam-x", UserID: uid, ClientID: "c", TelegramID: 5, ExpiresAt: time.Now().Add(time.Hour)}
	if err := s.SaveRefreshToken(ctx, "old", base); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := s.RotateRefreshToken(ctx, "old", "new", base); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	old, err := s.LookupRefreshToken(ctx, "old")
	if err != nil {
		t.Fatalf("lookup old: %v", err)
	}
	if !old.Revoked() {
		t.Error("rotated token not marked revoked")
	}
	if old.RevokedReason != "rotated" {
		t.Errorf("rotated token revoked_reason = %q, want \"rotated\"", old.RevokedReason)
	}
	newTok, err := s.LookupRefreshToken(ctx, "new")
	if err != nil {
		t.Fatalf("lookup new: %v", err)
	}
	if newTok.Revoked() {
		t.Error("freshly rotated token reported revoked")
	}
	child, err := s.LookupRefreshTokenByHashPair(ctx, "old", "new", "fam-x", "c")
	if err != nil {
		t.Fatalf("lookup by hash pair: %v", err)
	}
	if child.TelegramID != 5 {
		t.Errorf("lookup by hash pair returned wrong row: %+v", child)
	}
	// Rotating an already-revoked token must fail rather than mint a replacement.
	if err := s.RotateRefreshToken(ctx, "old", "new2", base); !errors.Is(err, ErrRefreshTokenNotFound) {
		t.Errorf("rotate of revoked token: err = %v, want ErrRefreshTokenNotFound", err)
	}
}

func TestRefreshToken_RevokeFamily(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUserByTelegramID(ctx, 9, "carol", "Carol")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	fam := RefreshToken{FamilyID: "kin", UserID: uid, ClientID: "c", TelegramID: 9, ExpiresAt: time.Now().Add(time.Hour)}
	if err := s.SaveRefreshToken(ctx, "a", fam); err != nil {
		t.Fatalf("save a: %v", err)
	}
	if err := s.SaveRefreshToken(ctx, "b", fam); err != nil {
		t.Fatalf("save b: %v", err)
	}
	n, err := s.RevokeRefreshTokenFamily(ctx, "kin", "reuse_detected")
	if err != nil {
		t.Fatalf("revoke family: %v", err)
	}
	if n != 2 {
		t.Errorf("revoked %d rows, want 2", n)
	}
	for _, tok := range []string{"a", "b"} {
		got, err := s.LookupRefreshToken(ctx, tok)
		if err != nil {
			t.Fatalf("lookup %s: %v", tok, err)
		}
		if !got.Revoked() {
			t.Errorf("token %s not revoked after family revoke", tok)
		}
		if got.RevokedReason != "reuse_detected" {
			t.Errorf("token %s revoked_reason = %q, want \"reuse_detected\"", tok, got.RevokedReason)
		}
	}
}

func TestRefreshToken_SweepExpired(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUserByTelegramID(ctx, 77, "dave", "Dave")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	live := RefreshToken{FamilyID: "f1", UserID: uid, ClientID: "c", TelegramID: 77, ExpiresAt: time.Now().Add(time.Hour)}
	dead := RefreshToken{FamilyID: "f2", UserID: uid, ClientID: "c", TelegramID: 77, ExpiresAt: time.Now().Add(-time.Hour)}
	if err := s.SaveRefreshToken(ctx, "live", live); err != nil {
		t.Fatalf("save live: %v", err)
	}
	if err := s.SaveRefreshToken(ctx, "dead", dead); err != nil {
		t.Fatalf("save dead: %v", err)
	}
	n, err := s.SweepExpiredRefreshTokens(ctx)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if n != 1 {
		t.Errorf("swept %d rows, want 1", n)
	}
	if _, err := s.LookupRefreshToken(ctx, "dead"); !errors.Is(err, ErrRefreshTokenNotFound) {
		t.Errorf("expired token survived sweep: err = %v", err)
	}
	if _, err := s.LookupRefreshToken(ctx, "live"); err != nil {
		t.Errorf("live token wrongly swept: %v", err)
	}
}
