package db

import (
	"context"
	"testing"
	"time"
)

// TestMigrate_UpgradesRefreshTokensWithoutRedirectURI: an upgraded database
// gains oauth_refresh_tokens.redirect_uri, a family issued before it reads
// back with an unknown redirect_uri (NULL, never ""), and rotating such a
// family keeps it unknown. A row written with a known redirect_uri, even an
// empty one, reads back known. Without the addColumnIfMissing call Migrate
// leaves the column out and every read here fails.
func TestMigrate_UpgradesRefreshTokensWithoutRedirectURI(t *testing.T) {
	ctx := context.Background()
	conn, err := Open(ctx, "file:refresh_redirect_upgrade?mode=memory&cache=shared", 0, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	// The shape before the redirect_uri column.
	if _, err := conn.ExecContext(ctx, `CREATE TABLE oauth_refresh_tokens (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		family_id TEXT NOT NULL,
		token_hash BLOB NOT NULL,
		user_id INTEGER NOT NULL,
		client_id TEXT NOT NULL,
		telegram_id INTEGER NOT NULL,
		telegram_username TEXT,
		scope TEXT,
		client_name TEXT NOT NULL DEFAULT '',
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		expires_at DATETIME NOT NULL,
		revoked_at DATETIME,
		parent_token_hash BLOB,
		revoked_reason TEXT
	)`); err != nil {
		t.Fatalf("seed pre-existing table: %v", err)
	}
	const legacy = "legacy-refresh-token-plaintext-01"
	if _, err := conn.ExecContext(ctx,
		`INSERT INTO oauth_refresh_tokens (family_id, token_hash, user_id, client_id, telegram_id, expires_at)
		 VALUES ('fam-legacy', $1, 1, 'claude.ai', 500100101, $2)`,
		hashRefreshToken(legacy), time.Now().Add(time.Hour).UTC(),
	); err != nil {
		t.Fatalf("seed legacy row: %v", err)
	}

	if err := Migrate(ctx, conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	store := &Store{DB: conn}
	uid, err := store.EnsureUserByTelegramID(ctx, 500100101, "dana_tg", "Dana")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(ctx, `UPDATE oauth_refresh_tokens SET user_id = $1`, uid); err != nil {
		t.Fatal(err)
	}

	rt, err := store.LookupRefreshToken(ctx, legacy)
	if err != nil {
		t.Fatalf("lookup legacy row: %v", err)
	}
	if rt.RedirectURIKnown || rt.RedirectURI != "" {
		t.Fatalf("legacy row redirect_uri = %q (known %v), want unknown", rt.RedirectURI, rt.RedirectURIKnown)
	}

	const successor = "legacy-refresh-token-plaintext-02"
	next := *rt
	next.ParentTokenHash = nil
	if err := store.RotateRefreshToken(ctx, legacy, successor, next); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	got, err := store.LookupRefreshTokenByHashPair(ctx, legacy, successor, rt.FamilyID, rt.ClientID)
	if err != nil {
		t.Fatalf("lookup successor: %v", err)
	}
	if got.RedirectURIKnown {
		t.Fatalf("rotation turned an unknown redirect_uri into known %q", got.RedirectURI)
	}

	for _, uri := range []string{"https://claude.ai/cb", ""} {
		plain := "known-redirect-token-" + uri
		if err := store.SaveRefreshToken(ctx, plain, RefreshToken{
			FamilyID: "fam-" + uri, UserID: uid, ClientID: "claude.ai", TelegramID: 500100101,
			ExpiresAt: time.Now().Add(time.Hour), RedirectURI: uri, RedirectURIKnown: true,
		}); err != nil {
			t.Fatal(err)
		}
		rt, err := store.LookupRefreshToken(ctx, plain)
		if err != nil {
			t.Fatal(err)
		}
		if !rt.RedirectURIKnown || rt.RedirectURI != uri {
			t.Fatalf("known redirect_uri %q read back as %q (known %v)", uri, rt.RedirectURI, rt.RedirectURIKnown)
		}
	}
}
