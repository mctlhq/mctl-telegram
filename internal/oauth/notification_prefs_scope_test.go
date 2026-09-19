package oauth

import (
	"context"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

// TestNotificationPrefs_GrantNoScope is T12: a user with an explicit
// product_updates=subscribed preference and no access_tier still resolves to
// zero scopes through ResolveScopes. A notification preference is the
// user's own data, never an input to scope resolution.
func TestNotificationPrefs_GrantNoScope(t *testing.T) {
	srv := newTestServer(t)
	ctx := context.Background()

	const tgID = int64(700000900)
	uid, err := srv.store.EnsureUserByTelegramID(ctx, tgID, "nodata", "No Data")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	// No access_tier is set — this id is neither an admin nor a lookup admin
	// nor a DB/env client, so ResolveScopes must return nothing for it.

	if err := srv.store.SetNotificationPrefs(ctx, uid, map[string]string{
		string(db.CategoryProductUpdates): db.PrefSubscribed,
	}, "account_api"); err != nil {
		t.Fatalf("SetNotificationPrefs: %v", err)
	}

	groups, scopes, err := srv.ResolveScopes(ctx, tgID)
	if err != nil {
		t.Fatalf("ResolveScopes: %v", err)
	}
	if len(groups) != 0 {
		t.Errorf("groups = %v, want empty — a notification preference must not grant a group", groups)
	}
	if len(scopes) != 0 {
		t.Errorf("scopes = %v, want empty — a notification preference must not grant a scope", scopes)
	}
}
