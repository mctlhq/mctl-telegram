package db

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/notify"
)

// TestListIdentities_IncludesClientIdentityModel is T15's store-layer half:
// ListIdentities returns the new identity/reachability/preference fields,
// merged without a per-user query (the merge itself is exercised by having
// more than one user, only one of which has reachability/prefs rows).
func TestListIdentities_IncludesClientIdentityModel(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	uidAlice, err := s.EnsureUserByTelegramCapture(ctx, TelegramIdentityCapture{
		TelegramID: 111,
		Username:   "alice",
		FirstName:  "Alice",
		LastName:   "Example",
		Source:     "telegram_oidc",
	})
	if err != nil {
		t.Fatalf("capture alice: %v", err)
	}
	if _, err := s.EnsureUserByTelegramID(ctx, 222, "bob", "Bob"); err != nil {
		t.Fatalf("ensure bob: %v", err)
	}

	outcome := notify.ClassifyDelivery(403, "Forbidden: bot was blocked by the user")
	if err := s.RecordBotReachability(ctx, uidAlice, outcome, "digest_delivery"); err != nil {
		t.Fatalf("record reachability: %v", err)
	}
	if err := s.SetNotificationPrefs(ctx, uidAlice, map[string]string{
		string(CategoryProductUpdates): PrefSubscribed,
	}, "account_api"); err != nil {
		t.Fatalf("set prefs: %v", err)
	}

	rows, err := s.ListIdentities(ctx)
	if err != nil {
		t.Fatalf("ListIdentities: %v", err)
	}
	byTgID := make(map[int64]IdentityRow, len(rows))
	for _, r := range rows {
		byTgID[r.TelegramID] = r
	}

	alice, ok := byTgID[111]
	if !ok {
		t.Fatal("alice missing from ListIdentities output")
	}
	if alice.FirstName != "Alice" || alice.LastName != "Example" {
		t.Errorf("alice first/last name = (%q, %q), want (Alice, Example)", alice.FirstName, alice.LastName)
	}
	if alice.IdentitySource != "telegram_oidc" {
		t.Errorf("alice identity_source = %q, want telegram_oidc", alice.IdentitySource)
	}
	if alice.IdentityCapturedAt == nil {
		t.Error("alice identity_captured_at is nil, want stamped")
	}
	if alice.Provenance["first_name"] != string(ProvenanceSupplied) {
		t.Errorf("alice first_name provenance = %q, want supplied", alice.Provenance["first_name"])
	}
	if alice.BotReachability == nil || alice.BotReachability.State != notify.StateBlocked {
		t.Errorf("alice bot_reachability = %+v, want state=blocked", alice.BotReachability)
	}
	foundProductUpdates := false
	for _, p := range alice.NotificationPrefs {
		if p.Category == string(CategoryProductUpdates) {
			foundProductUpdates = true
			if p.State != PrefSubscribed || !p.Explicit {
				t.Errorf("alice product_updates pref = %+v, want state=subscribed explicit=true", p)
			}
		}
	}
	if !foundProductUpdates {
		t.Error("alice's explicit product_updates preference is missing from ListIdentities output")
	}

	bob, ok := byTgID[222]
	if !ok {
		t.Fatal("bob missing from ListIdentities output")
	}
	if bob.BotReachability != nil {
		t.Errorf("bob has a bot_reachability row (%+v), want nil — none was ever recorded", bob.BotReachability)
	}
	if len(bob.NotificationPrefs) != 0 {
		t.Errorf("bob has %d notification prefs, want 0 — none were ever set explicitly", len(bob.NotificationPrefs))
	}
	if bob.Provenance["first_name"] != string(ProvenanceUnknown) {
		t.Errorf("bob first_name provenance = %q, want unknown (capture never ran via EnsureUserByTelegramID)", bob.Provenance["first_name"])
	}
}

// TestIdentityRow_JSONRoundTripsForOlderConsumer is the backward-compat half
// of T15: a consumer decoding into a struct that only knows today's fields
// (telegram_id, username, display_name, access_tier, has_session,
// created_at, connected_via) must not fail or lose those fields when handed
// the new, wider JSON payload.
func TestIdentityRow_JSONRoundTripsForOlderConsumer(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	if _, err := s.EnsureUserByTelegramCapture(ctx, TelegramIdentityCapture{
		TelegramID: 111,
		Username:   "alice",
		FirstName:  "Alice",
		Source:     "telegram_oidc",
	}); err != nil {
		t.Fatalf("capture: %v", err)
	}
	rows, err := s.ListIdentities(ctx)
	if err != nil {
		t.Fatalf("ListIdentities: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	blob, err := json.Marshal(rows[0])
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	type oldIdentityRow struct {
		TelegramID   int64    `json:"telegram_id"`
		Username     string   `json:"username,omitempty"`
		DisplayName  string   `json:"display_name,omitempty"`
		AccessTier   string   `json:"access_tier"`
		HasSession   bool     `json:"has_session"`
		ConnectedVia []string `json:"connected_via,omitempty"`
	}
	var old oldIdentityRow
	if err := json.Unmarshal(blob, &old); err != nil {
		t.Fatalf("an older consumer failed to decode the widened payload: %v", err)
	}
	if old.TelegramID != 111 || old.Username != "alice" {
		t.Errorf("older consumer lost known fields: %+v", old)
	}
}
