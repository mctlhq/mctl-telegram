package db

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/notify"
)

// TestBroadcastCampaignStore_SQLite and _Postgres run the same body on both
// dialects: the guarded transitions are hand-written SQL kept in two schema
// lists, so a dialect-specific break (a type the driver scans differently, a
// placeholder the planner rejects) must fail here rather than on the first
// real approval.
func TestBroadcastCampaignStore_SQLite(t *testing.T) {
	assertBroadcastCampaignStore(t, newTestStore(t), 810000001)
}

func TestBroadcastCampaignStore_Postgres(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	assertBroadcastCampaignStore(t, newPostgresTestStore(t, dsn), 820000001)
}

func assertBroadcastCampaignStore(t *testing.T, s *Store, tgID int64) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	prefix := fmt.Sprintf("bc_test_%d_", now.UnixNano())
	// Postgres keeps state between runs; SQLite is fresh each time.
	t.Cleanup(func() {
		_, _ = s.DB.Exec(`DELETE FROM broadcast_campaigns WHERE id LIKE $1`, prefix+"%")
	})
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM users WHERE telegram_login_id = $1`, tgID); err != nil {
		t.Fatalf("reset user: %v", err)
	}
	uid, err := s.EnsureUserByTelegramCapture(ctx, TelegramIdentityCapture{
		TelegramID: tgID, Username: "b", FirstName: "B", Source: "telegram_oidc", CapturedAt: now,
	})
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	if err := s.SetNotificationPrefs(ctx, uid, map[string]string{string(CategoryProductUpdates): PrefSubscribed}, "test"); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordBotReachability(ctx, uid, notify.DeliveryOutcome{State: notify.StateReachable, Conclusive: true}, "test"); err != nil {
		t.Fatal(err)
	}

	f, err := s.GetBroadcastRecipientFacts(ctx, uid, now)
	if err != nil || f == nil {
		t.Fatalf("facts: %+v, %v", f, err)
	}
	if f.TelegramID != tgID || f.IdentityCapturedAt == nil || f.Reachability != notify.StateReachable ||
		f.Prefs[string(CategoryProductUpdates)] != PrefSubscribed {
		t.Fatalf("facts = %+v", f)
	}
	if got := ResolvePrefState(CategoryMaintenance, f.Prefs); got != PrefSubscribed {
		t.Fatalf("maintenance default = %s", got)
	}
	all, err := s.ListBroadcastRecipientFacts(ctx, now)
	if err != nil {
		t.Fatalf("list facts: %v", err)
	}
	found := false
	for _, a := range all {
		found = found || a.UserID == uid
	}
	if !found {
		t.Fatal("list facts misses the user")
	}

	mk := func(suffix string, expires time.Time) string {
		id := prefix + suffix
		if err := s.CreateBroadcastCampaign(ctx, BroadcastCampaign{
			ID: id, Category: string(CategoryMaintenance), SelectorJSON: `{"category":"maintenance"}`,
			SelectorHash: "sh", Content: "text", ContentHash: "ch", CreatedBy: uid, Surface: "test",
			RecipientLimit: 10, PreviewCounts: `{"eligible":1}`, ExpiresAt: expires,
		}); err != nil {
			t.Fatalf("create %s: %v", suffix, err)
		}
		return id
	}

	a := mk("a", now.Add(time.Hour))
	if err := s.ApproveBroadcastCampaign(ctx, a, uid, "ch", "other", now); !errors.Is(err, ErrCampaignMismatch) {
		t.Fatalf("mismatch: %v", err)
	}
	if err := s.ApproveBroadcastCampaign(ctx, a, uid, "ch", "sh", now); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if err := s.ApproveBroadcastCampaign(ctx, a, uid, "ch", "sh", now); !errors.Is(err, ErrCampaignNotPrepared) {
		t.Fatalf("replay: %v", err)
	}
	got, err := s.GetBroadcastCampaign(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != CampaignApproved || got.ApprovedBy == nil || *got.ApprovedBy != uid || got.ApprovedAt == nil ||
		!got.ExpiresAt.Equal(now.Add(time.Hour)) || got.PreviewCounts != `{"eligible":1}` {
		t.Fatalf("approved row = %+v", got)
	}

	b := mk("b", now.Add(-time.Second))
	if err := s.ApproveBroadcastCampaign(ctx, b, uid, "ch", "sh", now); !errors.Is(err, ErrCampaignExpired) {
		t.Fatalf("expired: %v", err)
	}
	c := mk("c", now.Add(-time.Second))
	if n, err := s.ExpireBroadcastCampaigns(ctx, now); err != nil || n < 1 {
		t.Fatalf("expire sweep: n=%d %v", n, err)
	}
	if got, _ := s.GetBroadcastCampaign(ctx, c); got.State != CampaignExpired {
		t.Fatalf("swept state = %s", got.State)
	}

	d := mk("d", now.Add(time.Hour))
	if err := s.CancelBroadcastCampaign(ctx, d, uid, now); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if err := s.CancelBroadcastCampaign(ctx, d, uid, now); !errors.Is(err, ErrCampaignTerminal) {
		t.Fatalf("re-cancel: %v", err)
	}
	if err := s.CancelBroadcastCampaign(ctx, prefix+"missing", uid, now); !errors.Is(err, ErrCampaignNotFound) {
		t.Fatalf("cancel missing: %v", err)
	}
	pending, err := s.ListBroadcastCampaigns(ctx, 200, CampaignApproved)
	if err != nil {
		t.Fatal(err)
	}
	seen := false
	for _, p := range pending {
		if p.State != CampaignApproved {
			t.Fatalf("state filter leaked %s", p.State)
		}
		seen = seen || p.ID == a
	}
	if !seen {
		t.Fatal("approved campaign missing from filtered list")
	}
}
