package db

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"
)

// TestBroadcastDeliveryStore_SQLite and _Postgres run the delivery queue's
// hand-written SQL (row-value IN, UPDATE ... RETURNING, SKIP LOCKED on
// Postgres) on both dialects.
func TestBroadcastDeliveryStore_SQLite(t *testing.T) {
	assertBroadcastDeliveryStore(t, newTestStore(t), 830000001)
}

func TestBroadcastDeliveryStore_Postgres(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	assertBroadcastDeliveryStore(t, newPostgresTestStore(t, dsn), 840000001)
}

func assertBroadcastDeliveryStore(t *testing.T, s *Store, tgBase int64) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	prefix := fmt.Sprintf("bc_dtest_%d_", now.UnixNano())
	t.Cleanup(func() {
		_, _ = s.DB.Exec(`DELETE FROM broadcast_campaigns WHERE id LIKE $1`, prefix+"%")
	})
	var users []BroadcastRecipient
	for i := int64(0); i < 3; i++ {
		tg := tgBase + i
		if _, err := s.DB.ExecContext(ctx,
			`DELETE FROM broadcast_campaigns WHERE created_by IN (SELECT id FROM users WHERE telegram_login_id = $1)`, tg); err != nil {
			t.Fatal(err)
		}
		if _, err := s.DB.ExecContext(ctx, `DELETE FROM users WHERE telegram_login_id = $1`, tg); err != nil {
			t.Fatal(err)
		}
		uid, err := s.EnsureUserByTelegramCapture(ctx, TelegramIdentityCapture{TelegramID: tg, Username: "d", Source: "telegram_oidc", CapturedAt: now})
		if err != nil {
			t.Fatal(err)
		}
		users = append(users, BroadcastRecipient{UserID: uid, TelegramID: tg})
	}
	mk := func(suffix string) string {
		id := prefix + suffix
		if err := s.CreateBroadcastCampaign(ctx, BroadcastCampaign{
			ID: id, Category: "maintenance", SelectorJSON: "{}", SelectorHash: "sh", Content: "t", ContentHash: "ch",
			CreatedBy: users[0].UserID, RecipientLimit: 10, ExpiresAt: now.Add(time.Hour),
		}, now); err != nil {
			t.Fatal(err)
		}
		if err := s.ApproveBroadcastCampaign(ctx, id, users[0].UserID, "ch", "sh", now); err != nil {
			t.Fatal(err)
		}
		return id
	}
	status := func(id string, uid int64) (string, string, int) {
		var st, reason string
		var n int
		if err := s.DB.QueryRowContext(ctx, `SELECT status, reason, attempts FROM broadcast_deliveries WHERE campaign_id = $1 AND user_id = $2`, id, uid).Scan(&st, &reason, &n); err != nil {
			t.Fatalf("status %s/%d: %v", id, uid, err)
		}
		return st, reason, n
	}

	a := mk("a")
	if err := s.StartBroadcastCampaign(ctx, a, users, now); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := s.StartBroadcastCampaign(ctx, a, users, now); !errors.Is(err, ErrCampaignNotApproved) {
		t.Fatalf("second start: %v", err)
	}

	claimed, err := s.ClaimBroadcastDeliveries(ctx, 2, now)
	if err != nil || len(claimed) != 2 {
		t.Fatalf("claim: %+v %v", claimed, err)
	}
	for _, d := range claimed {
		if d.Attempts != 1 || d.CampaignID != a {
			t.Fatalf("claimed %+v", d)
		}
	}
	if err := s.FinishBroadcastDelivery(ctx, a, claimed[0].UserID, DeliveryDelivered, "", now); err != nil {
		t.Fatal(err)
	}
	if err := s.RetryBroadcastDelivery(ctx, a, claimed[1].UserID, "transient", now.Add(time.Minute), now); err != nil {
		t.Fatal(err)
	}
	// Not due yet: only the third, never-claimed recipient is claimable.
	next, err := s.ClaimBroadcastDeliveries(ctx, 10, now)
	if err != nil || len(next) != 1 || next[0].UserID == claimed[1].UserID {
		t.Fatalf("claim respects next_attempt_at: %+v %v", next, err)
	}

	// Idempotency key: even if a campaign were started again (here forced
	// back to approved), an already-delivered recipient is never re-queued.
	if _, err := s.DB.ExecContext(ctx, `UPDATE broadcast_campaigns SET state = $1 WHERE id = $2`, CampaignApproved, a); err != nil {
		t.Fatal(err)
	}
	if err := s.StartBroadcastCampaign(ctx, a, users, now); err != nil {
		t.Fatalf("forced restart: %v", err)
	}
	if st, _, _ := status(a, claimed[0].UserID); st != DeliveryDelivered {
		t.Fatalf("delivered row was re-queued as %s", st)
	}

	// Stale in-flight row -> failed/outcome_unknown, and a late Finish for
	// it does not overwrite that.
	if n, err := s.FailStaleBroadcastDeliveries(ctx, time.Minute, now.Add(2*time.Minute)); err != nil || n != 1 {
		t.Fatalf("stale sweep: %d %v", n, err)
	}
	if st, reason, _ := status(a, next[0].UserID); st != DeliveryFailed || reason != ReasonOutcomeUnknown {
		t.Fatalf("stale = %s/%s", st, reason)
	}
	if err := s.FinishBroadcastDelivery(ctx, a, next[0].UserID, DeliveryDelivered, "", now); err != nil {
		t.Fatal(err)
	}
	if st, _, _ := status(a, next[0].UserID); st != DeliveryFailed {
		t.Fatalf("late finish overwrote the stale outcome: %s", st)
	}

	// Still one pending (the retried row): not complete yet.
	if done, err := s.CompleteBroadcastCampaigns(ctx, now); err != nil || contains(done, a) {
		t.Fatalf("completed with pending work: %v %v", done, err)
	}
	later, err := s.ClaimBroadcastDeliveries(ctx, 10, now.Add(2*time.Minute))
	if err != nil || len(later) != 1 || later[0].Attempts != 2 {
		t.Fatalf("retry claim: %+v %v", later, err)
	}
	if err := s.FinishBroadcastDelivery(ctx, a, later[0].UserID, DeliveryFailed, "bot_blocked", now); err != nil {
		t.Fatal(err)
	}
	if done, err := s.CompleteBroadcastCampaigns(ctx, now); err != nil || !contains(done, a) {
		t.Fatalf("complete: %v %v", done, err)
	}
	counts, err := s.BroadcastDeliveryCounts(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int{"delivered/": 1, "failed/outcome_unknown": 1, "failed/bot_blocked": 1}
	if len(counts) != len(want) {
		t.Fatalf("counts = %+v", counts)
	}
	for _, c := range counts {
		if want[c.Status+"/"+c.Reason] != c.Count {
			t.Fatalf("counts = %+v", counts)
		}
	}

	// Cancelled campaign: pending rows are skipped, never claimed.
	b := mk("b")
	if err := s.StartBroadcastCampaign(ctx, b, users, now); err != nil {
		t.Fatal(err)
	}
	if err := s.CancelBroadcastCampaign(ctx, b, users[0].UserID, now); err != nil {
		t.Fatal(err)
	}
	if got, err := s.ClaimBroadcastDeliveries(ctx, 10, now.Add(time.Hour)); err != nil || len(got) != 0 {
		t.Fatalf("claimed work of a cancelled campaign: %+v %v", got, err)
	}
	if n, err := s.SkipCancelledBroadcastDeliveries(ctx, now); err != nil || n != 3 {
		t.Fatalf("skip cancelled: %d %v", n, err)
	}
	if done, _ := s.CompleteBroadcastCampaigns(ctx, now); contains(done, b) {
		t.Fatal("a cancelled campaign was marked completed")
	}

	// Release hands an unattempted claim back without counting it; Halt
	// cancels a sending campaign (and only a sending one).
	h := mk("h")
	if err := s.StartBroadcastCampaign(ctx, h, users[:1], now); err != nil {
		t.Fatal(err)
	}
	if got, err := s.ClaimBroadcastDeliveries(ctx, 10, now.Add(2*time.Hour)); err != nil || len(got) != 1 || got[0].CampaignID != h {
		t.Fatalf("claim h: %+v %v", got, err)
	}
	if err := s.ReleaseBroadcastDelivery(ctx, h, users[0].UserID, now); err != nil {
		t.Fatal(err)
	}
	if st, _, n := status(h, users[0].UserID); st != DeliveryPending || n != 0 {
		t.Fatalf("released = %s attempts=%d", st, n)
	}
	if err := s.ReleaseBroadcastDelivery(ctx, h, users[0].UserID, now); err != nil {
		t.Fatal(err)
	}
	if _, _, n := status(h, users[0].UserID); n != 0 {
		t.Fatalf("releasing a pending row changed attempts to %d", n)
	}
	if err := s.HaltBroadcastCampaign(ctx, h, "integrity", now); err != nil {
		t.Fatal(err)
	}
	if got, err := s.GetBroadcastCampaign(ctx, h); err != nil || got.State != CampaignCancelled || got.EndReason != "integrity" {
		t.Fatalf("halted = %+v %v", got, err)
	}
	if err := s.HaltBroadcastCampaign(ctx, h, "integrity", now); !errors.Is(err, ErrCampaignNotSending) {
		t.Fatalf("second halt: %v", err)
	}

	// End an approved campaign without delivery.
	c := mk("c")
	if err := s.EndBroadcastCampaign(ctx, c, CampaignCancelled, "recipient_limit_exceeded_at_send", now); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetBroadcastCampaign(ctx, c)
	if err != nil || got.State != CampaignCancelled || got.EndReason != "recipient_limit_exceeded_at_send" {
		t.Fatalf("ended = %+v %v", got, err)
	}
	if err := s.EndBroadcastCampaign(ctx, c, CampaignCompleted, "x", now); !errors.Is(err, ErrCampaignNotApproved) {
		t.Fatalf("second end: %v", err)
	}
}

func contains(ids []string, id string) bool {
	for _, x := range ids {
		if x == id {
			return true
		}
	}
	return false
}
