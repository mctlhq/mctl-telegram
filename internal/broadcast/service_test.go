package broadcast

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/notify"
)

const (
	operatorTG = int64(900001)
)

type env struct {
	t     *testing.T
	store *db.Store
	svc   *Service
	now   time.Time
	op    Actor
}

func newEnv(t *testing.T, mutate ...func(*Config)) *env {
	t.Helper()
	ctx := context.Background()
	conn, err := db.Open(ctx, "file:"+strings.ReplaceAll(t.Name(), "/", "_")+"?mode=memory&cache=shared", 0, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := db.Migrate(ctx, conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	e := &env{t: t, store: db.NewStore(conn, nil), now: time.Now().UTC()}
	cfg := Config{
		Operators: map[int64]bool{operatorTG: true},
		Policy:    Policy{AdminTelegramIDs: map[int64]bool{operatorTG: true}},
	}
	for _, m := range mutate {
		m(&cfg)
	}
	e.svc = NewService(e.store, cfg, func() time.Time { return e.now })
	e.op = Actor{UserID: e.user(operatorTG, db.TierClient), TelegramID: operatorTG, Surface: "test"}
	return e
}

// user creates a captured (live) client identity and returns users.id.
func (e *env) user(tg int64, tier string) int64 {
	e.t.Helper()
	ctx := context.Background()
	uid, err := e.store.EnsureUserByTelegramCapture(ctx, db.TelegramIdentityCapture{
		TelegramID: tg, Username: "u", FirstName: "U", Source: "telegram_oidc", CapturedAt: e.now,
	})
	if err != nil {
		e.t.Fatalf("capture: %v", err)
	}
	if tier != "" {
		if err := e.store.SetAccessTier(ctx, tg, tier); err != nil {
			e.t.Fatalf("tier: %v", err)
		}
	}
	return uid
}

func (e *env) prepare(sel Selector, text string) *Preview {
	e.t.Helper()
	p, err := e.svc.Prepare(context.Background(), e.op, PrepareRequest{Selector: sel, Text: text})
	if err != nil {
		e.t.Fatalf("prepare: %v", err)
	}
	return p
}

func (e *env) state(id string) string {
	e.t.Helper()
	c, err := e.store.GetBroadcastCampaign(context.Background(), id)
	if err != nil {
		e.t.Fatalf("get: %v", err)
	}
	return c.State
}

func TestPrepare_ResolvesAudienceServerSideAndSendsNothing(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.user(123456701, db.TierClient)       // eligible
	unsub := e.user(1002, db.TierClient)   // unsubscribed
	blocked := e.user(1003, db.TierClient) // unreachable
	e.user(1004, db.TierNone)              // banned
	deleted := e.user(1005, db.TierClient) // deleted account
	if err := e.store.SetNotificationPrefs(ctx, unsub, map[string]string{"maintenance": db.PrefUnsubscribed}, "test"); err != nil {
		t.Fatal(err)
	}
	if err := e.store.RecordBotReachability(ctx, blocked, notify.DeliveryOutcome{State: notify.StateBlocked, ReasonCode: "blocked", Conclusive: true}, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.store.HardDeleteAccount(ctx, deleted); err != nil {
		t.Fatal(err)
	}

	p := e.prepare(Selector{Category: "maintenance"}, "Planned maintenance tonight.")
	want := map[string]int{"no_account": 1, "policy": 2 /* banned + the admin operator */, "unsubscribed": 1, "unreachable": 1}
	if p.Counts.Eligible != 1 {
		t.Fatalf("eligible = %d, want 1 (counts %+v)", p.Counts.Eligible, p.Counts)
	}
	for k, v := range want {
		if p.Counts.Skipped[k] != v {
			t.Errorf("skipped[%s] = %d, want %d (all %+v)", k, p.Counts.Skipped[k], v, p.Counts.Skipped)
		}
	}
	if len(p.Sample) != 1 || p.Sample[0].TelegramID != "12…01" {
		t.Fatalf("sample = %+v, want one redacted entry", p.Sample)
	}
	if p.EstimatedBatches != 1 {
		t.Fatalf("batches = %d", p.EstimatedBatches)
	}
	if got := e.state(p.CampaignID); got != db.CampaignPrepared {
		t.Fatalf("state after prepare = %s, want prepared (prepare must never release delivery)", got)
	}
}

func TestPrepare_Refusals(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.RecipientLimit = 1 })
	ctx := context.Background()

	stranger := Actor{UserID: e.user(555, db.TierClient), TelegramID: 555}
	if _, err := e.svc.Prepare(ctx, stranger, PrepareRequest{Selector: Selector{Category: "maintenance"}, Text: "x"}); !errors.Is(err, ErrNotBroadcastAdmin) {
		t.Fatalf("non-operator prepare: %v", err)
	}
	// Only 555 is a client and product_updates defaults to unsubscribed.
	if _, err := e.svc.Prepare(ctx, e.op, PrepareRequest{Selector: Selector{Category: "product_updates"}, Text: "x"}); !errors.Is(err, ErrNoEligibleRecipients) {
		t.Fatalf("empty audience: %v", err)
	}
	e.user(556, db.TierClient)
	if _, err := e.svc.Prepare(ctx, e.op, PrepareRequest{Selector: Selector{Category: "maintenance"}, Text: "x"}); !errors.Is(err, ErrRecipientLimit) {
		t.Fatalf("over limit: %v", err)
	}
	if _, err := e.svc.Prepare(ctx, e.op, PrepareRequest{Selector: Selector{Category: "maintenance"}, Text: "  "}); err == nil {
		t.Fatal("blank text must be refused")
	}
	list, err := e.store.ListBroadcastCampaigns(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 0 {
		t.Fatalf("refused prepares must not create campaigns, got %d", len(list))
	}
}

func TestApprove_BindsContentAndSelectorAndIsSingleUse(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.user(1001, db.TierClient)
	p := e.prepare(Selector{Category: "maintenance"}, "Maintenance.")

	// Content drift: an approval for different text is refused and the
	// campaign stays approvable for the real content.
	if err := e.svc.Approve(ctx, e.op, p.CampaignID, Hash("Maintenance!"), p.SelectorHash); !errors.Is(err, db.ErrCampaignMismatch) {
		t.Fatalf("content drift: %v", err)
	}
	// Selector drift.
	other, _ := Selector{Category: "maintenance", Tiers: []string{"client", "admin"}}.Normalize()
	oj, _ := other.CanonicalJSON()
	if err := e.svc.Approve(ctx, e.op, p.CampaignID, p.ContentHash, Hash(oj)); !errors.Is(err, db.ErrCampaignMismatch) {
		t.Fatalf("selector drift: %v", err)
	}
	if got := e.state(p.CampaignID); got != db.CampaignPrepared {
		t.Fatalf("refused approvals must not change state, got %s", got)
	}
	// Non-operator.
	stranger := Actor{UserID: e.user(777, db.TierClient), TelegramID: 777}
	if err := e.svc.Approve(ctx, stranger, p.CampaignID, p.ContentHash, p.SelectorHash); !errors.Is(err, ErrNotBroadcastAdmin) {
		t.Fatalf("non-operator approve: %v", err)
	}

	if err := e.svc.Approve(ctx, e.op, p.CampaignID, p.ContentHash, p.SelectorHash); err != nil {
		t.Fatalf("approve: %v", err)
	}
	c, _ := e.store.GetBroadcastCampaign(ctx, p.CampaignID)
	if c.State != db.CampaignApproved || c.ApprovedBy == nil || *c.ApprovedBy != e.op.UserID || c.ApprovedAt == nil {
		t.Fatalf("approved row = %+v", c)
	}
	// Replay.
	if err := e.svc.Approve(ctx, e.op, p.CampaignID, p.ContentHash, p.SelectorHash); !errors.Is(err, db.ErrCampaignNotPrepared) {
		t.Fatalf("replayed approval: %v", err)
	}
}

func TestApprove_ExpiredApprovalIsRefusedAndRecorded(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.ApprovalTTL = time.Minute })
	ctx := context.Background()
	e.user(1001, db.TierClient)
	p := e.prepare(Selector{Category: "security"}, "Rotate your token.")
	e.now = e.now.Add(time.Minute) // exactly at expiry: no longer approvable
	if err := e.svc.Approve(ctx, e.op, p.CampaignID, p.ContentHash, p.SelectorHash); !errors.Is(err, db.ErrCampaignExpired) {
		t.Fatalf("expired approval: %v", err)
	}
	if got := e.state(p.CampaignID); got != db.CampaignExpired {
		t.Fatalf("state = %s, want expired", got)
	}
	if err := e.svc.Approve(ctx, e.op, p.CampaignID, p.ContentHash, p.SelectorHash); !errors.Is(err, db.ErrCampaignExpired) {
		t.Fatalf("second approval after expiry: %v", err)
	}
}

func TestApprove_RefusesRowAlteredAfterPreview(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.user(1001, db.TierClient)
	p := e.prepare(Selector{Category: "maintenance"}, "Original.")
	if _, err := e.store.DB.ExecContext(ctx, `UPDATE broadcast_campaigns SET content = 'Swapped.' WHERE id = $1`, p.CampaignID); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Approve(ctx, e.op, p.CampaignID, p.ContentHash, p.SelectorHash); !errors.Is(err, db.ErrCampaignMismatch) {
		t.Fatalf("tampered content approved: %v", err)
	}
	if got := e.state(p.CampaignID); got != db.CampaignPrepared {
		t.Fatalf("state = %s", got)
	}
}

func TestCancel(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.user(1001, db.TierClient)
	p := e.prepare(Selector{Category: "maintenance"}, "Cancel me.")
	if err := e.svc.Cancel(ctx, e.op, p.CampaignID); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if err := e.svc.Approve(ctx, e.op, p.CampaignID, p.ContentHash, p.SelectorHash); !errors.Is(err, db.ErrCampaignNotPrepared) {
		t.Fatalf("approve after cancel: %v", err)
	}
	if err := e.svc.Cancel(ctx, e.op, p.CampaignID); !errors.Is(err, db.ErrCampaignTerminal) {
		t.Fatalf("second cancel: %v", err)
	}
	if err := e.svc.Cancel(ctx, e.op, "bc_missing"); !errors.Is(err, db.ErrCampaignNotFound) {
		t.Fatalf("cancel missing: %v", err)
	}
	// An approved campaign can still be cancelled before delivery.
	p2 := e.prepare(Selector{Category: "maintenance"}, "Second.")
	if err := e.svc.Approve(ctx, e.op, p2.CampaignID, p2.ContentHash, p2.SelectorHash); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Cancel(ctx, e.op, p2.CampaignID); err != nil {
		t.Fatalf("cancel approved: %v", err)
	}
}

func TestExpireBroadcastCampaigns(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.ApprovalTTL = time.Minute })
	ctx := context.Background()
	e.user(1001, db.TierClient)
	p := e.prepare(Selector{Category: "maintenance"}, "Old.")
	n, err := e.store.ExpireBroadcastCampaigns(ctx, e.now)
	if err != nil || n != 0 {
		t.Fatalf("premature expiry: n=%d err=%v", n, err)
	}
	n, err = e.store.ExpireBroadcastCampaigns(ctx, e.now.Add(2*time.Minute))
	if err != nil || n != 1 {
		t.Fatalf("expiry: n=%d err=%v", n, err)
	}
	if got := e.state(p.CampaignID); got != db.CampaignExpired {
		t.Fatalf("state = %s", got)
	}
}

func TestRecipientFacts_ConnectedViaOnlyLiveGrants(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	uid := e.user(1001, db.TierClient)
	ins := `INSERT INTO oauth_refresh_tokens(family_id, token_hash, user_id, client_id, telegram_id, client_name, expires_at, revoked_at)
	        VALUES($1,$2,$3,'c',1001,$4,$5,$6)`
	if _, err := e.store.DB.ExecContext(ctx, ins, "f1", []byte("h1"), uid, "Claude", e.now.Add(time.Hour), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := e.store.DB.ExecContext(ctx, ins, "f2", []byte("h2"), uid, "ChatGPT", e.now.Add(-time.Hour), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := e.store.DB.ExecContext(ctx, ins, "f3", []byte("h3"), uid, "Cursor", e.now.Add(time.Hour), e.now); err != nil {
		t.Fatal(err)
	}
	f, err := e.store.GetBroadcastRecipientFacts(ctx, uid, e.now)
	if err != nil || f == nil {
		t.Fatalf("facts: %+v %v", f, err)
	}
	if len(f.ConnectedVia) != 1 || f.ConnectedVia[0] != "Claude" {
		t.Fatalf("connected_via = %v, want only the live Claude grant", f.ConnectedVia)
	}
	if missing, err := e.store.GetBroadcastRecipientFacts(ctx, 999999, e.now); err != nil || missing != nil {
		t.Fatalf("missing user: %+v %v", missing, err)
	}
}
