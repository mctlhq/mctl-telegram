package db

import (
	"context"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/notify"
)

func TestRecordOIDCBotAccessGrant(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUserByTelegramID(ctx, 111, "alice", "Alice")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()

	applied, err := s.RecordOIDCBotAccessGrant(ctx, uid, now.Add(-time.Hour), notify.SourceOIDCBotAccess)
	if err != nil || !applied {
		t.Fatalf("insert: applied=%v err=%v", applied, err)
	}
	r, _ := s.GetBotReachability(ctx, uid)
	if r == nil || r.State != notify.StateReachable || r.Source != notify.SourceOIDCBotAccess || r.ReasonCode != notify.SourceOIDCBotAccess {
		t.Fatalf("row: %+v", r)
	}
	// Same or older observation does not apply.
	if applied, _ := s.RecordOIDCBotAccessGrant(ctx, uid, now.Add(-time.Hour), notify.SourceOIDCBotAccess); applied {
		t.Fatal("equal observation applied")
	}
	// A conclusive blocked outcome overrides, and a later grant never lifts it.
	blocked := notify.DeliveryOutcome{State: notify.StateBlocked, ReasonCode: "bot_blocked", Conclusive: true}
	if err := s.RecordBotReachability(ctx, uid, blocked, "digest"); err != nil {
		t.Fatal(err)
	}
	if applied, _ := s.RecordOIDCBotAccessGrant(ctx, uid, now.Add(time.Hour), notify.SourceOIDCBotAccess); applied {
		t.Fatal("grant overwrote blocked")
	}
	// cannot_initiate with an older observed_at is lifted by a newer grant.
	ci := notify.DeliveryOutcome{State: notify.StateCannotInitiate, ReasonCode: "chat_not_found", Conclusive: true}
	if err := s.RecordBotReachability(ctx, uid, ci, "digest"); err != nil {
		t.Fatal(err)
	}
	if applied, err := s.RecordOIDCBotAccessGrant(ctx, uid, now.Add(time.Hour), notify.SourceOIDCBotAccess); err != nil || !applied {
		t.Fatalf("cannot_initiate lift: applied=%v err=%v", applied, err)
	}
	if _, err := s.RecordOIDCBotAccessGrant(ctx, 0, now, notify.SourceOIDCBotAccess); err == nil {
		t.Fatal("zero user accepted")
	}
	if _, err := s.RecordOIDCBotAccessGrant(ctx, uid, now.Add(2*time.Hour), "digest_delivery"); err == nil {
		t.Fatal("non-oidc source accepted")
	}
	// The getChat source is stored as both source and reason_code.
	if applied, err := s.RecordOIDCBotAccessGrant(ctx, uid, now.Add(3*time.Hour), notify.SourceOIDCGetChat); err != nil || !applied {
		t.Fatalf("getChat source: applied=%v err=%v", applied, err)
	}
	r, err = s.GetBotReachability(ctx, uid)
	if err != nil || r == nil || r.Source != notify.SourceOIDCGetChat || r.ReasonCode != notify.SourceOIDCGetChat {
		t.Fatalf("getChat row = %+v err=%v", r, err)
	}
}
