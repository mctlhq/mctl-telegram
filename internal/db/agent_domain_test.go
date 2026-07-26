package db

import (
	"context"
	"testing"
	"time"
)

func TestUpsertAgentProfile_DefaultsAndUpdate(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedAgentUser(t, s, "owner")

	if _, err := s.GetAgentProfile(ctx, uid); err != ErrAgentProfileNotFound {
		t.Fatalf("missing profile err = %v, want ErrAgentProfileNotFound", err)
	}

	// Zero-valued limits must be replaced with safe defaults, not stored as 0.
	if err := s.UpsertAgentProfile(ctx, AgentProfile{UserID: uid}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	p, err := s.GetAgentProfile(ctx, uid)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if p.Mode != AgentModeObserve {
		t.Fatalf("mode = %q, want observe", p.Mode)
	}
	if p.MaxAutonomousTurns != 6 || p.MaxMsgsPerMinute != 2 || p.MaxReplyChars != 1200 {
		t.Fatalf("limits = %d/%d/%d, want 6/2/1200",
			p.MaxAutonomousTurns, p.MaxMsgsPerMinute, p.MaxReplyChars)
	}

	// Full replace on conflict.
	if err := s.UpsertAgentProfile(ctx, AgentProfile{
		UserID: uid, Mode: AgentModeGuarded, ListenerEnabled: true,
		DisclosureText: "AI assistant", MaxAutonomousTurns: 3,
		MaxMsgsPerMinute: 1, MaxReplyChars: 500,
		IntentAllowlist: "greet,request_company", BlockedSenders: "42",
		SenderAllowlist: "555,777",
	}); err != nil {
		t.Fatalf("upsert 2: %v", err)
	}
	p, err = s.GetAgentProfile(ctx, uid)
	if err != nil {
		t.Fatalf("get 2: %v", err)
	}
	if p.Mode != AgentModeGuarded || !p.ListenerEnabled || p.MaxAutonomousTurns != 3 {
		t.Fatalf("update not applied: %+v", p)
	}
	if p.SenderAllowlist != "555,777" {
		t.Fatalf("sender allowlist = %q, want 555,777", p.SenderAllowlist)
	}

	// Pause flag flips independently.
	if err := s.SetAgentAutopilotPaused(ctx, uid, true); err != nil {
		t.Fatalf("pause: %v", err)
	}
	p, _ = s.GetAgentProfile(ctx, uid)
	if !p.AutopilotPaused {
		t.Fatal("autopilot_paused not set")
	}
	if err := s.SetAgentAutopilotPaused(ctx, uid+999, true); err != ErrAgentProfileNotFound {
		t.Fatalf("pause missing profile err = %v, want ErrAgentProfileNotFound", err)
	}
}

func TestListListenerEnabledProfiles(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	on := seedAgentUser(t, s, "on")
	off := seedAgentUser(t, s, "off")

	if err := s.UpsertAgentProfile(ctx, AgentProfile{UserID: on, ListenerEnabled: true}); err != nil {
		t.Fatalf("upsert on: %v", err)
	}
	if err := s.UpsertAgentProfile(ctx, AgentProfile{UserID: off}); err != nil {
		t.Fatalf("upsert off: %v", err)
	}
	got, err := s.ListListenerEnabledProfiles(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 || got[0].UserID != on {
		t.Fatalf("list = %+v, want exactly user %d", got, on)
	}
}

func TestEnsureConversation_UpsertAndTurnCounters(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedAgentUser(t, s, "owner")

	c1, err := s.EnsureConversation(ctx, uid, 555, "anna_hr", "Anna")
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if c1.State != ConversationActive || c1.AutonomousTurns != 0 {
		t.Fatalf("fresh conversation: %+v", c1)
	}

	// Same peer → same row, refreshed names.
	c2, err := s.EnsureConversation(ctx, uid, 555, "anna_hr_new", "Anna R.")
	if err != nil {
		t.Fatalf("ensure 2: %v", err)
	}
	if c2.ID != c1.ID {
		t.Fatalf("second ensure created new row: %d != %d", c2.ID, c1.ID)
	}
	if c2.PeerUsername != "anna_hr_new" {
		t.Fatalf("username not refreshed: %q", c2.PeerUsername)
	}

	// A later call with empty metadata (listener saw only a numeric peer)
	// must NOT erase the stored handle/name.
	c3, err := s.EnsureConversation(ctx, uid, 555, "", "")
	if err != nil {
		t.Fatalf("ensure 3: %v", err)
	}
	if c3.PeerUsername != "anna_hr_new" || c3.PeerDisplayName != "Anna R." {
		t.Fatalf("empty-metadata call erased peer info: %+v", c3)
	}

	if err := s.IncrementAutonomousTurns(ctx, uid, c1.ID); err != nil {
		t.Fatalf("increment: %v", err)
	}
	if err := s.IncrementAutonomousTurns(ctx, uid, c1.ID); err != nil {
		t.Fatalf("increment 2: %v", err)
	}
	got, _ := s.GetConversation(ctx, uid, c1.ID)
	if got.AutonomousTurns != 2 {
		t.Fatalf("turns = %d, want 2", got.AutonomousTurns)
	}
	if got.LastAgentReplyAt.IsZero() {
		t.Fatal("last_agent_reply_at not stamped")
	}
	if err := s.ResetAutonomousTurns(ctx, uid, c1.ID); err != nil {
		t.Fatalf("reset: %v", err)
	}
	got, _ = s.GetConversation(ctx, uid, c1.ID)
	if got.AutonomousTurns != 0 {
		t.Fatalf("turns after reset = %d, want 0", got.AutonomousTurns)
	}

	if err := s.SetConversationState(ctx, uid, c1.ID, ConversationTakenOver); err != nil {
		t.Fatalf("set state: %v", err)
	}
	got, _ = s.GetConversation(ctx, uid, c1.ID)
	if got.State != ConversationTakenOver {
		t.Fatalf("state = %q, want taken_over", got.State)
	}

	// User scoping: another user cannot see or mutate the conversation.
	other := seedAgentUser(t, s, "other")
	if _, err := s.GetConversation(ctx, other, c1.ID); err != ErrConversationNotFound {
		t.Fatalf("cross-user get err = %v, want ErrConversationNotFound", err)
	}
	if err := s.SetConversationState(ctx, other, c1.ID, ConversationClosed); err != ErrConversationNotFound {
		t.Fatalf("cross-user set err = %v, want ErrConversationNotFound", err)
	}
}

func TestConversationMessages_RoundTripAndOrder(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedAgentUser(t, s, "owner")
	conv, err := s.EnsureConversation(ctx, uid, 555, "anna_hr", "Anna")
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}

	bodies := []string{"first", "second", "third"}
	for i, b := range bodies {
		dir := DirectionIncoming
		if i == 1 {
			dir = DirectionAgentOutgoing
		}
		if _, err := s.InsertConversationMessage(ctx, uid, ConversationMessage{
			ConversationID: conv.ID, Direction: dir, Body: b, TGMessageID: int64(i + 1),
		}); err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
	}

	got, err := s.ListConversationMessages(ctx, uid, conv.ID, 2)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	// limit=2 must return the two newest, in chronological order.
	if len(got) != 2 || got[0].Body != "second" || got[1].Body != "third" {
		t.Fatalf("list = %+v, want [second third]", got)
	}
	if got[0].Direction != DirectionAgentOutgoing {
		t.Fatalf("direction = %q", got[0].Direction)
	}

	// Cross-user access must fail, both write and read.
	other := seedAgentUser(t, s, "other")
	if _, err := s.InsertConversationMessage(ctx, other, ConversationMessage{
		ConversationID: conv.ID, Direction: DirectionIncoming, Body: "sneak",
	}); err != ErrConversationNotFound {
		t.Fatalf("cross-user insert err = %v, want ErrConversationNotFound", err)
	}
	if _, err := s.ListConversationMessages(ctx, other, conv.ID, 10); err != ErrConversationNotFound {
		t.Fatalf("cross-user list err = %v, want ErrConversationNotFound", err)
	}
}

// TestListRecentAgentOutgoingTimestamps_SurvivesBusyConversation covers a
// Codex finding on #307: policy.Input.RecentAgentSends' rate-limit input
// used to be built by fetching ListConversationMessages' fixed top-50
// page (any direction) and filtering it in Go. A real agent_outgoing send
// followed by 50+ newer messages of any OTHER direction pushed that send
// out of the page entirely, silently undercounting the rate limit. Querying
// agent_outgoing rows directly (this test) must find the send regardless of
// how many other messages arrived after it.
func TestListRecentAgentOutgoingTimestamps_SurvivesBusyConversation(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedAgentUser(t, s, "owner")
	conv, err := s.EnsureConversation(ctx, uid, 555, "anna_hr", "Anna")
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	since := time.Now().UTC().Add(-time.Minute)

	if _, err := s.InsertConversationMessage(ctx, uid, ConversationMessage{
		ConversationID: conv.ID, Direction: DirectionAgentOutgoing, Body: "the real send", TGMessageID: 1,
	}); err != nil {
		t.Fatalf("insert agent_outgoing: %v", err)
	}
	// 60 newer messages of a DIFFERENT direction — enough to have pushed the
	// send above out of any fixed-size top-N page.
	for i := 0; i < 60; i++ {
		if _, err := s.InsertConversationMessage(ctx, uid, ConversationMessage{
			ConversationID: conv.ID, Direction: DirectionIncoming, Body: "noise", TGMessageID: int64(i + 2),
		}); err != nil {
			t.Fatalf("insert incoming %d: %v", i, err)
		}
	}

	got, err := s.ListRecentAgentOutgoingTimestamps(ctx, uid, conv.ID, since)
	if err != nil {
		t.Fatalf("list recent agent outgoing: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("recent agent outgoing timestamps = %d, want 1 (the send must not be lost behind 60 newer messages of another direction)", len(got))
	}
}
