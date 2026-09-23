package db

import (
	"context"
	"testing"
	"time"
)

// TestLastConnectStepFor_EmptyInputShortCircuits is T12: a nil/empty tgIDs
// slice must return an empty map without issuing a query at all (building
// "IN ()" is a syntax error on both engines, so this is a correctness
// requirement, not just an optimisation).
func TestLastConnectStepFor_EmptyInputShortCircuits(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	// A store whose DB is closed would error on any real query — proving
	// the short-circuit never reaches the database.
	if err := s.DB.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	out, err := s.LastConnectStepFor(ctx, nil)
	if err != nil {
		t.Fatalf("LastConnectStepFor(nil) returned an error against a closed DB: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("expected an empty map, got %+v", out)
	}
}

// TestLastConnectStepFor_MostRecentStepAndNeverStarted covers the core
// query: the most recent connect:* row wins, and a user with only
// non-connect audit rows is absent from the result.
func TestLastConnectStepFor_MostRecentStepAndNeverStarted(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	aliceUID, err := s.EnsureUserByTelegramID(ctx, 500100101, "alice_tg", "Alice")
	if err != nil {
		t.Fatalf("ensure alice: %v", err)
	}
	bobUID, err := s.EnsureUserByTelegramID(ctx, 500100102, "bob_tg", "Bob")
	if err != nil {
		t.Fatalf("ensure bob: %v", err)
	}
	carolUID, err := s.EnsureUserByTelegramID(ctx, 500100103, "carol_tg", "Carol")
	if err != nil {
		t.Fatalf("ensure carol: %v", err)
	}

	// Alice: two connect steps — the later one must win.
	s.LogToolCall(ctx, aliceUID, "connect:phone_submitted", "", "ok", "", "")
	time.Sleep(2 * time.Millisecond)
	s.LogToolCall(ctx, aliceUID, "connect:failed:flood_wait", "", "error", "FLOOD_WAIT_300", "")

	// Bob: only a non-connect tool call — must be absent from the result.
	s.LogToolCall(ctx, bobUID, "list_dialogs", "", "ok", "", "")

	// Carol: no audit rows at all.
	_ = carolUID

	out, err := s.LastConnectStepFor(ctx, []int64{500100101, 500100102, 500100103})
	if err != nil {
		t.Fatalf("LastConnectStepFor: %v", err)
	}

	alice, ok := out[500100101]
	if !ok {
		t.Fatal("expected an entry for alice")
	}
	if alice.Step != "failed:flood_wait" || alice.Status != "error" {
		t.Errorf("alice = %+v, want the later failed:flood_wait row", alice)
	}

	if _, ok := out[500100102]; ok {
		t.Error("bob has no connect:* row and must be absent from the result")
	}
	if _, ok := out[500100103]; ok {
		t.Error("carol has no audit rows at all and must be absent from the result")
	}
}

// TestLastConnectStepFor_RevokedReason is T8's companion for the reason
// half: a revoked session's reason rides along on the same call, keyed by
// Telegram id.
func TestLastConnectStepFor_RevokedReason(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	uid, err := s.EnsureUserByTelegramID(ctx, 500100104, "dana_tg", "Dana")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, telegram_user_id, session_encrypted, revoked_at, revoked_reason)
		 VALUES($1,$2,$3,CURRENT_TIMESTAMP,$4)`,
		uid, 500100104, []byte("s"), "disconnect",
	); err != nil {
		t.Fatalf("insert revoked account: %v", err)
	}

	out, err := s.LastConnectStepFor(ctx, []int64{500100104})
	if err != nil {
		t.Fatalf("LastConnectStepFor: %v", err)
	}
	cs, ok := out[500100104]
	if !ok {
		t.Fatal("expected an entry carrying the revoked_reason even with no connect:* audit row")
	}
	if cs.RevokedReason != "disconnect" {
		t.Errorf("RevokedReason = %q, want disconnect", cs.RevokedReason)
	}
}

// TestLastConnectStepFor_NeverSelectsPeerOrError is T8: the query never
// projects audit_logs.peer_redacted or .error, so a seeded row carrying a
// synthetic peer handle and a distinctive error marker in those columns must
// not leak into the result.
func TestLastConnectStepFor_NeverSelectsPeerOrError(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	uid, err := s.EnsureUserByTelegramID(ctx, 500100105, "erin_tg", "Erin")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	const peerMarker = "@erin_synthetic_handle"
	const errorMarker = "DO-NOT-LEAK-ERROR-MARKER-4471"
	s.LogToolCall(ctx, uid, "connect:failed:code_invalid", peerMarker, "error", errorMarker, "")

	out, err := s.LastConnectStepFor(ctx, []int64{500100105})
	if err != nil {
		t.Fatalf("LastConnectStepFor: %v", err)
	}
	cs, ok := out[500100105]
	if !ok {
		t.Fatal("expected an entry for erin")
	}
	if cs.Step != "failed:code_invalid" {
		t.Errorf("Step = %q, want failed:code_invalid", cs.Step)
	}
	// The struct has no field to hold either forbidden value — this is a
	// belt-and-braces check that nothing was ever scanned into Step/Status
	// that could carry them through.
	if cs.Step == peerMarker || cs.Step == errorMarker || cs.Status == peerMarker || cs.Status == errorMarker {
		t.Fatalf("leaked forbidden column content: %+v", cs)
	}
}

// TestVerifyAuditChain_UnaffectedByRevokedReasonColumn is T9: the new
// telegram_accounts.revoked_reason column lives outside audit_logs, so
// VerifyAuditChain must return OK both for a chain written before this
// change existed conceptually (no revoke involved at all) and for one
// written after a session on the same user was revoked with a reason —
// proving no new column feeds hashAuditEntry.
func TestVerifyAuditChain_UnaffectedByRevokedReasonColumn(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUserByTelegramID(ctx, 500100106, "frank_tg", "Frank")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}

	s.LogToolCall(ctx, uid, "connect:phone_submitted", "", "ok", "", "")
	if res, err := s.VerifyAuditChain(ctx, uid); err != nil || !res.OK {
		t.Fatalf("chain before revoke: OK=%v err=%v", res.OK, err)
	}

	if _, err := s.RevokeActiveSession(ctx, uid, "disconnect"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	s.LogToolCall(ctx, uid, "connect:success", "", "ok", "", "")

	res, err := s.VerifyAuditChain(ctx, uid)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.OK {
		t.Fatalf("chain must still verify after a revoke with a reason: %+v", res)
	}
	if res.Verified != 2 {
		t.Fatalf("Verified = %d, want 2", res.Verified)
	}
}
