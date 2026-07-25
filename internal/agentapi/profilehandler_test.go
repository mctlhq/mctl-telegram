package agentapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/crypto"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

// newProfileTestStore mirrors newHarness's DB setup (server_test.go) without
// pulling in the full Server/queue/router — this handler only needs a Store.
func newProfileTestStore(t *testing.T) *db.Store {
	t.Helper()
	ctx := context.Background()
	conn, err := db.Open(ctx, "file::memory:?cache=shared", 0, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := db.Migrate(ctx, conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	crypt, err := crypto.New(testCryptKey())
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}
	return db.NewStore(conn, crypt)
}

func adminIdentity() *auth.Identity {
	return &auth.Identity{UserID: 1, TelegramID: 42, Scopes: []string{"admin:users"}}
}

func doProfileReq(h http.HandlerFunc, id *auth.Identity, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPut, "/api/admin/agent/profile", bytes.NewBufferString(body))
	if id != nil {
		req = req.WithContext(auth.With(req.Context(), id))
	}
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

func TestAdminAgentProfileHandler_RejectsAnonymous(t *testing.T) {
	h := NewAdminAgentProfileHandler(newProfileTestStore(t))
	rec := doProfileReq(h, nil, `{"telegram_id":777}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestAdminAgentProfileHandler_RejectsNonAdmin(t *testing.T) {
	h := NewAdminAgentProfileHandler(newProfileTestStore(t))
	rec := doProfileReq(h, &auth.Identity{UserID: 1, TelegramID: 42}, `{"telegram_id":777}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403, body=%s", rec.Code, rec.Body.String())
	}
}

func TestAdminAgentProfileHandler_RejectsMissingTelegramID(t *testing.T) {
	h := NewAdminAgentProfileHandler(newProfileTestStore(t))
	rec := doProfileReq(h, adminIdentity(), `{}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestAdminAgentProfileHandler_RejectsInvalidMode(t *testing.T) {
	store := newProfileTestStore(t)
	if _, err := store.EnsureUserByTelegramID(context.Background(), 777, "reviewer", "Reviewer"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	h := NewAdminAgentProfileHandler(store)
	rec := doProfileReq(h, adminIdentity(), `{"telegram_id":777,"mode":"yolo"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}
}

func TestAdminAgentProfileHandler_UnknownTelegramID404s(t *testing.T) {
	h := NewAdminAgentProfileHandler(newProfileTestStore(t))
	rec := doProfileReq(h, adminIdentity(), `{"telegram_id":999999}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404, body=%s", rec.Code, rec.Body.String())
	}
}

func TestAdminAgentProfileHandler_CreatesWithSafeDefaults(t *testing.T) {
	store := newProfileTestStore(t)
	if _, err := store.EnsureUserByTelegramID(context.Background(), 777, "reviewer", "Reviewer"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	h := NewAdminAgentProfileHandler(store)
	rec := doProfileReq(h, adminIdentity(), `{"telegram_id":777}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	var resp agentProfileResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Mode != db.AgentModeObserve {
		t.Errorf("mode = %q, want observe", resp.Mode)
	}
	if !resp.AutopilotPaused {
		t.Errorf("autopilot_paused = false, want true (safe default)")
	}
	if resp.ListenerEnabled {
		t.Errorf("listener_enabled = true, want false (safe default)")
	}
}

// TestAdminAgentProfileHandler_ExplicitEmptyStringClearsField guards the P2
// fix: disclosure_text/intent_allowlist/blocked_senders must distinguish
// "field omitted" (leave alone) from "field explicitly set to empty string"
// (clear it) — otherwise, once set, none of them could ever be unset short of
// a direct SQL update.
func TestAdminAgentProfileHandler_ExplicitEmptyStringClearsField(t *testing.T) {
	store := newProfileTestStore(t)
	if _, err := store.EnsureUserByTelegramID(context.Background(), 777, "reviewer", "Reviewer"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	h := NewAdminAgentProfileHandler(store)

	first := doProfileReq(h, adminIdentity(), `{"telegram_id":777,"blocked_senders":"111,222","disclosure_text":"I'm an AI."}`)
	if first.Code != http.StatusOK {
		t.Fatalf("first call status = %d, want 200, body=%s", first.Code, first.Body.String())
	}

	second := doProfileReq(h, adminIdentity(), `{"telegram_id":777,"blocked_senders":""}`)
	if second.Code != http.StatusOK {
		t.Fatalf("second call status = %d, want 200, body=%s", second.Code, second.Body.String())
	}
	var resp agentProfileResponse
	if err := json.NewDecoder(second.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.BlockedSenders != "" {
		t.Errorf("blocked_senders = %q, want cleared to empty by explicit \"\"", resp.BlockedSenders)
	}
	if resp.DisclosureText != "I'm an AI." {
		t.Errorf("disclosure_text = %q, want unchanged (field omitted from second request)", resp.DisclosureText)
	}
}

// TestAdminAgentProfileHandler_DoesNotClobberConcurrentAutopilotPause guards
// the Codex P1: a partial update that never touches autopilot_paused must
// not revert a concurrent SetAgentAutopilotPaused(true) write (the call
// POST /autopilot/pause and the owner's /mctl pause command use) just
// because it happened to run between this handler reading and re-writing a
// stale copy of the row. The old read-modify-write implementation could
// lose exactly this race; the current UpdateAgentProfileFields-based
// implementation never reads autopilot_paused at all when the request
// doesn't mention it, so there is nothing to go stale.
func TestAdminAgentProfileHandler_DoesNotClobberConcurrentAutopilotPause(t *testing.T) {
	store := newProfileTestStore(t)
	ctx := context.Background()
	uid, err := store.EnsureUserByTelegramID(ctx, 777, "reviewer", "Reviewer")
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if err := store.UpsertAgentProfile(ctx, db.AgentProfile{UserID: uid, Mode: db.AgentModeObserve}); err != nil {
		t.Fatalf("seed profile: %v", err)
	}
	h := NewAdminAgentProfileHandler(store)

	// Simulates the safety pause landing in between this admin request's
	// (implicit) read of the account and its write -- e.g. the owner sends
	// /mctl pause in Saved Messages while an operator happens to be updating
	// an unrelated field like max_reply_chars at the same moment.
	if err := store.SetAgentAutopilotPaused(ctx, uid, true); err != nil {
		t.Fatalf("set autopilot paused: %v", err)
	}

	rec := doProfileReq(h, adminIdentity(), `{"telegram_id":777,"max_reply_chars":900}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	var resp agentProfileResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.AutopilotPaused {
		t.Errorf("autopilot_paused = false, want true -- the concurrent safety pause was clobbered")
	}
	if resp.MaxReplyChars != 900 {
		t.Errorf("max_reply_chars = %d, want 900", resp.MaxReplyChars)
	}
}

// TestAdminAgentProfileHandler_NegativeLimitDoesNotLeakIntoResponse guards
// the response/DB divergence found in review: a negative limit must not be
// echoed back as "honored" when UpsertAgentProfile is about to silently
// clamp it to the default.
func TestAdminAgentProfileHandler_NegativeLimitDoesNotLeakIntoResponse(t *testing.T) {
	store := newProfileTestStore(t)
	uid, err := store.EnsureUserByTelegramID(context.Background(), 777, "reviewer", "Reviewer")
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	h := NewAdminAgentProfileHandler(store)

	rec := doProfileReq(h, adminIdentity(), `{"telegram_id":777,"max_msgs_per_minute":-1}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	var resp agentProfileResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.MaxMsgsPerMinute != 2 {
		t.Errorf("max_msgs_per_minute = %d, want 2 (default) — a negative value must not be echoed as honored", resp.MaxMsgsPerMinute)
	}
	stored, err := store.GetAgentProfile(context.Background(), uid)
	if err != nil {
		t.Fatalf("get profile: %v", err)
	}
	if stored.MaxMsgsPerMinute != 2 {
		t.Errorf("stored max_msgs_per_minute = %d, want 2", stored.MaxMsgsPerMinute)
	}
}

// TestAdminAgentProfileHandler_PartialUpdatePreservesOtherFields is the
// read-modify-write guarantee the admin workflow depends on: flipping just
// listener_enabled must not reset mode/limits set by an earlier call.
func TestAdminAgentProfileHandler_PartialUpdatePreservesOtherFields(t *testing.T) {
	store := newProfileTestStore(t)
	if _, err := store.EnsureUserByTelegramID(context.Background(), 777, "reviewer", "Reviewer"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	h := NewAdminAgentProfileHandler(store)

	first := doProfileReq(h, adminIdentity(), `{"telegram_id":777,"mode":"guarded","max_reply_chars":500}`)
	if first.Code != http.StatusOK {
		t.Fatalf("first call status = %d, want 200, body=%s", first.Code, first.Body.String())
	}

	second := doProfileReq(h, adminIdentity(), `{"telegram_id":777,"listener_enabled":true}`)
	if second.Code != http.StatusOK {
		t.Fatalf("second call status = %d, want 200, body=%s", second.Code, second.Body.String())
	}
	var resp agentProfileResponse
	if err := json.NewDecoder(second.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.ListenerEnabled {
		t.Errorf("listener_enabled = false, want true")
	}
	if resp.Mode != db.AgentModeGuarded {
		t.Errorf("mode = %q, want guarded to survive the partial update", resp.Mode)
	}
	if resp.MaxReplyChars != 500 {
		t.Errorf("max_reply_chars = %d, want 500 to survive the partial update", resp.MaxReplyChars)
	}
}

// TestAdminAgentProfileHandler_CrossAccountIsolation guards against the
// obvious footgun for an endpoint keyed by telegram_id in the request body
// rather than the caller's own identity: upserting account A's profile must
// never touch account B's row.
func TestAdminAgentProfileHandler_CrossAccountIsolation(t *testing.T) {
	store := newProfileTestStore(t)
	ctx := context.Background()
	if _, err := store.EnsureUserByTelegramID(ctx, 111, "alice", "Alice"); err != nil {
		t.Fatalf("seed user A: %v", err)
	}
	bID, err := store.EnsureUserByTelegramID(ctx, 222, "bob", "Bob")
	if err != nil {
		t.Fatalf("seed user B: %v", err)
	}
	if err := store.UpsertAgentProfile(ctx, db.AgentProfile{
		UserID: bID, Mode: db.AgentModeGuarded, ListenerEnabled: true, MaxReplyChars: 999,
	}); err != nil {
		t.Fatalf("seed B profile: %v", err)
	}

	h := NewAdminAgentProfileHandler(store)
	rec := doProfileReq(h, adminIdentity(), `{"telegram_id":111,"mode":"off","listener_enabled":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}

	bProfile, err := store.GetAgentProfile(ctx, bID)
	if err != nil {
		t.Fatalf("get B profile: %v", err)
	}
	if bProfile.Mode != db.AgentModeGuarded || !bProfile.ListenerEnabled || bProfile.MaxReplyChars != 999 {
		t.Errorf("account B profile was mutated by an account A request: %+v", bProfile)
	}
}

func TestAdminAgentProfileHandler_RejectsUnknownFields(t *testing.T) {
	store := newProfileTestStore(t)
	if _, err := store.EnsureUserByTelegramID(context.Background(), 777, "reviewer", "Reviewer"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	h := NewAdminAgentProfileHandler(store)
	rec := doProfileReq(h, adminIdentity(), `{"telegram_id":777,"totally_made_up_field":true}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (strict decode should reject unknown fields), body=%s", rec.Code, rec.Body.String())
	}
}
