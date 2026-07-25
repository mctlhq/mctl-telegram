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
