package agentapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"testing/fstest"

	mctltelegram "github.com/mctlhq/mctl-telegram"
	"github.com/mctlhq/mctl-telegram/internal/assistant"
	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

func embeddedCatalog(t *testing.T) *assistant.Catalog {
	t.Helper()
	c, err := assistant.LoadCatalog(mctltelegram.Catalog)
	if err != nil {
		t.Fatalf("LoadCatalog: %v", err)
	}
	return c
}

func deployedPrompt(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("../../deploy/agent-worker/system-prompt.txt")
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// hrInstallJSON is the HR example install as JSON, with extra spec fields
// merged in.
func hrInstallJSON(t *testing.T, extra map[string]any) json.RawMessage {
	t.Helper()
	in := map[string]any{
		"apiVersion": "assistants.mctl.ai/v1alpha1",
		"kind":       "AssistantInstall",
		"spec": map[string]any{
			"assistant": map[string]any{"name": "hr-recruiter", "version": "0.1.0"},
			"mode":      "guarded",
			"paused":    false,
			"listening": true,
			"values": map[string]any{
				"name": "Dana", "role": "Backend engineer",
				"skills": []string{"Go", "Kubernetes", "PostgreSQL"},
			},
			"limits":     map[string]any{"maxAutonomousTurns": 50, "maxMsgsPerMinute": 2, "maxReplyChars": 1200},
			"disclosure": map[string]any{"enabled": false},
		},
	}
	for k, v := range extra {
		in["spec"].(map[string]any)[k] = v
	}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func doInstall(t *testing.T, h http.HandlerFunc, telegramID int64, install json.RawMessage) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]any{"telegram_id": telegramID, "install": install})
	if err != nil {
		t.Fatal(err)
	}
	return doProfileReq(h, adminIdentity(), string(body))
}

func TestAdminAgentInstallHandler_AppliesInstall(t *testing.T) {
	store := newProfileTestStore(t)
	ctx := context.Background()
	uid, err := store.EnsureUserByTelegramID(ctx, 777, "reviewer", "Reviewer")
	if err != nil {
		t.Fatal(err)
	}
	h := NewAdminAgentInstallHandler(store, embeddedCatalog(t))
	notes := "Keep replies under three sentences."
	rec := doInstall(t, h, 777, hrInstallJSON(t, map[string]any{
		"ownerNotes": notes, "intentTiers": map[string]any{"decline": "never"},
	}))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "Dana") || strings.Contains(rec.Body.String(), notes) {
		t.Fatalf("install values echoed: %s", rec.Body.String())
	}

	p, err := store.GetAgentProfile(ctx, uid)
	if err != nil {
		t.Fatal(err)
	}
	if p.Mode != "guarded" || p.AutopilotPaused || !p.ListenerEnabled || !p.DisclosureDisabled ||
		p.MaxAutonomousTurns != 50 || p.IntentAllowlist != "discovery,schedule" ||
		p.IntentDenylist != "decline" {
		t.Fatalf("profile = %+v", p)
	}
	a, err := store.GetAgentAssistant(ctx, uid)
	if err != nil {
		t.Fatal(err)
	}
	if a.Name != "hr-recruiter" || a.Version != "0.1.0" || !bytes.Contains(a.Install, []byte(notes)) {
		t.Fatalf("assistant = %s@%s install=%q", a.Name, a.Version, a.Install)
	}
	var blob []byte
	if err := store.DB.QueryRowContext(ctx,
		`SELECT install_encrypted FROM agent_profiles WHERE user_id = $1`, uid).Scan(&blob); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, []byte(notes)) || bytes.Contains(blob, []byte("Dana")) {
		t.Fatal("install stored in plaintext")
	}
	owner, err := store.GetAgentOwnerProfile(ctx, uid)
	if err != nil || !bytes.Contains(owner, []byte("Dana")) {
		t.Fatalf("owner profile = %s, err=%v", owner, err)
	}
}

func TestAdminAgentInstallHandler_Rejects(t *testing.T) {
	store := newProfileTestStore(t)
	if _, err := store.EnsureUserByTelegramID(context.Background(), 777, "reviewer", "Reviewer"); err != nil {
		t.Fatal(err)
	}
	h := NewAdminAgentInstallHandler(store, embeddedCatalog(t))

	rec := doProfileReq(h, nil, `{"telegram_id":777}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous status = %d", rec.Code)
	}
	unknown := hrInstallJSON(t, map[string]any{"assistant": map[string]any{"name": "hr-recruiter", "version": "9.9.9"}})
	cases := map[string]struct {
		body string
		code int
	}{
		"unknown key":       {`{"telegram_id":777,"install":{},"extra":1}`, http.StatusBadRequest},
		"missing install":   {`{"telegram_id":777}`, http.StatusBadRequest},
		"schema violation":  {`{"telegram_id":777,"install":{"kind":"AssistantInstall"}}`, http.StatusBadRequest},
		"unknown version":   {`{"telegram_id":777,"install":` + string(unknown) + `}`, http.StatusBadRequest},
		"unknown account":   {`{"telegram_id":778,"install":` + string(hrInstallJSON(t, nil)) + `}`, http.StatusNotFound},
		"above the ceiling": {`{"telegram_id":777,"install":` + string(hrInstallJSON(t, map[string]any{"limits": map[string]any{"maxAutonomousTurns": 51}})) + `}`, http.StatusBadRequest},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if rec := doProfileReq(h, adminIdentity(), tc.body); rec.Code != tc.code {
				t.Fatalf("status = %d, want %d, body=%s", rec.Code, tc.code, rec.Body.String())
			}
		})
	}
	rec = doProfileReq(h, &auth.Identity{UserID: 1, TelegramID: 42}, `{"telegram_id":777,"install":`+string(hrInstallJSON(t, nil))+`}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin status = %d", rec.Code)
	}
}

// Switching an account to another assistant has no lifecycle for its jobs
// and approvals yet, so it is refused rather than half-done.
func TestAdminAgentInstallHandler_RefusesAssistantSwitch(t *testing.T) {
	def, err := os.ReadFile("../../assistants/hr-recruiter/assistant.yaml")
	if err != nil {
		t.Fatal(err)
	}
	other := strings.Replace(strings.Replace(string(def), "name: hr-recruiter", "name: other-assistant", 1),
		"path: ../../deploy/agent-worker/system-prompt.txt", "path: prompt.txt", 1)
	catalog, err := assistant.LoadCatalog(fstest.MapFS{
		"assistants/other-assistant/assistant.yaml": {Data: []byte(other)},
		"assistants/other-assistant/prompt.txt":     {Data: []byte("Other rules.")},
	})
	if err != nil {
		t.Fatal(err)
	}
	store := newProfileTestStore(t)
	ctx := context.Background()
	uid, err := store.EnsureUserByTelegramID(ctx, 777, "reviewer", "Reviewer")
	if err != nil {
		t.Fatal(err)
	}
	install := hrInstallJSON(t, map[string]any{"assistant": map[string]any{"name": "other-assistant", "version": "0.1.0"}})
	rec := doInstall(t, NewAdminAgentInstallHandler(store, catalog), 777, install)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409, body=%s", rec.Code, rec.Body.String())
	}
	a, err := store.GetAgentAssistant(ctx, uid)
	if err != nil || a.Name != "hr-recruiter" || a.Install != nil {
		t.Fatalf("assistant after refusal = %+v, err=%v", a, err)
	}
}

func claimOne(t *testing.T, h *testHarness) (int, []jobEnvelope) {
	t.Helper()
	rec := h.do("POST", "/jobs/claim", nil)
	var body struct {
		Jobs []jobEnvelope `json:"jobs"`
	}
	if rec.Code == http.StatusOK {
		decodeBody(t, rec, &body)
	}
	return rec.Code, body.Jobs
}

// An account that predates the catalog runs the recruiter agent: the
// migration defaults its profile to hr-recruiter@0.1.0, and the claim
// carries the same prompt the worker used to read from its environment.
func TestClaim_CarriesDefaultAssistantInstructions(t *testing.T) {
	h := newHarness(t)
	h.srv.WithCatalog(embeddedCatalog(t))
	h.seedProfile(db.AgentModeGuarded)
	conv := h.seedConversation(555)
	h.seedJob("evt:v1:1:555:instr", conv.ID)

	code, jobs := claimOne(t, h)
	if code != http.StatusOK || len(jobs) != 1 {
		t.Fatalf("claim = %d %+v", code, jobs)
	}
	j := jobs[0]
	if j.Instructions != deployedPrompt(t) {
		t.Fatal("instructions differ from the deployed prompt")
	}
	if j.Assistant != "hr-recruiter@0.1.0" || !strings.HasPrefix(j.AssistantDigest, "sha256:") {
		t.Fatalf("assistant = %q digest = %q", j.Assistant, j.AssistantDigest)
	}
}

func TestClaim_CarriesOwnerNotesFromInstall(t *testing.T) {
	h := newHarness(t)
	h.srv.WithCatalog(embeddedCatalog(t))
	h.seedProfile(db.AgentModeGuarded)
	install := hrInstallJSON(t, map[string]any{"ownerNotes": "Keep replies under three sentences."})
	if err := h.store.UpdateAgentProfileFields(context.Background(), h.userID, db.AgentProfileUpdate{
		InstallDocument: (*[]byte)(&install),
	}); err != nil {
		t.Fatal(err)
	}
	conv := h.seedConversation(555)
	h.seedJob("evt:v1:1:555:notes", conv.ID)

	_, jobs := claimOne(t, h)
	if len(jobs) != 1 {
		t.Fatalf("jobs = %+v", jobs)
	}
	got := jobs[0].Instructions
	if !strings.HasPrefix(got, strings.TrimRight(deployedPrompt(t), "\n")) ||
		!strings.Contains(got, "<owner_notes>\nKeep replies under three sentences.\n</owner_notes>") {
		t.Fatalf("instructions do not end with the owner notes: %q", got[max(0, len(got)-300):])
	}
}

func TestClaim_OmitsInstructionsWithoutCatalog(t *testing.T) {
	h := newHarness(t)
	h.seedProfile(db.AgentModeGuarded)
	conv := h.seedConversation(555)
	h.seedJob("evt:v1:1:555:nocat", conv.ID)
	_, jobs := claimOne(t, h)
	if len(jobs) != 1 || jobs[0].Instructions != "" || jobs[0].Assistant != "" {
		t.Fatalf("jobs = %+v", jobs)
	}
}

// A profile naming an assistant the catalog lacks fails the claim before
// anything is claimed, so the job stays queued instead of running with the
// wrong instructions or sitting claimed until the sweeper.
func TestClaim_UnknownAssistantFailsBeforeClaiming(t *testing.T) {
	h := newHarness(t)
	h.srv.WithCatalog(embeddedCatalog(t))
	h.seedProfile(db.AgentModeGuarded)
	v := "9.9.9"
	if err := h.store.UpdateAgentProfileFields(context.Background(), h.userID, db.AgentProfileUpdate{
		AssistantVersion: &v,
	}); err != nil {
		t.Fatal(err)
	}
	conv := h.seedConversation(555)
	jobID := h.seedJob("evt:v1:1:555:unknown", conv.ID)

	if code, _ := claimOne(t, h); code != http.StatusInternalServerError {
		t.Fatalf("claim status = %d, want 500", code)
	}
	rec := h.do("GET", "/jobs/"+itoaTest(jobID), nil)
	var st jobStatusResponse
	decodeBody(t, rec, &st)
	if st.Status != db.JobPending || st.Attempt != 0 {
		t.Fatalf("job after failed claim = %+v, want pending attempt 0", st)
	}
}

// An enrolled worker for an account that has no profile row yet keeps
// getting empty claims, not a 500 on every poll.
func TestClaim_NoProfileRowIsAnEmptyClaim(t *testing.T) {
	h := newHarness(t)
	h.srv.WithCatalog(embeddedCatalog(t))
	code, jobs := claimOne(t, h)
	if code != http.StatusOK || len(jobs) != 0 {
		t.Fatalf("claim = %d %+v, want 200 with no jobs", code, jobs)
	}
}
