package agentapi

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/agent/profile"
	"github.com/mctlhq/mctl-telegram/internal/assistant"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

// TestAdminAgentProfileHandler_AcceptsHRAssistantInstall applies the HR
// catalog example through the real admin handler, so the mapping in
// internal/assistant cannot drift from the request this handler accepts.
func TestAdminAgentProfileHandler_AcceptsHRAssistantInstall(t *testing.T) {
	read := func(name string) []byte {
		raw, err := os.ReadFile("../../assistants/hr-recruiter/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	def, err := assistant.ParseDefinition(read("assistant.yaml"))
	if err != nil {
		t.Fatalf("definition: %v", err)
	}
	in, err := assistant.ParseInstall(read("install.example.yaml"))
	if err != nil {
		t.Fatalf("install: %v", err)
	}

	store := newProfileTestStore(t)
	ctx := context.Background()
	uid, err := store.EnsureUserByTelegramID(ctx, 777, "reviewer", "Reviewer")
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	req, err := assistant.ProfileRequest(def, in, 777)
	if err != nil {
		t.Fatalf("ProfileRequest: %v", err)
	}
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	rec := doProfileReq(NewAdminAgentProfileHandler(store), adminIdentity(), string(body))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}

	got, err := store.GetAgentProfile(ctx, uid)
	if err != nil {
		t.Fatalf("GetAgentProfile: %v", err)
	}
	want := db.AgentProfile{
		Mode:               "guarded",
		ListenerEnabled:    true,
		DisclosureDisabled: true,
		MaxAutonomousTurns: 50,
		MaxMsgsPerMinute:   2,
		MaxReplyChars:      1200,
		IntentAllowlist:    "discovery,schedule",
		InstallRevision:    1,
		AssistantName:      "hr-recruiter",
	}
	got.UserID, got.CreatedAt, got.UpdatedAt = 0, want.CreatedAt, want.UpdatedAt
	if *got != want {
		t.Fatalf("stored profile\n got %+v\nwant %+v", *got, want)
	}

	document, err := store.GetAgentOwnerProfile(ctx, uid)
	if err != nil {
		t.Fatalf("GetAgentOwnerProfile: %v", err)
	}
	d, err := profile.ParseJSON(document)
	if err != nil {
		t.Fatalf("stored owner profile: %v", err)
	}
	if d.Identity["name"] != "Dana" || !d.Restricted["salary_floor"].NeverAutoSend {
		t.Fatalf("stored owner profile = %+v", d)
	}
}
