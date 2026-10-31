package agentapi

import (
	"context"
	"net/http"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/agent/policy"
	"github.com/mctlhq/mctl-telegram/internal/assistant"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

// TestInstallNeverTier_DeniesProposal follows the never tier from an
// install to a proposal: the install resolves the intent onto the profile's
// denylist, get_policy shows it to the model, and propose_reply
// stores a reply with that intent as denied, with no approval code for the
// owner to release it, while another intent still goes through.
func TestInstallNeverTier_DeniesProposal(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	in, err := assistant.ParseInstall(hrInstallJSON(t, map[string]any{
		"intentTiers": map[string]any{"decline": "never"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	entry, _ := embeddedCatalog(t).Lookup("hr-recruiter", "0.1.0")
	r, err := assistant.Resolve(entry.Definition, in)
	if err != nil {
		t.Fatal(err)
	}
	if r.IntentDenylist != "decline" || r.IntentAllowlist != "discovery,schedule" {
		t.Fatalf("resolved intent lists = %q / %q", r.IntentAllowlist, r.IntentDenylist)
	}
	if err := h.store.UpsertAgentProfile(ctx, db.AgentProfile{
		UserID: h.userID, Mode: r.Mode, DisclosureText: "I'm an AI assistant.",
		MaxAutonomousTurns: r.MaxAutonomousTurns, MaxMsgsPerMinute: r.MaxMsgsPerMinute,
		MaxReplyChars: r.MaxReplyChars, IntentAllowlist: r.IntentAllowlist, IntentDenylist: r.IntentDenylist,
	}); err != nil {
		t.Fatal(err)
	}

	var pol policyResponse
	decodeBody(t, h.do("GET", "/policy", nil), &pol)
	if pol.IntentDenylist != "decline" {
		t.Fatalf("get_policy intent_denylist = %q", pol.IntentDenylist)
	}

	conv := h.seedConversation(555)
	rec := h.do("POST", "/actions/propose_reply", proposeReplyRequest{
		ConversationID: conv.ID, Intent: "decline", Text: "Thanks, but the owner is not looking right now.",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("propose status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var resp actionResponse
	decodeBody(t, rec, &resp)
	if resp.Decision != string(policy.Deny) || resp.Status != db.ActionDenied || resp.ApprovalCode != "" {
		t.Fatalf("never intent: %+v, want denied with no approval code", resp)
	}

	other := h.seedConversation(556)
	rec = h.do("POST", "/actions/propose_reply", proposeReplyRequest{
		ConversationID: other.ID, Intent: "discovery", Text: "Could you share the team size?",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("discovery status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var ok actionResponse
	decodeBody(t, rec, &ok)
	if ok.Decision != string(policy.Allow) {
		t.Fatalf("discovery: %+v, want allow", ok)
	}
}

// get_policy shows the owner's working hours, so the model knows a reply
// will wait for approval inside them.
func TestHandlePolicy_ShowsWorkingHours(t *testing.T) {
	h := newHarness(t)
	if err := h.store.UpsertAgentProfile(context.Background(), db.AgentProfile{
		UserID: h.userID, Mode: db.AgentModeGuarded, DisclosureText: "I'm an AI assistant.",
		WorkingHours: "UTC;mon-fri 09:00-18:00",
	}); err != nil {
		t.Fatal(err)
	}
	var pol policyResponse
	decodeBody(t, h.do("GET", "/policy", nil), &pol)
	if pol.WorkingHours != "UTC;mon-fri 09:00-18:00" {
		t.Fatalf("get_policy working_hours = %q", pol.WorkingHours)
	}
}

// TestInstallRevisionFencesStaleJob: a job claimed under one install
// revision cannot propose once the revision moves (#1018), and a fresh
// claim stamps the new revision.
func TestInstallRevisionFencesStaleJob(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if err := h.store.UpsertAgentProfile(ctx, db.AgentProfile{
		UserID: h.userID, Mode: db.AgentModeGuarded, DisclosureText: "I'm an AI assistant.", IntentAllowlist: "discovery",
	}); err != nil {
		t.Fatal(err)
	}
	conv := h.seedConversation(555)
	jobID := h.seedJob("evt:rev:1", conv.ID)
	claimed, err := h.store.ClaimAgentJobs(ctx, "test-replica", h.userID, 1)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim: %v %v", claimed, err)
	}
	if claimed[0].InstallRevision != 1 {
		t.Fatalf("claimed revision = %d, want 1", claimed[0].InstallRevision)
	}
	if err := h.store.UpdateAgentProfileFields(ctx, h.userID, db.AgentProfileUpdate{BumpInstallRevision: true}); err != nil {
		t.Fatal(err)
	}

	rec := h.do("POST", "/actions/propose_reply", proposeReplyRequest{
		ConversationID: conv.ID, JobID: jobID, Attempt: claimed[0].Attempts, Intent: "discovery", Text: "Could you share the team size?",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var resp actionResponse
	decodeBody(t, rec, &resp)
	if resp.Decision != string(policy.Deny) || len(resp.Reasons) != 1 || resp.Reasons[0] != policy.ReasonInstallChanged {
		t.Fatalf("stale job proposal = %+v, want denied as install changed", resp)
	}

	// A job claimed after the change carries the new revision and acts.
	if err := h.store.CompleteAgentJob(ctx, jobID, claimed[0].Attempts, db.JobIgnored, "test"); err != nil {
		t.Fatal(err)
	}
	fresh := h.seedJob("evt:rev:2", conv.ID)
	claimed, err = h.store.ClaimAgentJobs(ctx, "test-replica", h.userID, 1)
	if err != nil || len(claimed) != 1 || claimed[0].ID != fresh {
		t.Fatalf("claim fresh: %v %v", claimed, err)
	}
	if claimed[0].InstallRevision != 2 {
		t.Fatalf("fresh claim revision = %d, want 2", claimed[0].InstallRevision)
	}
	rec = h.do("POST", "/actions/propose_reply", proposeReplyRequest{
		ConversationID: conv.ID, JobID: fresh, Attempt: claimed[0].Attempts, Intent: "discovery", Text: "Could you share the team size?",
	})
	var ok actionResponse
	decodeBody(t, rec, &ok)
	if ok.Decision != string(policy.Allow) {
		t.Fatalf("fresh job proposal = %+v, want allow", ok)
	}
}
