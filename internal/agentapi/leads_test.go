package agentapi

import (
	"net/http"
	"testing"
)

// TestHandleSaveLead_LeadIDSelectsLead covers #951 at the API: a save
// without lead_id creates a lead, a save with lead_id updates that lead of
// the same conversation, and a lead_id from another conversation is a 404
// that changes nothing.
func TestHandleSaveLead_LeadIDSelectsLead(t *testing.T) {
	h := newHarness(t)
	alice := h.seedConversation(555)
	bob := h.seedConversation(556)
	save := func(req saveLeadRequest) (int, int64) {
		t.Helper()
		rec := h.do("POST", "/leads", req)
		if rec.Code != http.StatusOK {
			return rec.Code, 0
		}
		var body map[string]int64
		decodeBody(t, rec, &body)
		return rec.Code, body["lead_id"]
	}
	_, goLead := save(saveLeadRequest{ConversationID: alice.ID, Company: "Halcyon Talent", Role: "Senior Go Engineer"})
	_, sreLead := save(saveLeadRequest{ConversationID: alice.ID, Company: "Halcyon Talent", Role: "Site Reliability Engineer"})
	if goLead == 0 || sreLead == 0 || goLead == sreLead {
		t.Fatalf("lead ids = %d, %d; want two distinct leads", goLead, sreLead)
	}
	if code, id := save(saveLeadRequest{ConversationID: alice.ID, LeadID: goLead, Compensation: "to be discussed"}); code != http.StatusOK || id != goLead {
		t.Fatalf("update: code=%d id=%d, want 200 %d", code, id, goLead)
	}
	if code, _ := save(saveLeadRequest{ConversationID: bob.ID, LeadID: goLead, Company: "Injected"}); code != http.StatusNotFound {
		t.Fatalf("cross-conversation update code = %d, want 404", code)
	}

	var ctxBody struct {
		Lead  *leadDTO  `json:"lead"`
		Leads []leadDTO `json:"leads"`
	}
	decodeBody(t, h.do("GET", "/conversations/"+itoaTest(alice.ID)+"/context", nil), &ctxBody)
	if len(ctxBody.Leads) != 2 || ctxBody.Leads[0].ID != goLead || ctxBody.Leads[1].ID != sreLead {
		t.Fatalf("leads = %+v, want [go (just updated), sre]", ctxBody.Leads)
	}
	if ctxBody.Leads[0].Company != "Halcyon Talent" || ctxBody.Leads[0].Role != "Senior Go Engineer" ||
		ctxBody.Leads[0].Compensation != "to be discussed" {
		t.Fatalf("updated lead = %+v", ctxBody.Leads[0])
	}
	if ctxBody.Lead == nil || ctxBody.Lead.ID != goLead {
		t.Fatalf("lead = %+v, want the newest lead %d", ctxBody.Lead, goLead)
	}

	var bobCtx map[string]any
	decodeBody(t, h.do("GET", "/conversations/"+itoaTest(bob.ID)+"/context", nil), &bobCtx)
	if leads, ok := bobCtx["leads"].([]any); !ok || len(leads) != 0 {
		t.Fatalf("bob's leads = %#v, want an empty list (not null), unchanged by the refused update", bobCtx["leads"])
	}
}
