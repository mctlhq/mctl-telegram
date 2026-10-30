package agentworker

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"
)

// TestSaveJobLead_ForwardsLeadID: the model picks the lead to update from
// get_conversation_context's leads (#951); omitting lead_id creates one.
// The job's own conversation is always the one sent, so the server can
// refuse a lead_id that belongs elsewhere.
func TestSaveJobLead_ForwardsLeadID(t *testing.T) {
	api := &fakeAPI{}
	b := &toolBuilder{api: api, job: JobContext{JobID: 42, Attempt: 3, ConversationID: 9}}
	tool, handler := b.saveJobLead()
	if res := callTool(t, tool, handler, map[string]any{"role": "Site Reliability Engineer"}); res.IsError {
		t.Fatalf("create failed: %#v", res)
	}
	if res := callTool(t, tool, handler, map[string]any{"lead_id": float64(5), "compensation": "to be discussed"}); res.IsError {
		t.Fatalf("update failed: %#v", res)
	}
	if len(api.saveLeadCalls) != 2 {
		t.Fatalf("save calls = %d, want 2", len(api.saveLeadCalls))
	}
	if c := api.saveLeadCalls[0]; c.LeadID != 0 || c.ConversationID != 9 {
		t.Fatalf("create call = %+v, want no lead id in conversation 9", c)
	}
	if c := api.saveLeadCalls[1]; c.LeadID != 5 || c.ConversationID != 9 || c.Compensation != "to be discussed" {
		t.Fatalf("update call = %+v, want lead 5 in conversation 9", c)
	}
	if res := callTool(t, tool, handler, map[string]any{"lead_id": float64(5)}); !res.IsError {
		t.Fatal("a lead_id with no field to save must still be refused")
	}
}

func TestClient_SaveLead_SendsLeadIDOnlyWhenSet(t *testing.T) {
	var bodies []map[string]any
	client, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		bodies = append(bodies, b)
		writeJSONFixture(w, map[string]int64{"lead_id": 7})
	})
	for _, id := range []int64{0, 5} {
		if _, err := client.SaveLead(context.Background(), SaveLeadRequest{ConversationID: 9, LeadID: id, Company: "Acme"}); err != nil {
			t.Fatalf("SaveLead(%d): %v", id, err)
		}
	}
	// A server that predates #951 rejects unknown fields, so a create must
	// not carry lead_id at all.
	if _, present := bodies[0]["lead_id"]; present {
		t.Fatalf("create body carries lead_id: %#v", bodies[0])
	}
	if bodies[1]["lead_id"] != float64(5) {
		t.Fatalf("update body lead_id = %#v, want 5", bodies[1]["lead_id"])
	}
}

func TestGetLead_ReturnsAllLeadsWithLegacyFallback(t *testing.T) {
	api := &fakeAPI{
		leadToReturn:  &LeadDTO{ID: 2, Role: "Site Reliability Engineer"},
		leadsToReturn: []LeadDTO{{ID: 2, Role: "Site Reliability Engineer"}, {ID: 1, Role: "Senior Go Engineer"}},
	}
	b := &toolBuilder{api: api, job: JobContext{ConversationID: 9}}
	tool, handler := b.getLead()
	text := resultText(t, callTool(t, tool, handler, map[string]any{}))
	if !strings.Contains(text, "Senior Go Engineer") || !strings.Contains(text, "Site Reliability Engineer") {
		t.Fatalf("get_lead = %s, want both leads", text)
	}

	// An older server sends only lead.
	api.leadsToReturn = nil
	text = resultText(t, callTool(t, tool, handler, map[string]any{}))
	if !strings.Contains(text, `"leads"`) || !strings.Contains(text, "Site Reliability Engineer") {
		t.Fatalf("legacy get_lead = %s, want the single lead as a list", text)
	}
}

func resultText(t *testing.T, res *mcplib.CallToolResult) string {
	t.Helper()
	if res.IsError {
		t.Fatalf("tool error: %#v", res)
	}
	var sb strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(mcplib.TextContent); ok {
			sb.WriteString(tc.Text)
		}
	}
	return sb.String()
}
