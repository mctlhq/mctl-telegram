package agentworker

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTestServer(t *testing.T, handler http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return NewClient(srv.URL, "test-token", srv.Client()), srv
}

// TestNewClient_TrimsTrailingSlash guards against a Codex finding: every
// path this package builds already starts with "/", so an operator-supplied
// base URL ending in "/" (".../v1/", which reads as valid) produced a
// double slash (".../v1//events") that the mounted chi router never
// matches — a 404 on every single request, forever, with the worker
// otherwise looking healthy.
func TestNewClient_TrimsTrailingSlash(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		writeJSONFixture(w, map[string]any{"jobs": []JobEnvelope{}})
	}))
	t.Cleanup(srv.Close)
	client := NewClient(srv.URL+"/", "test-token", srv.Client())
	if _, err := client.PollEvents(context.Background(), 1); err != nil {
		t.Fatalf("PollEvents: %v", err)
	}
	if gotPath != "/events" {
		t.Fatalf("path = %q, want /events (no double slash)", gotPath)
	}
}

func TestClient_SendsBearerToken(t *testing.T) {
	var gotAuth string
	client, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		writeJSONFixture(w, map[string]any{"jobs": []JobEnvelope{}})
	})
	if _, err := client.PollEvents(context.Background(), 1); err != nil {
		t.Fatalf("PollEvents: %v", err)
	}
	if gotAuth != "Bearer test-token" {
		t.Fatalf("Authorization = %q", gotAuth)
	}
}

func TestClient_PollEvents_ParsesJobs(t *testing.T) {
	client, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("limit") != "3" {
			t.Fatalf("limit = %q", r.URL.Query().Get("limit"))
		}
		writeJSONFixture(w, map[string]any{"jobs": []JobEnvelope{
			{JobID: 1, EventID: "evt:1", ConversationID: 9, Attempt: 1, Deadline: "2026-01-01T00:00:00Z"},
		}})
	})
	jobs, err := client.PollEvents(context.Background(), 3)
	if err != nil {
		t.Fatalf("PollEvents: %v", err)
	}
	if len(jobs) != 1 || jobs[0].JobID != 1 || jobs[0].ConversationID != 9 {
		t.Fatalf("jobs = %#v", jobs)
	}
}

func TestClient_NonOKStatus_ReturnsAPIError(t *testing.T) {
	client, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "job is no longer claimed under that attempt"})
	})
	err := client.CompleteJob(context.Background(), 1, 1, "completed", "")
	if err == nil {
		t.Fatal("expected error")
	}
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("err type = %T", err)
	}
	if apiErr.StatusCode != http.StatusConflict {
		t.Fatalf("StatusCode = %d", apiErr.StatusCode)
	}
	if apiErr.Message != "job is no longer claimed under that attempt" {
		t.Fatalf("Message = %q", apiErr.Message)
	}
}

func TestClient_ProposeReply_OmitsJobIDWhenZero(t *testing.T) {
	var gotBody map[string]any
	client, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		writeJSONFixture(w, ActionResult{ActionID: 5, Decision: "require_approval", Status: "pending_approval", ApprovalCode: "AB12"})
	})
	res, err := client.ProposeReply(context.Background(), 9, 0, 0, "discovery", "hi there")
	if err != nil {
		t.Fatalf("ProposeReply: %v", err)
	}
	if res.ApprovalCode != "AB12" {
		t.Fatalf("ApprovalCode = %q", res.ApprovalCode)
	}
	if _, ok := gotBody["job_id"]; ok {
		t.Fatalf("job_id should be omitted when zero: %#v", gotBody)
	}
	if _, ok := gotBody["attempt"]; ok {
		t.Fatalf("attempt should be omitted when job_id is zero: %#v", gotBody)
	}
	if gotBody["conversation_id"].(float64) != 9 {
		t.Fatalf("conversation_id = %#v", gotBody["conversation_id"])
	}
}

// TestClient_ProposeReply_SendsAttemptWithJobID guards against a Codex
// finding on #308: InsertAgentAction now fences job-tied action inserts by
// the job's live status/attempt (see its doc comment), so a caller that
// omits attempt on a job-tied propose_reply would always be rejected as a
// stale attempt (0 never matches a real claimed job).
func TestClient_ProposeReply_SendsAttemptWithJobID(t *testing.T) {
	var gotBody map[string]any
	client, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		writeJSONFixture(w, ActionResult{ActionID: 5, Decision: "allow"})
	})
	if _, err := client.ProposeReply(context.Background(), 9, 42, 3, "discovery", "hi there"); err != nil {
		t.Fatalf("ProposeReply: %v", err)
	}
	if gotBody["job_id"].(float64) != 42 {
		t.Fatalf("job_id = %#v", gotBody["job_id"])
	}
	if gotBody["attempt"].(float64) != 3 {
		t.Fatalf("attempt = %#v, want 3", gotBody["attempt"])
	}
}

func TestClient_GetConversationContext_ParsesLead(t *testing.T) {
	client, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/conversations/9/context" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		writeJSONFixture(w, ConversationContext{
			Conversation: ConversationDTO{ID: 9, PeerTGID: 555, State: "active"},
			Messages:     []ConversationMessageDTO{{Direction: "incoming", Body: "hi"}},
			Lead:         &LeadDTO{ID: 1, Company: "Acme"},
		})
	})
	ctx, err := client.GetConversationContext(context.Background(), 9, 0)
	if err != nil {
		t.Fatalf("GetConversationContext: %v", err)
	}
	if ctx.Lead == nil || ctx.Lead.Company != "Acme" {
		t.Fatalf("lead = %#v", ctx.Lead)
	}
	if len(ctx.Messages) != 1 {
		t.Fatalf("messages = %#v", ctx.Messages)
	}
}

func TestClient_CompleteJob_SendsAttemptAndStatus(t *testing.T) {
	var gotBody map[string]any
	var gotPath string
	client, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		writeJSONFixture(w, map[string]any{"completed": true})
	})
	if err := client.CompleteJob(context.Background(), 42, 2, "completed", "sent reply"); err != nil {
		t.Fatalf("CompleteJob: %v", err)
	}
	if gotPath != "/jobs/42/complete" {
		t.Fatalf("path = %q", gotPath)
	}
	if gotBody["attempt"].(float64) != 2 || gotBody["status"] != "completed" {
		t.Fatalf("body = %#v", gotBody)
	}
}

func writeJSONFixture(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
