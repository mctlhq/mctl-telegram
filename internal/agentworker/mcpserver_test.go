package agentworker

import (
	"context"
	"errors"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
)

// fakeAPI records every call it receives and returns canned/erroring
// responses, so tool handlers can be tested without an httptest server.
type fakeAPI struct {
	getEventCalls               []string
	getConversationContextCalls []struct {
		convID int64
		limit  int
	}
	proposeReplyCalls []struct {
		convID, jobID int64
		intent, text  string
	}
	saveLeadCalls    []SaveLeadRequest
	completeJobCalls []struct {
		jobID   int64
		attempt int
		status  string
		note    string
	}
	pauseAutopilotCalls []bool

	// leadToReturn is served back on GetConversationContext's Lead field —
	// getLead resolves through that call now, not a standalone GetLead API.
	leadToReturn *LeadDTO

	err error
}

func (f *fakeAPI) GetEvent(ctx context.Context, eventID string) (*EventDTO, error) {
	f.getEventCalls = append(f.getEventCalls, eventID)
	if f.err != nil {
		return nil, f.err
	}
	return &EventDTO{EventID: eventID, Body: "hello"}, nil
}

func (f *fakeAPI) GetConversationContext(ctx context.Context, conversationID int64, limit int) (*ConversationContext, error) {
	f.getConversationContextCalls = append(f.getConversationContextCalls, struct {
		convID int64
		limit  int
	}{conversationID, limit})
	if f.err != nil {
		return nil, f.err
	}
	return &ConversationContext{Conversation: ConversationDTO{ID: conversationID}, Lead: f.leadToReturn}, nil
}

func (f *fakeAPI) GetRecruiterProfile(ctx context.Context, peerTGID int64) (map[string]any, error) {
	if f.err != nil {
		return nil, f.err
	}
	return map[string]any{"name": "Owner"}, nil
}

func (f *fakeAPI) GetPolicy(ctx context.Context) (*PolicyDTO, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &PolicyDTO{Mode: "observe"}, nil
}

func (f *fakeAPI) ProposeReply(ctx context.Context, conversationID, jobID int64, intent, text string) (*ActionResult, error) {
	f.proposeReplyCalls = append(f.proposeReplyCalls, struct {
		convID, jobID int64
		intent, text  string
	}{conversationID, jobID, intent, text})
	if f.err != nil {
		return nil, f.err
	}
	return &ActionResult{ActionID: 1, Decision: "require_approval", ApprovalCode: "AB12"}, nil
}

func (f *fakeAPI) SaveLead(ctx context.Context, req SaveLeadRequest) (int64, error) {
	f.saveLeadCalls = append(f.saveLeadCalls, req)
	if f.err != nil {
		return 0, f.err
	}
	return 7, nil
}

func (f *fakeAPI) RequestOwnerApproval(ctx context.Context, conversationID, jobID int64, intent, text string) (*OwnerFacingResult, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &OwnerFacingResult{ActionID: 2, NotificationID: 3}, nil
}

func (f *fakeAPI) SendOwnerSummary(ctx context.Context, conversationID, jobID int64, intent, text string) (*OwnerFacingResult, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &OwnerFacingResult{ActionID: 4, NotificationID: 5}, nil
}

func (f *fakeAPI) PauseAutopilot(ctx context.Context, paused bool) (bool, error) {
	f.pauseAutopilotCalls = append(f.pauseAutopilotCalls, paused)
	if f.err != nil {
		return false, f.err
	}
	return paused, nil
}

func (f *fakeAPI) CompleteJob(ctx context.Context, jobID int64, attempt int, status, note string) error {
	f.completeJobCalls = append(f.completeJobCalls, struct {
		jobID   int64
		attempt int
		status  string
		note    string
	}{jobID, attempt, status, note})
	return f.err
}

func callTool(t *testing.T, tool mcplib.Tool, handler mcpserver.ToolHandlerFunc, args map[string]any) *mcplib.CallToolResult {
	t.Helper()
	req := mcplib.CallToolRequest{}
	req.Params.Name = tool.Name
	req.Params.Arguments = args
	res, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	return res
}

func TestGetEvent_UsesJobsPinnedEventID_NotAnyModelArgument(t *testing.T) {
	api := &fakeAPI{}
	b := &toolBuilder{api: api, job: JobContext{EventID: "evt:v1:1:2:3"}}
	tool, handler := b.getEvent()
	// Even if a caller tried to pass an event_id argument, the tool schema
	// has no such parameter — the handler must still only ever use the
	// pinned job.EventID.
	callTool(t, tool, handler, map[string]any{"event_id": "evt:attacker-supplied"})
	if len(api.getEventCalls) != 1 || api.getEventCalls[0] != "evt:v1:1:2:3" {
		t.Fatalf("getEventCalls = %#v", api.getEventCalls)
	}
}

func TestProposeReply_AutoFillsConversationAndJobID(t *testing.T) {
	api := &fakeAPI{}
	b := &toolBuilder{api: api, job: JobContext{JobID: 42, ConversationID: 9}}
	tool, handler := b.proposeReply()
	res := callTool(t, tool, handler, map[string]any{"intent": "discovery", "text": "Thanks for reaching out!"})
	if res.IsError {
		t.Fatalf("unexpected tool error: %#v", res)
	}
	if len(api.proposeReplyCalls) != 1 {
		t.Fatalf("proposeReplyCalls = %#v", api.proposeReplyCalls)
	}
	call := api.proposeReplyCalls[0]
	if call.convID != 9 || call.jobID != 42 || call.text != "Thanks for reaching out!" {
		t.Fatalf("call = %#v", call)
	}
}

func TestProposeReply_EmptyTextIsRejectedLocally(t *testing.T) {
	api := &fakeAPI{}
	b := &toolBuilder{api: api, job: JobContext{JobID: 42, ConversationID: 9}}
	tool, handler := b.proposeReply()
	res := callTool(t, tool, handler, map[string]any{"intent": "discovery"})
	if !res.IsError {
		t.Fatal("expected tool error for missing text")
	}
	if len(api.proposeReplyCalls) != 0 {
		t.Fatalf("should not have called the API: %#v", api.proposeReplyCalls)
	}
}

func TestCompleteAgentJob_UsesJobsPinnedIDAndAttempt(t *testing.T) {
	api := &fakeAPI{}
	b := &toolBuilder{api: api, job: JobContext{JobID: 42, Attempt: 3}}
	tool, handler := b.completeAgentJob()
	// Even if the model tried to supply job_id/attempt, the schema has no
	// such parameters, so a stale or wrong value can never override the
	// worker's own claim.
	res := callTool(t, tool, handler, map[string]any{"status": "completed", "job_id": 999, "attempt": 1})
	if res.IsError {
		t.Fatalf("unexpected tool error: %#v", res)
	}
	if len(api.completeJobCalls) != 1 {
		t.Fatalf("completeJobCalls = %#v", api.completeJobCalls)
	}
	call := api.completeJobCalls[0]
	if call.jobID != 42 || call.attempt != 3 || call.status != "completed" {
		t.Fatalf("call = %#v", call)
	}
}

func TestCompleteAgentJob_MissingStatusIsRejectedLocally(t *testing.T) {
	api := &fakeAPI{}
	b := &toolBuilder{api: api, job: JobContext{JobID: 42, Attempt: 1}}
	tool, handler := b.completeAgentJob()
	res := callTool(t, tool, handler, map[string]any{})
	if !res.IsError {
		t.Fatal("expected tool error for missing status")
	}
}

func TestSaveJobLead_PassesThroughAllFields(t *testing.T) {
	api := &fakeAPI{}
	b := &toolBuilder{api: api, job: JobContext{JobID: 1, ConversationID: 9}}
	tool, handler := b.saveJobLead()
	callTool(t, tool, handler, map[string]any{
		"company": "Acme", "role": "Engineer", "recruiter_name": "Anna",
		"recruiter_tg_id": float64(555), "compensation": "$$$", "status": "discovery", "detail": "remote ok",
	})
	if len(api.saveLeadCalls) != 1 {
		t.Fatalf("saveLeadCalls = %#v", api.saveLeadCalls)
	}
	req := api.saveLeadCalls[0]
	if req.Company != "Acme" || req.RecruiterTGID != 555 || req.ConversationID != 9 || req.JobID != 1 {
		t.Fatalf("req = %#v", req)
	}
}

func TestAPIErrorSurfacesAsToolError(t *testing.T) {
	api := &fakeAPI{err: errors.New("agent api: 404: conversation not found")}
	b := &toolBuilder{api: api, job: JobContext{ConversationID: 9}}
	tool, handler := b.getConversationContext()
	res := callTool(t, tool, handler, map[string]any{})
	if !res.IsError {
		t.Fatal("expected tool error to surface")
	}
}

func TestNewMCPServer_RegistersAllElevenTools(t *testing.T) {
	srv := NewMCPServer(&fakeAPI{}, JobContext{JobID: 1, ConversationID: 2, EventID: "evt:1"})
	if srv == nil {
		t.Fatal("expected non-nil server")
	}
	got := srv.ListTools()
	if len(got) != 11 {
		t.Fatalf("registered %d tools, want 11: %v", len(got), toolNames(got))
	}
	for _, name := range allowedTools {
		if _, ok := got[name]; !ok {
			t.Fatalf("tool %q not registered: %v", name, toolNames(got))
		}
	}
}

func toolNames(m map[string]*mcpserver.ServerTool) []string {
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	return names
}

// TestGetLead_ScopedToJobsOwnConversation guards against the P1 finding
// that a model-supplied lead_id let a prompt-injected message fetch a
// different conversation's lead through this job's own token — get_lead now
// takes no lead_id argument at all and only ever resolves this job's own
// conversation, via the same call get_conversation_context uses.
func TestGetLead_ScopedToJobsOwnConversation(t *testing.T) {
	api := &fakeAPI{leadToReturn: &LeadDTO{ID: 7, Company: "Acme"}}
	b := &toolBuilder{api: api, job: JobContext{ConversationID: 9}}
	tool, handler := b.getLead()
	// Even if a caller tried to pass a lead_id, the tool schema has no such
	// parameter — confirm the underlying lookup used the job's own
	// conversation, not any attacker-supplied id.
	res := callTool(t, tool, handler, map[string]any{"lead_id": float64(999)})
	if res.IsError {
		t.Fatalf("unexpected tool error: %#v", res)
	}
	if len(api.getConversationContextCalls) != 1 || api.getConversationContextCalls[0].convID != 9 {
		t.Fatalf("getConversationContextCalls = %#v", api.getConversationContextCalls)
	}
}

func TestGetLead_NoLeadYetIsAToolError(t *testing.T) {
	api := &fakeAPI{}
	b := &toolBuilder{api: api, job: JobContext{ConversationID: 9}}
	tool, handler := b.getLead()
	res := callTool(t, tool, handler, map[string]any{})
	if !res.IsError {
		t.Fatal("expected a tool error when no lead exists yet")
	}
}

// TestPauseAutopilot_AlwaysPausesRegardlessOfArgument guards against the P1
// finding that a paused=false argument let a prompt-injected message clear
// the owner's own /mctl pause gate — the tool takes no argument at all now
// and always pauses.
func TestPauseAutopilot_AlwaysPausesRegardlessOfArgument(t *testing.T) {
	api := &fakeAPI{}
	b := &toolBuilder{api: api, job: JobContext{}}
	tool, handler := b.pauseAutopilot()
	callTool(t, tool, handler, map[string]any{"paused": false})
	if len(api.pauseAutopilotCalls) != 1 || api.pauseAutopilotCalls[0] != true {
		t.Fatalf("pauseAutopilotCalls = %#v, want [true] regardless of the paused=false argument", api.pauseAutopilotCalls)
	}
}

// TestSaveJobLead_AllEmptyFieldsIsRejectedLocally guards against the P2
// finding that an all-empty save_job_lead call still created a lead row
// satisfying complete_agent_job's durable-result guard, letting a job close
// with no reply, no real lead data, and no owner notification.
func TestSaveJobLead_AllEmptyFieldsIsRejectedLocally(t *testing.T) {
	api := &fakeAPI{}
	b := &toolBuilder{api: api, job: JobContext{JobID: 1, ConversationID: 9}}
	tool, handler := b.saveJobLead()
	res := callTool(t, tool, handler, map[string]any{})
	if !res.IsError {
		t.Fatal("expected a tool error for an all-empty save")
	}
	if len(api.saveLeadCalls) != 0 {
		t.Fatalf("should not have called the API: %#v", api.saveLeadCalls)
	}
}

// TestToolsRejectFurtherCallsAfterJobCompletes guards against the P1
// finding that the MCP server process stays alive and every other handler
// remains callable after complete_agent_job succeeds — nothing on the
// server side knows this MCP session is "done", so the local guard is what
// actually stops it.
func TestToolsRejectFurtherCallsAfterJobCompletes(t *testing.T) {
	api := &fakeAPI{leadToReturn: &LeadDTO{ID: 1}}
	b := &toolBuilder{api: api, job: JobContext{JobID: 1, Attempt: 1, ConversationID: 9}}

	completeTool, completeHandler := b.completeAgentJob()
	res := callTool(t, completeTool, completeHandler, map[string]any{"status": "ignored"})
	if res.IsError {
		t.Fatalf("first complete_agent_job call should succeed: %#v", res)
	}
	if len(api.completeJobCalls) != 1 {
		t.Fatalf("completeJobCalls = %#v", api.completeJobCalls)
	}

	cases := []struct {
		name    string
		call    func() *mcplib.CallToolResult
		apiHits func() int
	}{
		{"propose_reply", func() *mcplib.CallToolResult {
			tool, handler := b.proposeReply()
			return callTool(t, tool, handler, map[string]any{"text": "hi"})
		}, func() int { return len(api.proposeReplyCalls) }},
		{"save_job_lead", func() *mcplib.CallToolResult {
			tool, handler := b.saveJobLead()
			return callTool(t, tool, handler, map[string]any{"company": "Acme"})
		}, func() int { return len(api.saveLeadCalls) }},
		{"pause_autopilot", func() *mcplib.CallToolResult {
			tool, handler := b.pauseAutopilot()
			return callTool(t, tool, handler, map[string]any{})
		}, func() int { return len(api.pauseAutopilotCalls) }},
		{"complete_agent_job again", func() *mcplib.CallToolResult {
			tool, handler := b.completeAgentJob()
			return callTool(t, tool, handler, map[string]any{"status": "completed"})
		}, func() int { return len(api.completeJobCalls) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			before := c.apiHits()
			res := c.call()
			if !res.IsError {
				t.Fatalf("%s: expected a tool error after job completion", c.name)
			}
			if after := c.apiHits(); after != before {
				t.Fatalf("%s: API was called (before=%d after=%d) despite the job already being complete", c.name, before, after)
			}
		})
	}
}
