package agentworker

import (
	"fmt"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"

	"github.com/mctlhq/mctl-telegram/internal/agent/tools"
)

// toolDef is one tool as either runner sees it: the registered name, the
// schema (mcplib.Tool.InputSchema, unchanged) and the handler.
type toolDef struct {
	Tool    mcplib.Tool
	Handler mcpserver.ToolHandlerFunc
}

// buildToolSet is the single place that binds a job's tool names to handlers.
// NewMCPServer becomes a thin loop over it; OpenAIRunner calls it directly.
func buildToolSet(api agentAPI, job JobContext) (*toolBuilder, []toolDef, error) {
	bindings, err := tools.ForJob(job.Tools)
	if err != nil {
		return nil, nil, err
	}
	b := &toolBuilder{api: api, job: job}
	build := map[string]func() (mcplib.Tool, mcpserver.ToolHandlerFunc){
		"get_event": b.getEvent, "get_conversation_context": b.getConversationContext,
		"get_recruiter_profile": b.getRecruiterProfile, "get_lead": b.getLead,
		"get_policy": b.getPolicy, "propose_reply": b.proposeReply,
		"save_job_lead": b.saveJobLead, "request_owner_approval": b.requestOwnerApproval,
		"send_owner_summary": b.sendOwnerSummary, "pause_autopilot": b.pauseAutopilot,
		"complete_agent_job": b.completeAgentJob,
	}
	defs := make([]toolDef, 0, len(bindings))
	for _, bind := range bindings {
		f, ok := build[bind.Canonical]
		if !ok {
			return nil, nil, fmt.Errorf("no implementation for tool %q", bind.Canonical)
		}
		tool, handler := f()
		tool.Name = bind.Name
		defs = append(defs, toolDef{Tool: tool, Handler: handler})
	}
	return b, defs, nil
}
