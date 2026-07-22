package agentworker

import (
	"context"
	"errors"
	"sync"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
)

// agentAPI is the subset of *Client every tool needs — narrowed to an
// interface so tests can substitute a fake without spinning up httptest.
type agentAPI interface {
	GetEvent(ctx context.Context, eventID string) (*EventDTO, error)
	GetConversationContext(ctx context.Context, conversationID int64, limit int) (*ConversationContext, error)
	GetRecruiterProfile(ctx context.Context, peerTGID int64) (map[string]any, error)
	GetPolicy(ctx context.Context) (*PolicyDTO, error)
	ProposeReply(ctx context.Context, conversationID, jobID int64, intent, text string) (*ActionResult, error)
	SaveLead(ctx context.Context, req SaveLeadRequest) (int64, error)
	RequestOwnerApproval(ctx context.Context, conversationID, jobID int64, intent, text string) (*OwnerFacingResult, error)
	SendOwnerSummary(ctx context.Context, conversationID, jobID int64, intent, text string) (*OwnerFacingResult, error)
	PauseAutopilot(ctx context.Context, paused bool) (bool, error)
	CompleteJob(ctx context.Context, jobID int64, attempt int, status, note string) error
}

// JobContext pins the identity of the single job this MCP server instance
// was spawned to work on. These values come from the worker's own poll
// loop (see worker.go), never from the model — a tool that took job_id,
// attempt, conversation_id, or event_id as a model-supplied argument would
// let a confused or adversarial turn address a different job's data with
// this process's credential; auto-filling them here removes that whole
// class of mistake, matching the same "server derives it, caller can't
// override" shape as agentapi.handleProposeReply's peer-less design.
type JobContext struct {
	JobID          int64
	Attempt        int
	EventID        string
	ConversationID int64
}

// ServerName is the MCP server name every worker-spawned Claude invocation
// registers this under; tool names are addressed on the CLI as
// "mcp__<ServerName>__<tool>" (e.g. --allowedTools).
const ServerName = "agent"

// NewMCPServer builds the stdio MCP server for one job. Every tool proxies
// directly onto the matching /api/agent/v1 endpoint via api — there is no
// shell, filesystem, or generic HTTP tool in this surface, satisfying A-PR8's
// restricted-tool-surface requirement by construction (nothing else is ever
// registered).
func NewMCPServer(api agentAPI, job JobContext) *mcpserver.MCPServer {
	srv := mcpserver.NewMCPServer(ServerName, "0.1.0", mcpserver.WithToolCapabilities(false))
	b := &toolBuilder{api: api, job: job}
	srv.AddTool(b.getEvent())
	srv.AddTool(b.getConversationContext())
	srv.AddTool(b.getRecruiterProfile())
	srv.AddTool(b.getLead())
	srv.AddTool(b.getPolicy())
	srv.AddTool(b.proposeReply())
	srv.AddTool(b.saveJobLead())
	srv.AddTool(b.requestOwnerApproval())
	srv.AddTool(b.sendOwnerSummary())
	srv.AddTool(b.pauseAutopilot())
	srv.AddTool(b.completeAgentJob())
	return srv
}

type toolBuilder struct {
	api agentAPI
	job JobContext

	// mu guards completed AND serializes every state-changing tool call.
	// mcp-go's stdio server dispatches queued tool calls to a worker pool,
	// not strictly one-at-a-time — a model turn that issues several tool
	// calls together (a lead save alongside complete_agent_job, say) can
	// have them execute concurrently. An earlier version of this guard only
	// held the lock across the completed-or-not *check*, releasing it
	// before the actual API call ran: two concurrent calls could both pass
	// the check before either finished, so an action could still be
	// persisted (or a second complete_agent_job could still succeed) after
	// the job was already terminal. Holding the lock across the whole
	// handler — check, API call, and (for complete_agent_job) setting
	// completed — closes that race: only one state-changing tool call is
	// ever in flight for a given job at a time.
	mu        sync.Mutex
	completed bool
}

var errJobAlreadyCompleted = errors.New("this job was already marked complete — no further actions are allowed")

// guarded serializes fn against every other guarded call on this
// toolBuilder and refuses to run it at all once complete_agent_job has
// succeeded. fn is called WITH the lock held — it must not call back into
// guarded itself (no handler does).
func (b *toolBuilder) guarded(fn func() (*mcplib.CallToolResult, error)) (*mcplib.CallToolResult, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.completed {
		return toolErr(errJobAlreadyCompleted), nil
	}
	return fn()
}

func (b *toolBuilder) getEvent() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("get_event",
		mcplib.WithDescription("Fetch the full body/metadata of the incoming Telegram message that triggered this job."),
	)
	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		ev, err := b.api.GetEvent(ctx, b.job.EventID)
		if err != nil {
			return toolErr(err), nil
		}
		return jsonResult(ev)
	}
	return tool, handler
}

func (b *toolBuilder) getConversationContext() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("get_conversation_context",
		mcplib.WithDescription("Fetch recent message history and any saved job lead for this job's conversation."),
		mcplib.WithNumber("limit", mcplib.Description("Max messages to return (default 20, max 100).")),
	)
	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		args := req.GetArguments()
		limit := intArg(args, "limit", 0)
		out, err := b.api.GetConversationContext(ctx, b.job.ConversationID, limit)
		if err != nil {
			return toolErr(err), nil
		}
		return jsonResult(out)
	}
	return tool, handler
}

func (b *toolBuilder) getRecruiterProfile() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("get_recruiter_profile",
		mcplib.WithDescription("Fetch the owner's public profile (restricted fields already stripped) to answer questions about the owner's background."),
		mcplib.WithNumber("peer_tg_id",
			mcplib.Required(),
			mcplib.Description("Telegram id of the recruiter/peer asking."),
		),
	)
	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		args := req.GetArguments()
		peer := int64(intArg(args, "peer_tg_id", 0))
		if peer <= 0 {
			return mcplib.NewToolResultError("peer_tg_id is required"), nil
		}
		out, err := b.api.GetRecruiterProfile(ctx, peer)
		if err != nil {
			return toolErr(err), nil
		}
		return jsonResult(out)
	}
	return tool, handler
}

// getLead deliberately takes NO lead_id argument. GET /leads/{id} on the
// server side only checks the caller's account (id.UserID), not which
// conversation a lead belongs to — accepting a model-supplied lead_id would
// let a prompt-injected message from one recruiter fetch another
// conversation's lead details (company, compensation, recruiter identity)
// through this account's own token. Always resolving via this job's own
// conversation (the same lookup get_conversation_context already exposes)
// keeps the tool scoped to data this job is actually allowed to see, the
// same "server derives it, caller can't override" shape as JobContext's
// other pinned fields.
func (b *toolBuilder) getLead() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("get_lead",
		mcplib.WithDescription("Fetch the job lead saved for this job's own conversation, if one exists. Equivalent to get_conversation_context's lead field, offered separately for a quick standalone lookup."),
	)
	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		convCtx, err := b.api.GetConversationContext(ctx, b.job.ConversationID, 0)
		if err != nil {
			return toolErr(err), nil
		}
		if convCtx.Lead == nil {
			return mcplib.NewToolResultError("no lead saved yet for this conversation"), nil
		}
		return jsonResult(convCtx.Lead)
	}
	return tool, handler
}

func (b *toolBuilder) getPolicy() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("get_policy",
		mcplib.WithDescription("Fetch the account's current communication-agent policy (mode, autopilot state, limits) before deciding whether to propose a reply. Advisory only — the server re-evaluates policy on every action regardless of what this returns."),
	)
	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		out, err := b.api.GetPolicy(ctx)
		if err != nil {
			return toolErr(err), nil
		}
		return jsonResult(out)
	}
	return tool, handler
}

func (b *toolBuilder) proposeReply() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("propose_reply",
		mcplib.WithDescription("Propose a reply to send back to this job's conversation peer. The server evaluates policy and may deny, require owner approval, or allow it — it is never sent directly by this call."),
		mcplib.WithString("intent", mcplib.Required(), mcplib.Description("Short intent label, e.g. \"discovery\", \"decline\", \"schedule\".")),
		mcplib.WithString("text", mcplib.Required(), mcplib.Description("Proposed reply text.")),
	)
	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		return b.guarded(func() (*mcplib.CallToolResult, error) {
			args := req.GetArguments()
			intent := stringArg(args, "intent", "")
			text := stringArg(args, "text", "")
			if text == "" {
				return mcplib.NewToolResultError("text is required"), nil
			}
			out, err := b.api.ProposeReply(ctx, b.job.ConversationID, b.job.JobID, intent, text)
			if err != nil {
				return toolErr(err), nil
			}
			return jsonResult(out)
		})
	}
	return tool, handler
}

func (b *toolBuilder) saveJobLead() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("save_job_lead",
		mcplib.WithDescription("Save or update the job-opportunity details extracted from this conversation so far. Safe to call repeatedly with partial data as the conversation progresses — later calls upsert, they do not erase earlier answers."),
		mcplib.WithString("company", mcplib.Description("Company name, if known.")),
		mcplib.WithString("role", mcplib.Description("Role/title, if known.")),
		mcplib.WithString("recruiter_name", mcplib.Description("Recruiter's name, if known.")),
		mcplib.WithNumber("recruiter_tg_id", mcplib.Description("Recruiter's Telegram id, if different from the conversation peer.")),
		mcplib.WithString("compensation", mcplib.Description("Compensation details, if discussed.")),
		mcplib.WithString("status", mcplib.Description("Free-form lead status, e.g. \"discovery\", \"awaiting_details\".")),
		mcplib.WithString("detail", mcplib.Description("Any other relevant free-text detail.")),
	)
	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		return b.guarded(func() (*mcplib.CallToolResult, error) {
			args := req.GetArguments()
			lead := SaveLeadRequest{
				ConversationID: b.job.ConversationID,
				JobID:          b.job.JobID,
				Company:        stringArg(args, "company", ""),
				Role:           stringArg(args, "role", ""),
				RecruiterName:  stringArg(args, "recruiter_name", ""),
				RecruiterTGID:  int64(intArg(args, "recruiter_tg_id", 0)),
				Compensation:   stringArg(args, "compensation", ""),
				Status:         stringArg(args, "status", ""),
				Detail:         stringArg(args, "detail", ""),
			}
			// An all-empty call would still create (or re-bind) a lead row on
			// the server, which is enough to satisfy complete_agent_job's
			// "durable result exists" guard — letting a confused or injected
			// turn close a job with no reply, no real lead data, and no owner
			// notification. Require at least one real field before forwarding.
			if lead.Company == "" && lead.Role == "" && lead.RecruiterName == "" && lead.RecruiterTGID == 0 &&
				lead.Compensation == "" && lead.Status == "" && lead.Detail == "" {
				return mcplib.NewToolResultError("at least one field is required — nothing to save"), nil
			}
			leadID, err := b.api.SaveLead(ctx, lead)
			if err != nil {
				return toolErr(err), nil
			}
			return jsonResult(map[string]any{"lead_id": leadID})
		})
	}
	return tool, handler
}

func (b *toolBuilder) requestOwnerApproval() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("request_owner_approval",
		mcplib.WithDescription("Ask the owner to review and approve/reject something in their own Saved Messages, outside the normal propose_reply flow (e.g. an unusual request that needs an explicit human call)."),
		mcplib.WithString("intent", mcplib.Description("Short intent label.")),
		mcplib.WithString("text", mcplib.Required(), mcplib.Description("What to ask the owner.")),
	)
	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		return b.guarded(func() (*mcplib.CallToolResult, error) {
			args := req.GetArguments()
			text := stringArg(args, "text", "")
			if text == "" {
				return mcplib.NewToolResultError("text is required"), nil
			}
			out, err := b.api.RequestOwnerApproval(ctx, b.job.ConversationID, b.job.JobID, stringArg(args, "intent", ""), text)
			if err != nil {
				return toolErr(err), nil
			}
			return jsonResult(out)
		})
	}
	return tool, handler
}

func (b *toolBuilder) sendOwnerSummary() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("send_owner_summary",
		mcplib.WithDescription("Send the owner an informational summary in their own Saved Messages — no response required from them, purely FYI."),
		mcplib.WithString("intent", mcplib.Description("Short intent label.")),
		mcplib.WithString("text", mcplib.Required(), mcplib.Description("Summary text for the owner.")),
	)
	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		return b.guarded(func() (*mcplib.CallToolResult, error) {
			args := req.GetArguments()
			text := stringArg(args, "text", "")
			if text == "" {
				return mcplib.NewToolResultError("text is required"), nil
			}
			out, err := b.api.SendOwnerSummary(ctx, b.job.ConversationID, b.job.JobID, stringArg(args, "intent", ""), text)
			if err != nil {
				return toolErr(err), nil
			}
			return jsonResult(out)
		})
	}
	return tool, handler
}

// pauseAutopilot is pause-only by construction — it takes no arguments and
// always pauses, never resumes. Resuming is a deliberate, standing-down
// decision only the owner should make, via the authenticated /mctl continue
// slash-command path (internal/agent/control), not a model call. An earlier
// version accepted a paused=false argument: since every action's policy
// check reads the same AutopilotPaused flag, a prompt-injected incoming
// message could otherwise call this tool with paused=false and silently
// clear an owner's own /mctl pause before the worker went on to send a
// reply — undoing the one safety gate the owner has for "stop the agent
// from replying on its own."
func (b *toolBuilder) pauseAutopilot() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("pause_autopilot",
		mcplib.WithDescription("Pause autonomous replies for this account. Use this if the conversation has become something you should not keep handling on your own. Pause-only — resuming is a deliberate owner decision made via /mctl continue, not something this tool can do."),
	)
	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		return b.guarded(func() (*mcplib.CallToolResult, error) {
			out, err := b.api.PauseAutopilot(ctx, true)
			if err != nil {
				return toolErr(err), nil
			}
			return jsonResult(map[string]any{"autopilot_paused": out})
		})
	}
	return tool, handler
}

// completeAgentJob deliberately has no free-text "note" argument. An earlier
// version forwarded a model-supplied note straight to CompleteJob, which
// the server stores unencrypted in agent_jobs.last_error /
// agent_job_attempts.error — a plaintext column, unlike message bodies and
// action payloads elsewhere in this codebase. A field literally described
// as "note about the outcome" is exactly the kind of thing a confused or
// prompt-injected turn would fill with quoted Telegram message content,
// bypassing that encryption. status alone is enough signal for operators.
func (b *toolBuilder) completeAgentJob() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("complete_agent_job",
		mcplib.WithDescription("Mark this job as finished. Call this exactly once, as the last thing you do, after you have taken every action this turn warrants (a reply proposal, a lead save, an owner notification) or determined none was needed. status=completed requires that you actually persisted a result via one of the other tools first — it will be rejected otherwise. Use status=ignored if this message genuinely needed no action, or status=failed if you could not process it."),
		mcplib.WithString("status", mcplib.Required(), mcplib.Description("One of: completed, failed, ignored.")),
	)
	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		return b.guarded(func() (*mcplib.CallToolResult, error) {
			args := req.GetArguments()
			status := stringArg(args, "status", "")
			if status == "" {
				return mcplib.NewToolResultError("status is required"), nil
			}
			if err := b.api.CompleteJob(ctx, b.job.JobID, b.job.Attempt, status, ""); err != nil {
				return toolErr(err), nil
			}
			b.completed = true
			return jsonResult(map[string]any{"completed": true})
		})
	}
	return tool, handler
}

func toolErr(err error) *mcplib.CallToolResult {
	return mcplib.NewToolResultError(err.Error())
}
