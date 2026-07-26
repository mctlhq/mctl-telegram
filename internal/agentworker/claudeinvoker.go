package agentworker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// mcpConfigTempFile writes cfg to a 0600 temp file and returns its path.
// --mcp-config accepts either an inline JSON string or a file path — using a
// file keeps AGENT_API_TOKEN (embedded in the MCP server's env block) out of
// the claude process's argv, which every other process on the host can read
// via /proc/<pid>/cmdline or `ps auxww`.
func mcpConfigTempFile(cfg mcpConfig) (path string, cleanup func(), err error) {
	f, err := os.CreateTemp("", "agent-worker-mcp-*.json")
	if err != nil {
		return "", nil, fmt.Errorf("create mcp config temp file: %w", err)
	}
	cleanup = func() { _ = os.Remove(f.Name()) }
	if err := f.Chmod(0o600); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("chmod mcp config temp file: %w", err)
	}
	enc := json.NewEncoder(f)
	encErr := enc.Encode(cfg)
	closeErr := f.Close()
	if encErr != nil {
		cleanup()
		return "", nil, fmt.Errorf("write mcp config temp file: %w", encErr)
	}
	if closeErr != nil {
		cleanup()
		return "", nil, fmt.Errorf("close mcp config temp file: %w", closeErr)
	}
	return f.Name(), cleanup, nil
}

// allowedTools is the exact and complete set of MCP tools a spawned `claude`
// invocation may use — no Bash, Read, Write, WebFetch, or any other
// built-in tool is ever allowed, so the model's only way to affect anything
// is through this package's 11 API-proxying tools. See NewMCPServer's doc
// comment for why job identity is pinned server-side rather than accepted
// as a tool argument.
var allowedTools = []string{
	"get_event", "get_conversation_context", "get_recruiter_profile", "get_lead", "get_policy",
	"propose_reply", "save_job_lead", "request_owner_approval", "send_owner_summary",
	"pause_autopilot", "complete_agent_job",
}

func qualifiedToolNames() []string {
	out := make([]string, len(allowedTools))
	for i, name := range allowedTools {
		out[i] = fmt.Sprintf("mcp__%s__%s", ServerName, name)
	}
	return out
}

// ClaudeInvoker is the concrete Runner that shells out to the `claude` CLI
// binary (see cmd/agent-worker for the self-invocation `--mcp-serve` mode
// that becomes the MCP server's command). Self is the absolute path to this
// same worker binary (os.Executable()) — the spawned `claude` process
// re-execs it as the MCP server so the tool implementations run in-process
// with this worker's own AGENT_API_TOKEN, never handed to Claude itself.
type ClaudeInvoker struct {
	ClaudeBin    string
	Self         string
	APIBaseURL   string
	APIToken     string
	SystemPrompt string
	// MaxBudgetUSD, if > 0, is passed as --max-budget-usd so a single job
	// cannot spend past this even if the model loops.
	MaxBudgetUSD float64
}

// mcpConfig is the JSON shape `claude --mcp-config` expects for an inline
// (non-file) server definition.
type mcpConfig struct {
	MCPServers map[string]mcpServerConfig `json:"mcpServers"`
}

type mcpServerConfig struct {
	Command    string            `json:"command"`
	Args       []string          `json:"args"`
	Env        map[string]string `json:"env"`
	AlwaysLoad bool              `json:"alwaysLoad"`
}

// ErrAgentDidNotCompleteJob means Claude exited successfully but the durable
// job remained non-terminal (or was completed under a different attempt).
// A zero process exit is not a successful worker outcome unless the model
// actually called complete_agent_job and its fenced database transition
// succeeded.
var ErrAgentDidNotCompleteJob = errors.New("agent did not complete job")

// Run builds and executes one `claude -p` invocation for job. The model does
// all of its work through the 11 MCP tools, and this method reports success
// only when both the CLI result is successful and the API confirms that this
// exact claimed attempt reached a terminal state.
func (c *ClaudeInvoker) Run(ctx context.Context, job JobEnvelope) error {
	cfg := mcpConfig{MCPServers: map[string]mcpServerConfig{
		ServerName: {
			Command: c.Self,
			Args:    []string{"--mcp-serve"},
			// Claude Code starts MCP servers asynchronously by default. A
			// single-turn `claude -p` can therefore build and dispatch its
			// only model request before this cold stdio server's tools are
			// present. alwaysLoad makes startup wait for the server (bounded
			// by Claude Code's MCP connection timeout) and eagerly includes
			// all 11 tools in the first turn.
			AlwaysLoad: true,
			Env: map[string]string{
				"AGENT_API_BASE_URL": c.APIBaseURL,
				"AGENT_API_TOKEN":    c.APIToken,
				"AGENT_JOB_ID":       fmt.Sprintf("%d", job.JobID),
				"AGENT_JOB_ATTEMPT":  fmt.Sprintf("%d", job.Attempt),
				"AGENT_JOB_EVENT_ID": job.EventID,
				"AGENT_JOB_CONV_ID":  fmt.Sprintf("%d", job.ConversationID),
			},
		},
	}}
	cfgPath, cleanup, err := mcpConfigTempFile(cfg)
	if err != nil {
		return fmt.Errorf("write mcp config: %w", err)
	}
	defer cleanup()

	args := []string{
		"-p", jobPrompt(),
		"--mcp-config", cfgPath,
		"--strict-mcp-config",
		// --allowedTools only grants permission for the listed tools — it
		// does not remove Claude's built-in tools (Bash, Read, Write, ...)
		// from the available set. --tools "" disables every built-in tool
		// so the model's ONLY way to affect anything is the 11 MCP tools
		// this package exposes — the restriction allowedTools's own doc
		// comment already claimed but didn't actually enforce.
		"--tools", "",
		"--allowedTools", strings.Join(qualifiedToolNames(), ","),
		"--output-format", "json",
		// The transcript for every job otherwise contains plaintext Telegram
		// message bodies and history (from get_event/get_conversation_context
		// tool results) written under HOME by Claude Code's own session
		// persistence — outside this service's encrypted tables and
		// retention sweeper entirely. --no-session-persistence (documented
		// for --print mode) stops that write.
		"--no-session-persistence",
	}
	if c.SystemPrompt != "" {
		args = append(args, "--system-prompt", c.SystemPrompt)
	}
	if c.MaxBudgetUSD > 0 {
		args = append(args, "--max-budget-usd", fmt.Sprintf("%.2f", c.MaxBudgetUSD))
	}

	claudeBin := c.ClaudeBin
	if claudeBin == "" {
		claudeBin = "claude"
	}
	cmd := exec.CommandContext(ctx, claudeBin, args...)
	cmd.Env = minimalEnv()
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	if runErr != nil {
		// Deliberately excludes stderr content from the returned error:
		// worker.Loop logs this error verbatim (slog.Warn), and stderr can
		// carry the model's own output — which can itself carry the
		// fetched Telegram message body it was reasoning about, on a
		// malformed-output or prompt-injection path. The redaction layer
		// operates on structured attribute keys, not free-form error
		// values, so embedding raw content here would bypass it. Length is
		// still useful for triage without the content.
		return fmt.Errorf("claude -p exited: %w (stderr: %d bytes, see run logs)", runErr, stderr.Len())
	}
	res, parseErr := ParseClaudeResult(stdout.Bytes())
	if parseErr != nil {
		return fmt.Errorf("job %d: %w (stdout: %d bytes, see run logs)", job.JobID, parseErr, stdout.Len())
	}
	if err := CheckResult(res); err != nil {
		return err
	}

	// The final model text is never evidence of a completed action: a model
	// with no tools can emit text that merely resembles a tool call and still
	// exit 0/is_error=false. Query the API's durable, user-scoped job record
	// instead. Requiring the same attempt preserves the claim fencing used by
	// complete_agent_job and prevents a stale invocation from taking credit
	// for a newer worker's completion.
	status, err := NewClient(c.APIBaseURL, c.APIToken, nil).GetJobStatus(ctx, job.JobID)
	if err != nil {
		return fmt.Errorf("verify job %d completion: %w", job.JobID, err)
	}
	if status.JobID != job.JobID || status.Attempt != job.Attempt || !status.Terminal() {
		return fmt.Errorf("%w: job_id=%d returned_job_id=%d status=%s attempt=%d expected_attempt=%d",
			ErrAgentDidNotCompleteJob, job.JobID, status.JobID, status.Status, status.Attempt, job.Attempt)
	}
	return nil
}

// jobPrompt is deliberately minimal AND deliberately job-identity-free: the
// model has get_event and get_conversation_context tools to pull its own
// context, resolved server-side from the pinned JobContext (see
// NewMCPServer's doc comment), so the prompt never needs to name this turn's
// event. An earlier version embedded job.EventID directly — which encodes
// the account/chat/message Telegram IDs (see the evt:v1:<acct>:<chat>:<msgid>
// format) — in this string, and -p places it straight into the claude
// process's argv, defeating the same /proc/<pid>/cmdline exposure the
// 0600 mcp-config file was written specifically to avoid for the API token.
func jobPrompt() string {
	return "A new Telegram message arrived. Use get_event and get_conversation_context to see it and the conversation so far, decide what to do, and call complete_agent_job exactly once when you are done."
}

// minimalEnv passes through only what the `claude` subprocess needs to
// authenticate and run (HOME for credential/config lookup, PATH to find its
// own dependencies, explicit proxy/custom-CA settings, and any
// CLAUDE_CODE_*/ANTHROPIC_* auth vars already in this process's environment)
// rather than the worker's full environment —
// AGENT_API_TOKEN in particular must never leak into the model's own
// process env since it is set only on the MCP server subprocess's env
// (see Run's mcpServerConfig.Env), not this one.
func minimalEnv() []string {
	var out []string
	passthrough := map[string]struct{}{
		"HOME": {}, "PATH": {}, "USER": {},
		"HTTP_PROXY": {}, "HTTPS_PROXY": {}, "NO_PROXY": {},
		"http_proxy": {}, "https_proxy": {}, "no_proxy": {},
		"NODE_EXTRA_CA_CERTS": {}, "SSL_CERT_FILE": {}, "SSL_CERT_DIR": {},
	}
	for _, kv := range os.Environ() {
		key, _, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		_, explicitlyAllowed := passthrough[key]
		switch {
		case explicitlyAllowed:
			out = append(out, kv)
		case strings.HasPrefix(key, "CLAUDE_"):
			out = append(out, kv)
		case strings.HasPrefix(key, "ANTHROPIC_"):
			out = append(out, kv)
		}
	}
	return out
}
