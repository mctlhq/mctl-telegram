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

	"github.com/mctlhq/mctl-telegram/internal/agent/tools"
	"github.com/mctlhq/mctl-telegram/internal/metrics"
)

// mcpConfigTempFile writes cfg to a 0600 temp file and returns its path.
// Using a file keeps AGENT_API_TOKEN out of argv.
func mcpConfigTempFile(cfg mcpConfig) (path string, cleanup func(), err error) {
	f, err := os.CreateTemp("", "agent-worker-mcp-*.json")
	if err != nil {
		return "", nil, fmt.Errorf("create mcp config temp file: %w", err)
	}
	cleanup = func() { _ = os.Remove(f.Name()) }
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
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

// promptTempFile keeps the per-account system prompt out of argv.
func promptTempFile(prompt string) (path string, cleanup func(), err error) {
	f, err := os.CreateTemp("", "agent-worker-prompt-*.txt")
	if err != nil {
		return "", nil, fmt.Errorf("create prompt temp file: %w", err)
	}
	cleanup = func() { _ = os.Remove(f.Name()) }
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		cleanup()
		return "", nil, fmt.Errorf("chmod prompt temp file: %w", err)
	}
	_, writeErr := f.WriteString(prompt)
	closeErr := f.Close()
	if writeErr != nil {
		cleanup()
		return "", nil, fmt.Errorf("write system prompt: %w", writeErr)
	}
	if closeErr != nil {
		cleanup()
		return "", nil, fmt.Errorf("close system prompt: %w", closeErr)
	}
	return f.Name(), cleanup, nil
}

func jobTools(job JobEnvelope) ([]tools.Binding, error) {
	return tools.ForJob(job.Tools)
}

func qualifiedToolNames(bindings []tools.Binding) []string {
	out := make([]string, len(bindings))
	for i, b := range bindings {
		out[i] = fmt.Sprintf("mcp__%s__%s", ServerName, b.Name)
	}
	return out
}

// ClaudeInvoker is the existing CLI-backed Runner. OpenAIRunner shares its
// result/error/cost tail through finishRun, but not its subprocess transport.
type ClaudeInvoker struct {
	ClaudeBin    string
	Self         string
	APIBaseURL   string
	APIToken     string
	SystemPrompt string
	MaxBudgetUSD float64
	Metrics      *metrics.Registry
}

type mcpConfig struct {
	MCPServers map[string]mcpServerConfig `json:"mcpServers"`
}

type mcpServerConfig struct {
	Command    string            `json:"command"`
	Args       []string          `json:"args"`
	Env        map[string]string `json:"env"`
	AlwaysLoad bool              `json:"alwaysLoad"`
}

var ErrAgentDidNotCompleteJob = errors.New("agent did not complete job")

func (c *ClaudeInvoker) mcpToken(job JobEnvelope) string {
	if job.JobToken != "" {
		return job.JobToken
	}
	return c.APIToken
}

func (c *ClaudeInvoker) systemPrompt(job JobEnvelope) string {
	if job.Instructions != "" {
		return job.Instructions
	}
	return c.SystemPrompt
}

func (c *ClaudeInvoker) buildMCPConfig(job JobEnvelope) mcpConfig {
	env := map[string]string{
		"AGENT_API_BASE_URL": c.APIBaseURL,
		"AGENT_API_TOKEN":    c.mcpToken(job),
		"AGENT_JOB_ID":       fmt.Sprintf("%d", job.JobID),
		"AGENT_JOB_ATTEMPT":  fmt.Sprintf("%d", job.Attempt),
		"AGENT_JOB_EVENT_ID": job.EventID,
		"AGENT_JOB_CONV_ID":  fmt.Sprintf("%d", job.ConversationID),
	}
	if len(job.SourceEventIDs) > 1 {
		env["AGENT_JOB_SOURCE_EVENT_IDS"] = strings.Join(job.SourceEventIDs, ",")
	}
	if len(job.Tools) > 0 {
		env["AGENT_JOB_TOOLS"] = strings.Join(job.Tools, ",")
	}
	return mcpConfig{MCPServers: map[string]mcpServerConfig{
		ServerName: {
			Command: c.Self, Args: []string{"--mcp-serve"}, AlwaysLoad: true, Env: env,
		},
	}}
}

// Run executes Claude Code and delegates the common post-run accounting,
// result classification and durable terminal-state verification to finishRun.
func (c *ClaudeInvoker) Run(ctx context.Context, job JobEnvelope) error {
	bindings, err := jobTools(job)
	if err != nil {
		return fmt.Errorf("job tools: %w", err)
	}
	cfgPath, cleanup, err := mcpConfigTempFile(c.buildMCPConfig(job))
	if err != nil {
		return fmt.Errorf("write mcp config: %w", err)
	}
	defer cleanup()

	args := []string{
		"-p", jobPrompt(),
		"--mcp-config", cfgPath,
		"--strict-mcp-config",
		"--tools", "",
		"--allowedTools", strings.Join(qualifiedToolNames(bindings), ","),
		"--output-format", "json",
		"--no-session-persistence",
	}
	if prompt := c.systemPrompt(job); prompt != "" {
		promptPath, cleanupPrompt, err := promptTempFile(prompt)
		if err != nil {
			return fmt.Errorf("write system prompt: %w", err)
		}
		defer cleanupPrompt()
		args = append(args, "--system-prompt-file", promptPath)
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
	if runErr := cmd.Run(); runErr != nil {
		// stderr may contain model-derived Telegram content; only expose size.
		return fmt.Errorf("claude -p exited: %w (stderr: %d bytes, see run logs)", runErr, stderr.Len())
	}
	res, parseErr := ParseClaudeResult(stdout.Bytes())
	if parseErr != nil {
		return fmt.Errorf("job %d: %w (stdout: %d bytes, see run logs)", job.JobID, parseErr, stdout.Len())
	}
	client := NewClient(c.APIBaseURL, c.APIToken, nil)
	return finishRun(ctx, client, job, res, c.Metrics)
}

// Keep these methods as compatibility/test seams while the actual logic is
// shared with OpenAIRunner.
func (c *ClaudeInvoker) recordCost(ctx context.Context, client *Client, job JobEnvelope, res *ClaudeResult) {
	recordRunCost(ctx, client, job, res, c.Metrics)
}

func (c *ClaudeInvoker) countResultError(err error) {
	countRunResultError(c.Metrics, err)
}

func jobPrompt() string {
	return "A new Telegram message arrived. Use get_event and get_conversation_context to see it and the conversation so far, decide what to do, and call complete_agent_job exactly once when you are done."
}

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
