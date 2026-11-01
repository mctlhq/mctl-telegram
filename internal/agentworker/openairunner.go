package agentworker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	mcplib "github.com/mark3labs/mcp-go/mcp"

	"github.com/mctlhq/mctl-telegram/internal/metrics"
)

var errNoJobToken = errors.New("job has no job token")

const canceledCostReportTimeout = 2 * time.Second

type OpenAIRunner struct {
	Client     *OpenAIClient
	APIBaseURL string
	// APIToken is the worker's account token. It is used ONLY for the
	// worker-side calls that must outlive the job token (cost report and
	// terminal-state verification), exactly as ClaudeInvoker does. The job
	// token expires at the claim deadline, which is also when a deadline
	// cancellation fires, so a /cost write sent with it would be rejected
	// with 401 and the spend silently dropped. Every model-reachable tool
	// call keeps using the job token, and the model never sees either token
	// in this runner. Empty falls back to the job token (older callers).
	APIToken     string
	SystemPrompt string // fallback, as in ClaudeInvoker
	MaxTurns     int    // AGENT_MAX_TURNS, default 12
	MaxBudgetUSD float64
	Prices       Prices // input/output USD per MTok
	MinInterval  time.Duration
	Metrics      *metrics.Registry

	rateMu      sync.Mutex
	nextRequest time.Time
}

func (r *OpenAIRunner) Run(ctx context.Context, job JobEnvelope) error {
	if job.JobToken == "" {
		return errNoJobToken
	}
	if r.Client == nil {
		return errors.New("openai client is required")
	}
	api := NewClient(r.APIBaseURL, job.JobToken, nil)
	workerAPI := api
	if r.APIToken != "" {
		workerAPI = NewClient(r.APIBaseURL, r.APIToken, nil)
	}
	builder, defs, err := buildToolSet(api, JobContext{
		JobID: job.JobID, Attempt: job.Attempt, EventID: job.EventID,
		ConversationID: job.ConversationID, SourceEventIDs: job.SourceEventIDs, Tools: job.Tools,
	})
	if err != nil {
		return fmt.Errorf("build tool set: %w", err)
	}

	msgs := make([]ChatMessage, 0, 16)
	prompt := job.Instructions
	if prompt == "" {
		prompt = r.SystemPrompt
	}
	if prompt != "" {
		msgs = append(msgs, ChatMessage{Role: "system", Content: prompt})
	}
	msgs = append(msgs, ChatMessage{Role: "user", Content: jobPrompt()})

	maxTurns := r.MaxTurns
	if maxTurns <= 0 {
		maxTurns = 12
	}
	started := time.Now()
	totalCost := 0.0
	costObserved := false
	usageMissing := false
	turns := 0

	result := func(subtype string, isError bool) *ClaudeResult {
		res := &ClaudeResult{Type: "result", Subtype: subtype, IsError: isError, NumTurns: turns,
			DurationMS: time.Since(started).Milliseconds()}
		if costObserved {
			if usageMissing {
				// Reported cost is a lower bound: some turns carried no usage.
				slog.Warn("agent-worker: reporting partial job cost (lower bound); some turns carried no provider usage", "job_id", job.JobID)
			}
			cost := totalCost
			res.TotalCostUSD = &cost
		}
		return res
	}
	finish := func(subtype string, isError bool) error {
		return finishRun(ctx, workerAPI, job, result(subtype, isError), r.Metrics)
	}
	reportCanceledCost := func() {
		if !costObserved {
			return
		}
		// The job context is already canceled, but the provider usage for
		// completed turns is still real spend. Give the best-effort /cost
		// write a small independent bound instead of dropping it solely
		// because the job deadline fired between turns.
		reportCtx, cancel := context.WithTimeout(context.Background(), canceledCostReportTimeout)
		defer cancel()
		recordRunCost(reportCtx, workerAPI, job, result("error_context_canceled", true), r.Metrics)
	}

	for turns < maxTurns {
		turns++
		out, err := r.chatWithRetry(ctx, msgs, defs)
		if err != nil {
			if ctx.Err() != nil {
				reportCanceledCost()
				return ctx.Err()
			}
			var pe *ProviderError
			if errors.As(err, &pe) && pe.Status == 429 {
				return finish("error_provider_429", true)
			}
			return finish("error_provider", true)
		}
		if !out.UsageReported {
			// Unknown spend is not zero spend. With a budget configured, a
			// provider that omits usage would bypass AGENT_MAX_BUDGET_USD on
			// every turn, so fail closed; without one there is nothing to
			// bypass, so warn and keep the cost unreported rather than
			// recording a fabricated $0.
			if r.MaxBudgetUSD > 0 {
				return finish("error_provider_no_usage", true)
			}
			usageMissing = true
			slog.Warn("agent-worker: provider response carried no usage; cost not recorded for this turn", "job_id", job.JobID)
		} else {
			costObserved = true
			totalCost += r.Prices.Cost(out.Usage)
		}
		if r.MaxBudgetUSD > 0 && totalCost > r.MaxBudgetUSD {
			return finish("error_max_budget", true)
		}

		msgs = append(msgs, out.Message)
		if len(out.Message.ToolCalls) == 0 {
			return finish("success", false)
		}
		for _, call := range out.Message.ToolCalls {
			content := executeToolCall(ctx, defs, call)
			msgs = append(msgs, ChatMessage{Role: "tool", ToolCallID: call.ID, Content: content})
			if builder.Completed() {
				return finish("success", false)
			}
		}
	}
	return finish("error_max_turns", true)
}

func (r *OpenAIRunner) chatWithRetry(ctx context.Context, msgs []ChatMessage, defs []toolDef) (*ChatResult, error) {
	var last error
	backoff := time.Second
	for attempt := 0; attempt < 4; attempt++ {
		if err := r.waitForTurn(ctx); err != nil {
			return nil, err
		}
		out, err := r.Client.Chat(ctx, msgs, defs)
		if err == nil {
			return out, nil
		}
		last = err
		var pe *ProviderError
		if !errors.As(err, &pe) || (pe.Status != 429 && (pe.Status < 500 || pe.Status > 599)) {
			return nil, err
		}
		if attempt == 3 {
			break
		}
		wait := pe.RetryAfter
		if wait <= 0 {
			wait = backoff
			if backoff < 8*time.Second {
				backoff *= 2
			}
		}
		if deadline, ok := ctx.Deadline(); ok {
			remaining := time.Until(deadline)
			if remaining <= 0 || wait >= remaining {
				// Do not turn a known provider refusal into an opaque context
				// deadline by sleeping through the rest of the job window.
				// Returning the ProviderError keeps 429 classification intact.
				return nil, last
			}
		}
		if err := waitContext(ctx, wait); err != nil {
			return nil, err
		}
	}
	return nil, last
}

// waitForTurn is the process-wide provider pacing guard. State lives on the
// one OpenAIRunner instance instead of in package globals, which keeps tests
// isolated while still serialising requests from concurrent jobs in prod.
func (r *OpenAIRunner) waitForTurn(ctx context.Context) error {
	if r.MinInterval <= 0 {
		return nil
	}
	// Reserve a slot under the lock, then sleep outside it: a waiter whose
	// deadline passed or whose worker is shutting down leaves through its own
	// context instead of queueing behind every sleeper ahead of it. A
	// cancelled waiter's slot stays consumed, which only spaces later
	// requests further apart (the safe direction for a provider limit).
	r.rateMu.Lock()
	slot := time.Now()
	if r.nextRequest.After(slot) {
		slot = r.nextRequest
	}
	r.nextRequest = slot.Add(r.MinInterval)
	r.rateMu.Unlock()
	return waitContext(ctx, time.Until(slot))
}

func waitContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func executeToolCall(ctx context.Context, defs []toolDef, call ToolCall) string {
	var def *toolDef
	for i := range defs {
		if defs[i].Tool.Name == call.Name {
			def = &defs[i]
			break
		}
	}
	if def == nil {
		return `{"error":"unknown tool"}`
	}
	args := map[string]any{}
	if strings.TrimSpace(call.Arguments) != "" {
		if err := json.Unmarshal([]byte(call.Arguments), &args); err != nil {
			return `{"error":"invalid tool arguments"}`
		}
	}
	res, err := def.Handler(ctx, mcplib.CallToolRequest{Params: mcplib.CallToolParams{Name: call.Name, Arguments: args}})
	if err != nil {
		return `{"error":"tool execution failed"}`
	}
	return toolResultText(res)
}

func toolResultText(res *mcplib.CallToolResult) string {
	if res == nil {
		return `{"error":"empty tool result"}`
	}
	var parts []string
	for _, c := range res.Content {
		if tc, ok := mcplib.AsTextContent(c); ok {
			parts = append(parts, tc.Text)
		}
	}
	if len(parts) > 0 {
		return strings.Join(parts, "\n")
	}
	if res.StructuredContent != nil {
		if b, err := json.Marshal(res.StructuredContent); err == nil {
			return string(b)
		}
	}
	if res.IsError {
		return `{"error":"tool refused"}`
	}
	return `{}`
}
