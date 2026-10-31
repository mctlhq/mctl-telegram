package agentworker

import (
	"context"
	_ "embed"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	mctltelegram "github.com/mctlhq/mctl-telegram"
	"github.com/mctlhq/mctl-telegram/internal/agenteval"
	"github.com/mctlhq/mctl-telegram/internal/assistant"
)

//go:embed testdata/c1-system-prompt.txt
var c1SystemPrompt string

// This is an opt-in model evaluation, not a normal unit test. It launches the
// real Claude Code CLI and the real agent-worker stdio MCP server once per
// fixture of hr-recruiter@0.1.0's eval suite
// (assistants/hr-recruiter/eval/0.1.0), while internal/agenteval's fake Agent
// API records durable effects and judges every proposed reply with the
// guarded policy as a dry run. Run with:
//
//	AGENT_C1_EVAL=1 go test ./internal/agentworker -run TestC1ObserveEval -count=1 -v
//
// The normal test suite skips it so CI never consumes model quota.
//
// AGENT_C1_EVAL_PROMPT=catalog runs the same fixtures with the prompt the
// server hands out on claim: the hr-recruiter catalog entry rendered with the
// suite's values, delivered as JobEnvelope.Instructions with no fallback
// SystemPrompt. That is the P1 acceptance run for the assistant catalog.
func TestC1ObserveEval(t *testing.T) {
	if os.Getenv("AGENT_C1_EVAL") != "1" {
		t.Skip("set AGENT_C1_EVAL=1 to run the real Claude Code evaluation")
	}
	catalog, err := assistant.LoadCatalog(mctltelegram.Catalog)
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	base, ok := catalog.Lookup("hr-recruiter", "0.1.0")
	if !ok {
		t.Fatal("catalog has no hr-recruiter@0.1.0")
	}
	suite, err := agenteval.LoadSuite(mctltelegram.Catalog, base)
	if err != nil {
		t.Fatalf("load suite: %v", err)
	}
	target, err := agenteval.Prepare(base, base, suite)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	t.Logf("C1: %s@%s digest=%s suite=%s harness=%s", base.Definition.Metadata.Name,
		base.Definition.Metadata.Version, base.Digest, suite.Digest, agenteval.HarnessVersion)

	var only []string
	if filter := strings.TrimSpace(os.Getenv("AGENT_C1_EVAL_FILTER")); filter != "" {
		for _, id := range strings.Split(filter, ",") {
			only = append(only, strings.TrimSpace(id))
		}
	}
	fixtures := make([]agenteval.Fixture, 0, len(suite.Fixtures))
	for _, f := range suite.Fixtures {
		if len(only) == 0 || slices.Contains(only, f.ID) {
			fixtures = append(fixtures, f)
		}
	}
	if len(fixtures) == 0 {
		t.Fatalf("AGENT_C1_EVAL_FILTER=%v matched no fixtures", only)
	}

	workerBin := buildEvalWorker(t)
	systemPrompt, instructions := c1SystemPrompt, ""
	if os.Getenv("AGENT_C1_EVAL_PROMPT") == "catalog" {
		instructions, systemPrompt = target.Instructions, ""
	}
	claudeBin := os.Getenv("AGENT_CLAUDE_BIN")
	if claudeBin == "" {
		claudeBin = "claude"
	}
	if _, err := exec.LookPath(claudeBin); err != nil {
		t.Fatalf("find Claude Code CLI %q: %v", claudeBin, err)
	}

	results := make([]agenteval.FixtureResult, 0, len(fixtures))
	for i, fixture := range fixtures {
		jobID := int64(1000 + i)
		task := agenteval.NewTask(target, fixture, jobID, "c1-eval-token")
		api := httptest.NewServer(task)
		job := JobEnvelope{
			JobID: jobID, EventID: "eval-" + fixture.ID,
			ConversationID: 1, Attempt: 1, Instructions: instructions, Tools: target.JobTools,
			Deadline: time.Now().Add(3 * time.Minute).Format(time.RFC3339),
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		err := (&ClaudeInvoker{
			ClaudeBin: claudeBin, Self: workerBin, APIBaseURL: api.URL,
			APIToken: "c1-eval-token", SystemPrompt: systemPrompt, MaxBudgetUSD: 0.50,
		}).Run(ctx, job)
		cancel()
		api.Close()
		if err != nil {
			t.Logf("%s [%s]: invocation failed: %v", fixture.ID, fixture.Category, err)
		}
		results = append(results, task.Result())
	}

	report := agenteval.Score(suite, target.Adaptation, results, only)
	for _, o := range report.Outcomes {
		f, _ := suite.Fixture(o.ID)
		t.Logf("%s [%s]: action=%s want=%s correct=%t status=%s terminal=%t leaks=%v binding_violation=%t auto_sends=%d wrong_auto_sends=%d expected_decision=%s",
			o.ID, o.Category, o.Action, f.ExpectedAction, o.Correct, o.Status, o.Terminal,
			o.Leaks, o.BindingViolation, len(o.AutoSends), o.WrongAutoSends, f.ExpectedDecision)
		if o.Alerts > 0 || len(o.SummaryIntents) > 0 || len(o.ToolRefused) > 0 {
			t.Logf("%s: manipulation_alerts=%d summary_intents=%v tool_refused=%v", o.ID, o.Alerts, o.SummaryIntents, o.ToolRefused)
		}
	}
	t.Logf("C1 summary: classification=%d/%d terminal=%d/%d leaks=%d binding_violations=%d wrong_auto_sends=%d",
		report.Classified, report.Total, report.Terminal, report.Total, report.Leaks,
		report.BindingViolations, report.WrongAutoSends)
	for _, failure := range report.Failures {
		t.Error(failure)
	}
}

func buildEvalWorker(t *testing.T) string {
	t.Helper()
	if bin := os.Getenv("AGENT_EVAL_WORKER_BIN"); bin != "" {
		if _, err := os.Stat(bin); err != nil {
			t.Fatalf("AGENT_EVAL_WORKER_BIN %q: %v", bin, err)
		}
		return bin
	}
	bin := filepath.Join(t.TempDir(), "agent-worker")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/agent-worker")
	cmd.Dir = evalRepoRoot(t)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build eval worker: %v\n%s", err, out)
	}
	return bin
}

func evalRepoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve eval source path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}
