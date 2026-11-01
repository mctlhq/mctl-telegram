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
	"strconv"
	"strings"
	"testing"
	"time"

	mctltelegram "github.com/mctlhq/mctl-telegram"
	"github.com/mctlhq/mctl-telegram/internal/agenteval"
	"github.com/mctlhq/mctl-telegram/internal/assistant"
)

//go:embed testdata/c1-system-prompt.txt
var c1SystemPrompt string

// This is an opt-in model evaluation, not a normal unit test. By default it
// exercises Claude Code as before. Set AGENT_C1_EVAL_RUNNER=openai to run the
// exact same fixtures through OpenAIRunner and its shared in-process tool set.
// The normal test suite skips it so CI never consumes model quota.
func TestC1ObserveEval(t *testing.T) {
	if os.Getenv("AGENT_C1_EVAL") != "1" {
		t.Skip("set AGENT_C1_EVAL=1 to run the real model evaluation")
	}
	catalog, err := assistant.LoadCatalog(mctltelegram.Catalog)
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	version := os.Getenv("AGENT_C1_EVAL_VERSION")
	if version == "" {
		version = "0.1.0"
	}
	base, ok := catalog.Lookup("hr-recruiter", version)
	if !ok {
		t.Fatalf("catalog has no hr-recruiter@%s", version)
	}
	suite, err := agenteval.LoadSuite(mctltelegram.Catalog, base)
	if err != nil {
		t.Fatalf("load suite: %v", err)
	}
	target, err := agenteval.Prepare(base, base, suite)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	runnerName := strings.ToLower(strings.TrimSpace(os.Getenv("AGENT_C1_EVAL_RUNNER")))
	if runnerName == "" {
		runnerName = "claude"
	}
	t.Logf("C1: runner=%s %s@%s digest=%s suite=%s harness=%s", runnerName,
		base.Definition.Metadata.Name, base.Definition.Metadata.Version, base.Digest, suite.Digest, agenteval.HarnessVersion)

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

	systemPrompt, instructions := c1SystemPrompt, ""
	if os.Getenv("AGENT_C1_EVAL_PROMPT") == "catalog" {
		instructions, systemPrompt = target.Instructions, ""
	}

	var claude *ClaudeInvoker
	var openai *OpenAIRunner
	switch runnerName {
	case "claude":
		workerBin := buildEvalWorker(t)
		claudeBin := os.Getenv("AGENT_CLAUDE_BIN")
		if claudeBin == "" {
			claudeBin = "claude"
		}
		if _, err := exec.LookPath(claudeBin); err != nil {
			t.Fatalf("find Claude Code CLI %q: %v", claudeBin, err)
		}
		claude = &ClaudeInvoker{ClaudeBin: claudeBin, Self: workerBin, APIToken: "c1-eval-token", SystemPrompt: systemPrompt, MaxBudgetUSD: 0.50}
	case "openai":
		baseURL := evalRequiredEnv(t, "AGENT_OPENAI_BASE_URL")
		apiKey := evalRequiredEnv(t, "AGENT_OPENAI_API_KEY")
		model := evalRequiredEnv(t, "AGENT_MODEL")
		inputPrice := evalFloat(t, "MODEL_INPUT_USD_PER_MTOK")
		outputPrice := evalFloat(t, "MODEL_OUTPUT_USD_PER_MTOK")
		minInterval := time.Duration(0)
		if raw := strings.TrimSpace(os.Getenv("AGENT_OPENAI_MIN_INTERVAL")); raw != "" {
			minInterval, err = time.ParseDuration(raw)
			if err != nil || minInterval < 0 {
				t.Fatalf("AGENT_OPENAI_MIN_INTERVAL=%q: want non-negative duration", raw)
			}
		}
		openai = &OpenAIRunner{
			Client: &OpenAIClient{
				BaseURL: baseURL, APIKey: apiKey, GatewayToken: os.Getenv("AGENT_GATEWAY_TOKEN"), Model: model,
			},
			SystemPrompt: systemPrompt, MaxTurns: 12, MaxBudgetUSD: 0.50,
			Prices: Prices{InputUSDPerMTok: inputPrice, OutputUSDPerMTok: outputPrice}, MinInterval: minInterval,
		}
	default:
		t.Fatalf("AGENT_C1_EVAL_RUNNER=%q: want claude or openai", runnerName)
	}

	results := make([]agenteval.FixtureResult, 0, len(fixtures))
	for i, fixture := range fixtures {
		jobID := int64(1000 + i)
		task := agenteval.NewTask(target, fixture, jobID, "c1-eval-token")
		api := httptest.NewServer(task)
		job := JobEnvelope{
			JobID: jobID, EventID: "eval-" + fixture.ID,
			ConversationID: 1, Attempt: 1, Instructions: instructions, Tools: target.JobTools,
			JobToken: "c1-eval-token", Deadline: time.Now().Add(3 * time.Minute).Format(time.RFC3339),
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		var runErr error
		if claude != nil {
			claude.APIBaseURL = api.URL
			runErr = claude.Run(ctx, job)
		} else {
			openai.APIBaseURL = api.URL
			runErr = openai.Run(ctx, job)
		}
		cancel()
		api.Close()
		if runErr != nil {
			t.Logf("%s [%s]: invocation failed: %v", fixture.ID, fixture.Category, runErr)
		}
		results = append(results, task.Result())
	}

	report := agenteval.Score(suite, target.Adaptation, results, only)
	var cost float64
	reported := 0
	for _, r := range results {
		if r.CostUSD != nil {
			cost += *r.CostUSD
			reported++
		}
	}
	t.Logf("C1 cost: $%.4f reported by %d/%d invocations", cost, reported, len(results))
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

func evalRequiredEnv(t *testing.T, key string) string {
	t.Helper()
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		t.Fatalf("%s is required for AGENT_C1_EVAL_RUNNER=openai", key)
	}
	return v
}

func evalFloat(t *testing.T, key string) float64 {
	t.Helper()
	raw := evalRequiredEnv(t, key)
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil || v < 0 {
		t.Fatalf("%s=%q: want non-negative number", key, raw)
	}
	return v
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
