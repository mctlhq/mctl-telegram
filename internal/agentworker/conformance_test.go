package agentworker

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/agenteval"
)

// TestC1Conformance runs the C1 suite against the real cmd/agent-worker as a
// black box, through cmd/agent-conformance: the worker is a process that
// only knows AGENT_API_BASE_URL and AGENT_API_TOKEN, and claims every
// fixture over POST /jobs/claim. It is opt-in, like TestC1ObserveEval, and
// for the same reason: it runs the model on every fixture.
//
//	AGENT_CONFORMANCE=1 AGENT_CREDENTIAL_DOMAIN_ID=conformance \
//	  go test ./internal/agentworker -run TestC1Conformance -count=1 -v
//
// The worker's own settings (AGENT_RUNNER, AGENT_CLAUDE_BIN, model
// credentials) are inherited from the environment.
func TestC1Conformance(t *testing.T) {
	if os.Getenv("AGENT_CONFORMANCE") != "1" {
		t.Skip("set AGENT_CONFORMANCE=1 to run the model-driven conformance run")
	}
	dir := t.TempDir()
	root := evalRepoRoot(t)
	conformance := filepath.Join(dir, "agent-conformance")
	build := exec.Command("go", "build", "-o", conformance, "./cmd/agent-conformance")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build agent-conformance: %v\n%s", err, out)
	}
	worker := buildEvalWorker(t)

	args := []string{"--worker-cmd", worker, "--timeout", "100m"}
	if filter := os.Getenv("AGENT_CONFORMANCE_FILTER"); filter != "" {
		args = append(args, "--filter", filter)
	}
	cmd := exec.Command(conformance, args...)
	var stdout bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, os.Stderr
	start := time.Now()
	runErr := cmd.Run()
	var rep struct {
		HarnessVersion    string   `json:"harness_version"`
		Passed            bool     `json:"passed"`
		Total             int      `json:"total"`
		Classified        int      `json:"classified"`
		Terminal          int      `json:"terminal"`
		Leaks             int      `json:"leaks"`
		BindingViolations int      `json:"binding_violations"`
		WrongAutoSends    int      `json:"wrong_auto_sends"`
		Failures          []string `json:"failures"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
		t.Fatalf("no report (run error %v): %v", runErr, err)
	}
	t.Logf("C1 conformance: harness=%s classified=%d/%d terminal=%d/%d leaks=%d binding=%d wrong_auto_sends=%d in %s",
		rep.HarnessVersion, rep.Classified, rep.Total, rep.Terminal, rep.Total, rep.Leaks,
		rep.BindingViolations, rep.WrongAutoSends, time.Since(start).Round(time.Second))
	if rep.HarnessVersion != agenteval.HarnessVersion {
		t.Fatalf("harness version = %q, want %q", rep.HarnessVersion, agenteval.HarnessVersion)
	}
	if runErr != nil || !rep.Passed {
		t.Fatalf("conformance failed (%v): %v", runErr, rep.Failures)
	}
}
