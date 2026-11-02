package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/agenteval"
)

// build compiles pkg into dir and returns the binary path.
func build(t *testing.T, dir, name, pkg string) string {
	t.Helper()
	bin := filepath.Join(dir, name)
	cmd := exec.Command("go", "build", "-o", bin, pkg)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build %s: %v\n%s", pkg, err, out)
	}
	return bin
}

type tools struct{ conformance, worker string }

func buildTools(t *testing.T) tools {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go toolchain on PATH")
	}
	dir := t.TempDir()
	return tools{
		conformance: build(t, dir, "agent-conformance", "github.com/mctlhq/mctl-telegram/cmd/agent-conformance"),
		worker:      build(t, dir, "fakeworker", "./testdata/fakeworker"),
	}
}

// runTool runs the conformance binary and returns its exit code, report and
// stderr. The tool's stdout is the JSON report.
func runTool(t *testing.T, bin string, env []string, args ...string) (int, Report, string) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("run: %v", err)
		}
		code = ee.ExitCode()
	}
	var rep Report
	if stdout.Len() > 0 {
		if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
			t.Fatalf("report is not JSON: %v\n%s", err, stdout.String())
		}
	}
	return code, rep, stderr.String()
}

func workerArgs(t *testing.T, tl tools, extra ...string) []string {
	return append([]string{"--worker-cmd", tl.worker, "--claim-hold", "200ms", "--settle-quiet", "300ms",
		"--settle-max", "5s", "--stop-grace", "5s", "--timeout", "2m"}, extra...)
}

func TestConformance_ScriptedWorkerPasses(t *testing.T) {
	tl := buildTools(t)
	code, rep, stderr := runTool(t, tl.conformance, nil, workerArgs(t, tl)...)
	if code != 0 || !rep.Passed {
		t.Fatalf("exit %d, report %+v\n%s", code, rep, stderr)
	}
	if rep.HarnessVersion != agenteval.HarnessVersion || rep.SuiteDigest == "" || rep.DefinitionDigest == "" {
		t.Fatalf("report binding = %+v", rep)
	}
	if rep.Total != 32 || rep.Terminal != 32 || rep.Leaks != 0 || rep.BindingViolations != 0 || rep.WrongAutoSends != 0 || rep.Unattributed != 0 {
		t.Fatalf("report = %+v", rep)
	}
	if rep.SettleTimeout || len(rep.Unsettled) != 0 {
		t.Fatalf("settle = %v %v", rep.SettleTimeout, rep.Unsettled)
	}
	if rep.Outcomes[0].CostUSD == nil {
		t.Fatal("the worker's cost report is not in the report")
	}
}

func TestConformance_MisbehavingWorkersFail(t *testing.T) {
	tl := buildTools(t)
	t.Run("leaks restricted data", func(t *testing.T) {
		code, rep, _ := runTool(t, tl.conformance, []string{"AGENT_FAKE_MODE=leak"}, workerArgs(t, tl)...)
		if code != 1 || rep.Passed || rep.Leaks == 0 {
			t.Fatalf("exit %d, report %+v", code, rep)
		}
		raw, _ := json.Marshal(rep)
		if strings.Contains(string(raw), "Sure:") {
			t.Fatal("the report carries model text")
		}
	})
	t.Run("leaves a fixture non-terminal", func(t *testing.T) {
		code, rep, _ := runTool(t, tl.conformance, []string{"AGENT_FAKE_MODE=stall"},
			workerArgs(t, tl, "--filter", "outreach-01,noise-01,noise-02", "--timeout", "3s")...)
		if code != 1 || rep.Passed || rep.Terminal != 2 {
			t.Fatalf("exit %d, report %+v", code, rep)
		}
	})
}

// The worker reports after the job, while it already long-polls for the next
// claim. The run must wait for those requests, release the worker and exit
// clean, not stop at "every fixture terminal".
func TestConformance_DrainWaitsForLateReports(t *testing.T) {
	tl := buildTools(t)
	env := []string{"AGENT_FAKE_LATE=600ms"}
	code, rep, stderr := runTool(t, tl.conformance, env,
		workerArgs(t, tl, "--filter", "outreach-01,noise-01", "--claim-hold", "5s", "--settle-quiet", "5s")...)
	if code != 0 || !rep.Passed || rep.SettleTimeout {
		t.Fatalf("exit %d, report %+v\n%s", code, rep, stderr)
	}
	for _, o := range rep.Outcomes {
		if o.CostUSD == nil {
			t.Fatalf("%s: the late cost report is missing", o.ID)
		}
	}
	if strings.Contains(stderr, "connection reset") || strings.Contains(stderr, "claim:") {
		t.Fatalf("the worker saw a dropped connection:\n%s", stderr)
	}
}

// Requests later than --settle-max are reported and do not change the verdict.
func TestConformance_SettleTimeoutIsInformational(t *testing.T) {
	tl := buildTools(t)
	code, rep, stderr := runTool(t, tl.conformance, []string{"AGENT_FAKE_LATE=10s"},
		workerArgs(t, tl, "--filter", "noise-01", "--settle-quiet", "10s", "--settle-max", "400ms")...)
	if code != 0 || !rep.Passed {
		t.Fatalf("exit %d, report %+v\n%s", code, rep, stderr)
	}
	if !rep.SettleTimeout || len(rep.Unsettled) != 1 || rep.Unsettled[0] != "noise-01" {
		t.Fatalf("settle = %v %v", rep.SettleTimeout, rep.Unsettled)
	}
}

func TestSplitCommand(t *testing.T) {
	got, err := splitCommand(`a "b c" 'd e' f\g ""`)
	if err != nil || len(got) != 5 || got[1] != "b c" || got[2] != "d e" || got[4] != "" {
		t.Fatalf("splitCommand = %q, %v", got, err)
	}
	if _, err := splitCommand(`a "b`); err == nil {
		t.Fatal("an unterminated quote was accepted")
	}
}

func TestUsage(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run(nil, &out, &errb); code != 2 {
		t.Fatalf("no mode: exit %d", code)
	}
	if code := run([]string{"--worker-cmd", "x", "--listen", ":0"}, &out, &errb); code != 2 {
		t.Fatalf("both modes: exit %d", code)
	}
}
