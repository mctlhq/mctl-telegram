// Command agent-conformance runs the C1 conformance suite against a worker
// it does not link: the worker is a process that speaks the agent job API
// (docs/contracts/agent-job-api.md), and this tool is the API's other side.
//
// It serves a fake agent API on loopback (or on --listen), hands the suite's
// fixtures to the worker one job per claim, and scores what the worker did
// with the existing agenteval gates: classification at the suite's
// threshold, every fixture terminal, and no leak, binding violation or
// wrong auto-send. It adds no check of its own.
//
// The token it issues stands for the account-scoped aud=agent token and the
// job token in each claim stands for aud=agent-job; both exist only inside
// the fake and mean nothing to a real server.
//
//	agent-conformance --worker-cmd "./agent-worker"
//	agent-conformance --listen :8099      # start the worker yourself
//
// The run is a drain, not a kill: after the last fixture is terminal the
// tool waits for the worker's status reads and cost reports, releases a
// long-polling worker, stops it, and shuts the server down gracefully
// before it computes the report. The report is JSON bound to
// agenteval.HarnessVersion, the suite digest and the definition digest. It
// holds no model text. Exit status: 0 pass, 1 fail, 2 usage or setup error.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	mctltelegram "github.com/mctlhq/mctl-telegram"
	"github.com/mctlhq/mctl-telegram/internal/agenteval"
	"github.com/mctlhq/mctl-telegram/internal/assistant"
)

// apiPrefix is where the fake serves the agent API, as the real server does.
const apiPrefix = "/api/agent/v1"

type config struct {
	suite       string
	workerCmd   string
	listen      string
	timeout     time.Duration
	filter      []string
	reportPath  string
	settleQuiet time.Duration
	settleMax   time.Duration
	stopGrace   time.Duration
	claimHold   time.Duration
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func run(args []string, stdout, stderr io.Writer) int {
	var cfg config
	var filter string
	fs := flag.NewFlagSet("agent-conformance", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&cfg.suite, "suite", "hr-recruiter@0.1.0", "suite to run, name@version of a catalog assistant")
	fs.StringVar(&cfg.workerCmd, "worker-cmd", os.Getenv("AGENT_CONFORMANCE_WORKER_CMD"),
		"worker command to run; gets AGENT_API_BASE_URL and AGENT_API_TOKEN")
	fs.StringVar(&cfg.listen, "listen", os.Getenv("AGENT_CONFORMANCE_LISTEN"),
		"serve the fake API on this address for a worker you start yourself")
	fs.DurationVar(&cfg.timeout, "timeout", durationEnv("AGENT_CONFORMANCE_TIMEOUT"), "overall run limit (default: 3 minutes per fixture)")
	fs.StringVar(&filter, "filter", "", "comma-separated fixture ids; a diagnosis run, every one must classify")
	fs.StringVar(&cfg.reportPath, "report", "", "write the JSON report here instead of stdout")
	fs.DurationVar(&cfg.settleQuiet, "settle-quiet", 2*time.Second, "a finished fixture is settled after this long without a request")
	fs.DurationVar(&cfg.settleMax, "settle-max", 30*time.Second, "longest wait for post-terminal status reads and cost reports")
	fs.DurationVar(&cfg.stopGrace, "stop-grace", 10*time.Second, "grace for the worker to stop and for in-flight requests to finish")
	fs.DurationVar(&cfg.claimHold, "claim-hold", time.Second, "how long a claim of an empty queue is held")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	for _, id := range strings.Split(filter, ",") {
		if id = strings.TrimSpace(id); id != "" {
			cfg.filter = append(cfg.filter, id)
		}
	}
	if (cfg.workerCmd == "") == (cfg.listen == "") {
		fmt.Fprintln(stderr, "agent-conformance: give exactly one of --worker-cmd and --listen")
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	rep, err := execute(ctx, cfg, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "agent-conformance:", err)
		return 2
	}
	out, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		fmt.Fprintln(stderr, "agent-conformance:", err)
		return 2
	}
	out = append(out, '\n')
	if cfg.reportPath != "" {
		if err := os.WriteFile(cfg.reportPath, out, 0o600); err != nil {
			fmt.Fprintln(stderr, "agent-conformance:", err)
			return 2
		}
	} else {
		_, _ = stdout.Write(out)
	}
	for _, f := range rep.Failures {
		fmt.Fprintln(stderr, "FAIL:", f)
	}
	if rep.Passed {
		fmt.Fprintln(stderr, "PASS")
		return 0
	}
	return 1
}

func durationEnv(key string) time.Duration {
	d, _ := time.ParseDuration(os.Getenv(key))
	return d
}

// Report is the JSON the tool prints: the scored run bound to the harness
// version, the suite and the definition. It holds no model text.
type Report struct {
	HarnessVersion    string `json:"harness_version"`
	Suite             string `json:"suite"`
	SuiteDigest       string `json:"suite_digest"`
	DefinitionDigest  string `json:"definition_digest"`
	Passed            bool   `json:"passed"`
	Full              bool   `json:"full"`
	Total             int    `json:"total"`
	MinClassification int    `json:"min_classification"`
	Classified        int    `json:"classified"`
	Terminal          int    `json:"terminal"`
	Leaks             int    `json:"leaks"`
	BindingViolations int    `json:"binding_violations"`
	WrongAutoSends    int    `json:"wrong_auto_sends"`
	// Unattributed counts requests that named no single fixture and were
	// refused with 409. Each is a binding violation and fails the run.
	Unattributed int      `json:"unattributed_requests"`
	Missing      []string `json:"missing,omitempty"`
	Unexpected   []string `json:"unexpected,omitempty"`
	Failures     []string `json:"failures,omitempty"`
	// SettleTimeout is true when the post-terminal requests had not all
	// arrived by --settle-max. It is informational: it does not change
	// Passed.
	SettleTimeout bool      `json:"settle_timeout"`
	Unsettled     []string  `json:"unsettled,omitempty"`
	WorkerExit    string    `json:"worker_exit,omitempty"`
	Outcomes      []Outcome `json:"outcomes"`
}

// Outcome is one fixture's scored result. Leaks name a field and a marker;
// no text the worker or model produced is kept.
type Outcome struct {
	ID               string   `json:"id"`
	Category         string   `json:"category"`
	Action           string   `json:"action"`
	Status           string   `json:"status"`
	Terminal         bool     `json:"terminal"`
	Correct          bool     `json:"correct"`
	LeadFieldsOK     bool     `json:"lead_fields_ok"`
	Leaks            []string `json:"leaks,omitempty"`
	BindingViolation bool     `json:"binding_violation"`
	ToolRefused      []string `json:"tool_refused,omitempty"`
	WrongAutoSends   int      `json:"wrong_auto_sends"`
	Alerts           int      `json:"alerts,omitempty"`
	CostUSD          *float64 `json:"cost_usd,omitempty"`
}

func prepare(cfg config) (*agenteval.Target, []agenteval.Fixture, error) {
	name, version, ok := strings.Cut(cfg.suite, "@")
	if !ok || name == "" || version == "" {
		return nil, nil, fmt.Errorf("--suite %q: want name@version", cfg.suite)
	}
	catalog, err := assistant.LoadCatalog(mctltelegram.Catalog)
	if err != nil {
		return nil, nil, fmt.Errorf("load catalog: %w", err)
	}
	base, found := catalog.Lookup(name, version)
	if !found {
		return nil, nil, fmt.Errorf("catalog has no %s@%s", name, version)
	}
	suite, err := agenteval.LoadSuite(mctltelegram.Catalog, base)
	if err != nil {
		return nil, nil, fmt.Errorf("load suite: %w", err)
	}
	target, err := agenteval.Prepare(base, base, suite)
	if err != nil {
		return nil, nil, fmt.Errorf("prepare: %w", err)
	}
	var fixtures []agenteval.Fixture
	for _, id := range cfg.filter {
		if _, ok := suite.Fixture(id); !ok {
			return nil, nil, fmt.Errorf("--filter: suite has no fixture %q", id)
		}
	}
	for _, f := range suite.Fixtures {
		if len(cfg.filter) == 0 || slices.Contains(cfg.filter, f.ID) {
			fixtures = append(fixtures, f)
		}
	}
	return target, fixtures, nil
}

// execute runs the suite and returns the scored report. Its states are
// Running, Settling, Draining and Scored; the report is computed only after
// the worker and the server have stopped.
func execute(ctx context.Context, cfg config, stderr io.Writer) (*Report, error) {
	target, fixtures, err := prepare(cfg)
	if err != nil {
		return nil, err
	}
	timeout := cfg.timeout
	if timeout <= 0 {
		timeout = time.Duration(len(fixtures)) * 3 * time.Minute
	}

	addr := cfg.listen
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}
	token := agenteval.NewHarnessToken()
	conf := agenteval.NewConformance(target, fixtures, token, cfg.claimHold)
	srv := &http.Server{Handler: http.StripPrefix(apiPrefix, conf), ReadHeaderTimeout: 10 * time.Second}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()
	baseURL := "http://" + ln.Addr().String() + apiPrefix

	var worker *exec.Cmd
	workerDone := make(chan error, 1)
	if cfg.workerCmd != "" {
		argv, err := splitCommand(cfg.workerCmd)
		if err != nil {
			_ = srv.Close()
			return nil, err
		}
		worker = exec.Command(argv[0], argv[1:]...)
		worker.Env = append(os.Environ(), "AGENT_API_BASE_URL="+baseURL, "AGENT_API_TOKEN="+token)
		worker.Stdout, worker.Stderr = stderr, stderr
		if err := worker.Start(); err != nil {
			_ = srv.Close()
			return nil, fmt.Errorf("start worker: %w", err)
		}
		go func() { workerDone <- worker.Wait() }()
	} else {
		fmt.Fprintf(stderr, "AGENT_API_BASE_URL=%s\nAGENT_API_TOKEN=%s\n", baseURL, token)
		fmt.Fprintf(stderr, "waiting for %d fixtures; start the worker with these two variables\n", len(fixtures))
	}

	// Running.
	var workerExit string
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	poll := time.NewTicker(20 * time.Millisecond)
	defer poll.Stop()
running:
	for !conf.Finished() {
		select {
		case <-ctx.Done():
			fmt.Fprintln(stderr, "interrupted")
			break running
		case <-deadline.C:
			fmt.Fprintln(stderr, "timeout")
			break running
		case err := <-serveErr:
			return nil, fmt.Errorf("serve: %w", err)
		case err := <-workerDone:
			workerExit = exitText(err)
			workerDone <- err // still to be reaped when the worker is stopped
			break running
		case <-poll.C:
		}
	}

	// Settling: the post-terminal status reads and cost reports still to come.
	settleCtx, cancelSettle := context.WithTimeout(context.Background(), cfg.settleMax+time.Second)
	timedOut, unsettled := conf.Settle(settleCtx, cfg.settleQuiet, cfg.settleMax)
	cancelSettle()

	// Draining: release a long-poll, stop the worker, let in-flight
	// requests finish.
	conf.Drain()
	if worker != nil {
		workerExit = stopWorker(worker, workerDone, cfg.stopGrace, workerExit)
	}
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), cfg.stopGrace)
	if err := srv.Shutdown(shutdownCtx); err != nil {
		_ = srv.Close()
		fmt.Fprintln(stderr, "server shutdown:", err)
	}
	cancelShutdown()
	if err := <-serveErr; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return nil, fmt.Errorf("serve: %w", err)
	}

	// Scored.
	score := agenteval.Score(target.Suite, target.Adaptation, conf.Results(), cfg.filter)
	rep := &Report{
		HarnessVersion:    agenteval.HarnessVersion,
		Suite:             cfg.suite,
		SuiteDigest:       target.Suite.Digest,
		DefinitionDigest:  target.Entry.Digest,
		Full:              score.Full,
		Total:             score.Total,
		MinClassification: score.MinClassification,
		Classified:        score.Classified,
		Terminal:          score.Terminal,
		Leaks:             score.Leaks,
		BindingViolations: score.BindingViolations,
		WrongAutoSends:    score.WrongAutoSends,
		Unattributed:      conf.Unattributed(),
		Missing:           score.Missing,
		Unexpected:        score.Unexpected,
		Failures:          score.Failures,
		SettleTimeout:     timedOut,
		Unsettled:         unsettled,
		WorkerExit:        workerExit,
		Outcomes:          []Outcome{},
	}
	if rep.Unattributed > 0 {
		rep.Failures = append(rep.Failures, fmt.Sprintf("requests that named no single job = %d, want 0", rep.Unattributed))
	}
	rep.Passed = score.Passed && rep.Unattributed == 0
	for _, o := range score.Outcomes {
		rep.Outcomes = append(rep.Outcomes, Outcome{
			ID: o.ID, Category: o.Category, Action: o.Action, Status: o.Status, Terminal: o.Terminal,
			Correct: o.Correct, LeadFieldsOK: o.LeadFieldsOK, Leaks: o.Leaks, BindingViolation: o.BindingViolation,
			ToolRefused: o.ToolRefused, WrongAutoSends: o.WrongAutoSends, Alerts: o.Alerts, CostUSD: o.CostUSD,
		})
	}
	return rep, nil
}

func exitText(err error) string {
	if err == nil {
		return "exit 0"
	}
	return err.Error()
}

// stopWorker asks the worker to stop with SIGTERM and kills it after grace.
// It returns the exit text, keeping an earlier one if the worker had
// already exited.
func stopWorker(cmd *exec.Cmd, done chan error, grace time.Duration, earlier string) string {
	timer := time.NewTimer(grace)
	defer timer.Stop()
	_ = cmd.Process.Signal(syscall.SIGTERM)
	select {
	case err := <-done:
		if earlier != "" {
			return earlier
		}
		return exitText(err)
	case <-timer.C:
		_ = cmd.Process.Kill()
		<-done
		return "killed after the stop grace"
	}
}

// splitCommand splits a command line into words, honouring single and
// double quotes. It runs no shell.
func splitCommand(s string) ([]string, error) {
	var words []string
	var cur strings.Builder
	var quote rune
	started := false
	for _, r := range s {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote, started = r, true
		case r == ' ' || r == '\t':
			if started || cur.Len() > 0 {
				words = append(words, cur.String())
				cur.Reset()
				started = false
			}
		default:
			cur.WriteRune(r)
		}
	}
	if quote != 0 {
		return nil, fmt.Errorf("--worker-cmd: unterminated quote")
	}
	if started || cur.Len() > 0 {
		words = append(words, cur.String())
	}
	if len(words) == 0 {
		return nil, fmt.Errorf("--worker-cmd is empty")
	}
	return words, nil
}
