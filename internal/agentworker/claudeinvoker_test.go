package agentworker

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/mctlhq/mctl-telegram/internal/metrics"
)

func jobStatusServer(t *testing.T, jobID int64, status string, attempt int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/jobs/42" {
			t.Fatalf("completion check = %s %s, want GET /jobs/42", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer super-secret-token" {
			t.Fatalf("completion check Authorization = %q", got)
		}
		writeJSONFixture(w, JobStatus{JobID: jobID, Status: status, Attempt: attempt})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// fakeClaudeScript writes a shell script standing in for the real `claude`
// binary: it dumps its argv to argvFile (one arg per line, so the test can
// assert on exact flags/values), and — because Run deletes the file it
// passes via --mcp-config as soon as it returns — captures that file's
// content into mcpConfigCopy and its permission bits into mcpConfigPerm
// before the script exits, so the test can inspect both after the fact. GNU
// stat (Linux CI) and BSD stat (local macOS dev) use different flags, hence
// trying both.
func fakeClaudeScript(t *testing.T, stdout string, exitCode int) (bin, argvFile, mcpConfigCopy, mcpConfigPerm string) {
	t.Helper()
	dir := t.TempDir()
	bin = filepath.Join(dir, "fake-claude.sh")
	argvFile = filepath.Join(dir, "argv.txt")
	mcpConfigCopy = filepath.Join(dir, "mcp-config-copy.json")
	mcpConfigPerm = filepath.Join(dir, "mcp-config-perm.txt")
	script := "#!/bin/sh\n" +
		"prev=\"\"\n" +
		"for a in \"$@\"; do\n" +
		"  printf '%s\\n' \"$a\" >> " + argvFile + "\n" +
		"  if [ \"$prev\" = \"--mcp-config\" ]; then\n" +
		"    cp \"$a\" " + mcpConfigCopy + "\n" +
		"    (stat -c %a \"$a\" 2>/dev/null || stat -f %Lp \"$a\") > " + mcpConfigPerm + "\n" +
		"  fi\n" +
		"  prev=\"$a\"\n" +
		"done\n" +
		"cat <<'STDOUT_EOF'\n" + stdout + "\nSTDOUT_EOF\n" +
		"exit " + strconv.Itoa(exitCode) + "\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake claude script: %v", err)
	}
	return bin, argvFile, mcpConfigCopy, mcpConfigPerm
}

func readArgv(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read argv file: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	return lines
}

func TestClaudeInvoker_Run_BuildsExpectedInvocation(t *testing.T) {
	stdout := `{"type":"result","subtype":"success","is_error":false,"num_turns":2,"result":"handled it"}`
	bin, argvFile, mcpConfigCopy, mcpConfigPerm := fakeClaudeScript(t, stdout, 0)
	statusSrv := jobStatusServer(t, 42, "completed", 1)

	inv := &ClaudeInvoker{
		ClaudeBin:  bin,
		Self:       "/usr/local/bin/agent-worker",
		APIBaseURL: statusSrv.URL,
		APIToken:   "super-secret-token",
	}
	job := JobEnvelope{JobID: 42, EventID: "evt:v1:1:2:3", ConversationID: 9, Attempt: 1}

	if err := inv.Run(context.Background(), job); err != nil {
		t.Fatalf("Run: %v", err)
	}

	argv := readArgv(t, argvFile)
	joined := strings.Join(argv, "\x00")
	for _, want := range []string{"-p", "--strict-mcp-config", "--allowedTools", "--output-format", "json", "--mcp-config", "--tools", "--no-session-persistence"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("argv missing %q: %v", want, argv)
		}
	}
	// The prompt must never name this job's event — job.EventID encodes the
	// account/chat/message Telegram IDs (evt:v1:<acct>:<chat>:<msgid>), and
	// -p places the prompt directly in argv, which /proc/<pid>/cmdline and
	// `ps auxww` can read. The model gets the same information through
	// get_event's own (env-pinned, not argv) job identity instead.
	if strings.Contains(joined, job.EventID) {
		t.Fatalf("job event ID leaked into argv: %v", argv)
	}
	if !strings.Contains(joined, "mcp__"+ServerName+"__complete_agent_job") {
		t.Fatalf("allowedTools missing complete_agent_job: %v", argv)
	}
	// --tools must be the empty string (disable every built-in tool) — not
	// just present. --allowedTools alone only grants permission for the
	// listed tools, it does not remove Claude's built-in ones from the
	// available set.
	for i, a := range argv {
		if a == "--tools" {
			if i+1 >= len(argv) || argv[i+1] != "" {
				t.Fatalf("--tools value = %q, want empty string (disable all built-ins)", argvOrEmpty(argv, i+1))
			}
		}
	}
	// The API token must never appear in argv at all (it's only readable
	// from --mcp-config's value) — /proc/<pid>/cmdline and `ps auxww` are
	// visible to every process on the host.
	if strings.Contains(joined, "super-secret-token") {
		t.Fatal("API token leaked into argv")
	}
	// The mcp-config arg is now a FILE PATH, not inline JSON (moving the
	// token out of argv). Run deletes the original as soon as it returns, so
	// fakeClaudeScript captured its content and permission bits into copies
	// before that — confirm job identity, the API token, and 0600
	// permissions all made it through.
	hasCfgFlag := false
	for _, a := range argv {
		if a == "--mcp-config" {
			hasCfgFlag = true
		}
	}
	if !hasCfgFlag {
		t.Fatal("did not find --mcp-config flag in argv")
	}
	permBytes, err := os.ReadFile(mcpConfigPerm)
	if err != nil {
		t.Fatalf("read mcp-config perm file: %v", err)
	}
	if perm := strings.TrimSpace(string(permBytes)); perm != "600" {
		t.Fatalf("mcp-config file mode = %q, want 600", perm)
	}
	cfgBytes, err := os.ReadFile(mcpConfigCopy)
	if err != nil {
		t.Fatalf("read mcp-config copy: %v", err)
	}
	var cfg mcpConfig
	if err := json.Unmarshal(cfgBytes, &cfg); err != nil {
		t.Fatalf("mcp-config file is not valid JSON: %v (%s)", err, cfgBytes)
	}
	serverCfg, ok := cfg.MCPServers[ServerName]
	if !ok {
		t.Fatalf("mcp-config missing %q server: %#v", ServerName, cfg)
	}
	if serverCfg.Env["AGENT_JOB_ID"] != "42" || serverCfg.Env["AGENT_JOB_ATTEMPT"] != "1" {
		t.Fatalf("job identity not passed through: %#v", serverCfg.Env)
	}
	if serverCfg.Env["AGENT_API_TOKEN"] != "super-secret-token" {
		t.Fatalf("api token not passed to mcp server env: %#v", serverCfg.Env)
	}
	if !serverCfg.AlwaysLoad {
		t.Fatal("mcp server alwaysLoad = false, want true so tools are present in the first turn")
	}
}

func argvOrEmpty(argv []string, i int) string {
	if i < 0 || i >= len(argv) {
		return "<missing>"
	}
	return argv[i]
}

func TestMinimalEnv_PreservesProxyAndTrustSettingsWithoutAgentSecrets(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://proxy.test:8443")
	t.Setenv("NO_PROXY", "localhost,.svc")
	t.Setenv("NODE_EXTRA_CA_CERTS", "/etc/ssl/custom.pem")
	t.Setenv("SSL_CERT_FILE", "/etc/ssl/cert.pem")
	t.Setenv("AGENT_API_TOKEN", "must-not-leak")

	got := make(map[string]string)
	for _, kv := range minimalEnv() {
		key, value, ok := strings.Cut(kv, "=")
		if ok {
			got[key] = value
		}
	}
	if got["HTTPS_PROXY"] != "http://proxy.test:8443" ||
		got["NO_PROXY"] != "localhost,.svc" ||
		got["NODE_EXTRA_CA_CERTS"] != "/etc/ssl/custom.pem" ||
		got["SSL_CERT_FILE"] != "/etc/ssl/cert.pem" {
		t.Fatalf("proxy/trust settings not preserved: %#v", got)
	}
	if _, ok := got["AGENT_API_TOKEN"]; ok {
		t.Fatalf("AGENT_API_TOKEN leaked into Claude env: %#v", got)
	}
}

func TestClaudeInvoker_Run_ReturnsErrorWhenClaudeReportsIsError(t *testing.T) {
	stdout := `{"type":"result","subtype":"error_max_turns","is_error":true,"result":"ran out of turns"}`
	bin, _, _, _ := fakeClaudeScript(t, stdout, 0)
	inv := &ClaudeInvoker{ClaudeBin: bin, Self: "/bin/agent-worker"}
	err := inv.Run(context.Background(), JobEnvelope{JobID: 1})
	if err == nil {
		t.Fatal("expected an error when claude reports is_error=true")
	}
}

func TestClaudeInvoker_Run_NonZeroExitIsAnError(t *testing.T) {
	bin, _, _, _ := fakeClaudeScript(t, "", 1)
	inv := &ClaudeInvoker{ClaudeBin: bin, Self: "/bin/agent-worker"}
	err := inv.Run(context.Background(), JobEnvelope{JobID: 1})
	if err == nil {
		t.Fatal("expected an error for nonzero exit")
	}
}

func TestClaudeInvoker_Run_RejectsSuccessfulCLIWithoutDurableCompletion(t *testing.T) {
	stdout := `{"type":"result","subtype":"success","is_error":false,"num_turns":1,"result":"mcp__agent__complete_agent_job({\"status\":\"completed\"})"}`
	bin, _, _, _ := fakeClaudeScript(t, stdout, 0)
	statusSrv := jobStatusServer(t, 42, "processing", 1)
	inv := &ClaudeInvoker{
		ClaudeBin: bin, Self: "/bin/agent-worker", APIBaseURL: statusSrv.URL,
		APIToken: "super-secret-token",
	}

	err := inv.Run(context.Background(), JobEnvelope{JobID: 42, Attempt: 1})
	if !errors.Is(err, ErrAgentDidNotCompleteJob) {
		t.Fatalf("Run err = %v, want ErrAgentDidNotCompleteJob", err)
	}
}

func TestClaudeInvoker_Run_RejectsCompletionByDifferentAttempt(t *testing.T) {
	stdout := `{"type":"result","subtype":"success","is_error":false,"num_turns":1,"result":"done"}`
	bin, _, _, _ := fakeClaudeScript(t, stdout, 0)
	statusSrv := jobStatusServer(t, 42, "completed", 2)
	inv := &ClaudeInvoker{
		ClaudeBin: bin, Self: "/bin/agent-worker", APIBaseURL: statusSrv.URL,
		APIToken: "super-secret-token",
	}

	err := inv.Run(context.Background(), JobEnvelope{JobID: 42, Attempt: 1})
	if !errors.Is(err, ErrAgentDidNotCompleteJob) {
		t.Fatalf("Run err = %v, want ErrAgentDidNotCompleteJob", err)
	}
}

// costReportingServer handles both GET /jobs/{id} (status check) and
// POST /jobs/{id}/cost (worker cost report) for T5's recordCost tests, and
// records every cost report it receives.
type costReportingServer struct {
	mu          sync.Mutex
	costReports []struct {
		attempt int
		cost    float64
	}
	jobID, attempt int64
	status         string
}

func newCostReportingServer(t *testing.T, jobID int64, status string, attempt int) (*httptest.Server, *costReportingServer) {
	t.Helper()
	crs := &costReportingServer{jobID: jobID, attempt: int64(attempt), status: status}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/jobs/"+strconv.FormatInt(jobID, 10):
			writeJSONFixture(w, JobStatus{JobID: jobID, Status: crs.status, Attempt: attempt})
		case r.Method == http.MethodPost && r.URL.Path == "/jobs/"+strconv.FormatInt(jobID, 10)+"/cost":
			var body struct {
				Attempt int     `json:"attempt"`
				CostUSD float64 `json:"cost_usd"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			crs.mu.Lock()
			crs.costReports = append(crs.costReports, struct {
				attempt int
				cost    float64
			}{body.Attempt, body.CostUSD})
			crs.mu.Unlock()
			writeJSONFixture(w, map[string]any{"recorded": true})
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, crs
}

// TestClaudeInvoker_Run_RecordsCostBeforeCheckResult_Success covers T5's
// success case: the fixture's total_cost_usd increases
// mctl_agent_job_cost_usd_total{result="success"}.
func TestClaudeInvoker_Run_RecordsCostBeforeCheckResult_Success(t *testing.T) {
	stdout := `{"type":"result","subtype":"success","is_error":false,"num_turns":2,"total_cost_usd":0.25,"result":"handled it"}`
	bin, _, _, _ := fakeClaudeScript(t, stdout, 0)
	srv, crs := newCostReportingServer(t, 42, "completed", 1)
	m := metrics.New()
	inv := &ClaudeInvoker{ClaudeBin: bin, Self: "/bin/agent-worker", APIBaseURL: srv.URL, APIToken: "tok", Metrics: m}

	before := testutil.ToFloat64(m.AgentJobCostUSDTotal.WithLabelValues("success"))
	if err := inv.Run(context.Background(), JobEnvelope{JobID: 42, Attempt: 1}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	after := testutil.ToFloat64(m.AgentJobCostUSDTotal.WithLabelValues("success"))
	if after != before+0.25 {
		t.Fatalf("cost total = %v, want %v", after, before+0.25)
	}
	crs.mu.Lock()
	defer crs.mu.Unlock()
	if len(crs.costReports) != 1 || crs.costReports[0].cost != 0.25 || crs.costReports[0].attempt != 1 {
		t.Fatalf("cost reports = %+v", crs.costReports)
	}
}

// TestClaudeInvoker_Run_RecordsCostBeforeCheckResult_Error covers T5's
// is_error=true case: the cost must still be recorded (and reported) even
// though CheckResult subsequently fails Run — proving recordCost runs
// before the check, not after. Moving recordCost after CheckResult fails
// this case (the cost report would never happen).
func TestClaudeInvoker_Run_RecordsCostBeforeCheckResult_Error(t *testing.T) {
	stdout := `{"type":"result","subtype":"error_max_turns","is_error":true,"total_cost_usd":0.42,"result":"ran out of turns"}`
	bin, _, _, _ := fakeClaudeScript(t, stdout, 0)
	srv, crs := newCostReportingServer(t, 7, "processing", 1)
	m := metrics.New()
	inv := &ClaudeInvoker{ClaudeBin: bin, Self: "/bin/agent-worker", APIBaseURL: srv.URL, APIToken: "tok", Metrics: m}

	before := testutil.ToFloat64(m.AgentJobCostUSDTotal.WithLabelValues("error"))
	err := inv.Run(context.Background(), JobEnvelope{JobID: 7, Attempt: 1})
	if err == nil {
		t.Fatal("expected an error from CheckResult")
	}
	if !errors.Is(err, ErrClaudeReportedError) {
		t.Fatalf("err = %v, want ErrClaudeReportedError", err)
	}
	after := testutil.ToFloat64(m.AgentJobCostUSDTotal.WithLabelValues("error"))
	if after != before+0.42 {
		t.Fatalf("cost total = %v, want %v (recordCost must run before CheckResult)", after, before+0.42)
	}
	crs.mu.Lock()
	defer crs.mu.Unlock()
	if len(crs.costReports) != 1 || crs.costReports[0].cost != 0.42 {
		t.Fatalf("cost reports = %+v, want one report of 0.42 despite the subsequent CheckResult failure", crs.costReports)
	}

	classErr := testutil.ToFloat64(m.AgentClaudeResultErrorsTotal.WithLabelValues("other"))
	if classErr != 1 {
		t.Fatalf("AgentClaudeResultErrorsTotal{class=other} = %v, want 1", classErr)
	}
}

// TestClaudeInvoker_Run_NilMetricsIsANoOp guards recordCost/countResultError's
// nil-safety: a ClaudeInvoker with no Metrics registry must behave exactly
// as before this proposal.
func TestClaudeInvoker_Run_NilMetricsIsANoOp(t *testing.T) {
	stdout := `{"type":"result","subtype":"success","is_error":false,"total_cost_usd":0.1,"result":"ok"}`
	bin, _, _, _ := fakeClaudeScript(t, stdout, 0)
	statusSrv := jobStatusServer(t, 42, "completed", 1)
	inv := &ClaudeInvoker{ClaudeBin: bin, Self: "/bin/agent-worker", APIBaseURL: statusSrv.URL, APIToken: "super-secret-token"}
	if err := inv.Run(context.Background(), JobEnvelope{JobID: 42, Attempt: 1}); err != nil {
		t.Fatalf("Run: %v", err)
	}
}

// TestClaudeInvoker_Run_MetricsExpositionCarriesNoConversationContent covers
// T12: after running a job whose result carries a synthetic persona's
// message body verbatim (Bob, per .claude/CLAUDE.md's fixture-persona
// rule), the worker registry's own exposition output must contain none of
// that content, none of the peer handle, and none of the synthetic event
// id — the new metric families are labeled only by bounded, content-free
// values (result, class, domain_id).
func TestClaudeInvoker_Run_MetricsExpositionCarriesNoConversationContent(t *testing.T) {
	const (
		peerHandle = "@bob_the_recruiter"
		eventID    = "evt:v1:1:9001:4242"
		msgBody    = "Bob asked: are you available for a call about the Staff Engineer role at Acme?"
	)
	stdout := `{"type":"result","subtype":"error_during_execution","is_error":true,"total_cost_usd":0.05,"result":"` + msgBody + `"}`
	bin, _, _, _ := fakeClaudeScript(t, stdout, 0)
	srv, _ := newCostReportingServer(t, 55, "processing", 1)
	m := metrics.New()
	m.AgentCredentialDomain.WithLabelValues("acct-privacy-test").Set(1)
	inv := &ClaudeInvoker{ClaudeBin: bin, Self: "/bin/agent-worker", APIBaseURL: srv.URL, APIToken: "tok", Metrics: m}

	err := inv.Run(context.Background(), JobEnvelope{JobID: 55, EventID: eventID, Attempt: 1})
	if err == nil {
		t.Fatal("expected an error from CheckResult")
	}

	handler := promhttp.HandlerFor(m.Prometheus, promhttp.HandlerOpts{})
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	out := rec.Body.String()
	for _, secret := range []string{peerHandle, eventID, msgBody, "Bob"} {
		if strings.Contains(out, secret) {
			t.Fatalf("metrics exposition leaked %q: %s", secret, out)
		}
	}
}

func TestClaudeInvoker_Run_RejectsCompletionForDifferentJob(t *testing.T) {
	stdout := `{"type":"result","subtype":"success","is_error":false,"num_turns":1,"result":"done"}`
	bin, _, _, _ := fakeClaudeScript(t, stdout, 0)
	statusSrv := jobStatusServer(t, 99, "completed", 1)
	inv := &ClaudeInvoker{
		ClaudeBin: bin, Self: "/bin/agent-worker", APIBaseURL: statusSrv.URL,
		APIToken: "super-secret-token",
	}

	err := inv.Run(context.Background(), JobEnvelope{JobID: 42, Attempt: 1})
	if !errors.Is(err, ErrAgentDidNotCompleteJob) {
		t.Fatalf("Run err = %v, want ErrAgentDidNotCompleteJob", err)
	}
}

// TestClaudeInvoker_Run_NegativeCostIsDropped guards recordCost against a
// negative total_cost_usd from the claude CLI: prometheus.Counter.Add panics
// on a negative delta and there is no recover() in the worker, so a single
// bad value would take the poll loop down. The value must be dropped — no
// counter increment, no cost report — without failing the job.
func TestClaudeInvoker_Run_NegativeCostIsDropped(t *testing.T) {
	stdout := `{"type":"result","subtype":"success","is_error":false,"num_turns":2,"total_cost_usd":-0.25,"result":"handled it"}`
	bin, _, _, _ := fakeClaudeScript(t, stdout, 0)
	srv, crs := newCostReportingServer(t, 42, "completed", 1)
	m := metrics.New()
	inv := &ClaudeInvoker{ClaudeBin: bin, Self: "/bin/agent-worker", APIBaseURL: srv.URL, APIToken: "tok", Metrics: m}

	before := testutil.ToFloat64(m.AgentJobCostUSDTotal.WithLabelValues("success"))
	if err := inv.Run(context.Background(), JobEnvelope{JobID: 42, Attempt: 1}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	after := testutil.ToFloat64(m.AgentJobCostUSDTotal.WithLabelValues("success"))
	if after != before {
		t.Fatalf("cost total = %v, want %v (a negative cost must not be counted)", after, before)
	}
	crs.mu.Lock()
	defer crs.mu.Unlock()
	if len(crs.costReports) != 0 {
		t.Fatalf("cost reports = %+v, want none for a negative cost", crs.costReports)
	}
}
