package agentworker

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

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

	inv := &ClaudeInvoker{
		ClaudeBin:  bin,
		Self:       "/usr/local/bin/agent-worker",
		APIBaseURL: "https://example.test/api/agent/v1",
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
