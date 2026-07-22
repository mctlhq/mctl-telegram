package agentworker

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeClaudeScript writes a shell script standing in for the real `claude`
// binary: it dumps its argv to argvFile (one arg per line, so the test can
// assert on exact flags/values) and prints stdout on its own stdout,
// letting Run's parsing be exercised without ever invoking the real CLI or
// spending real API budget.
func fakeClaudeScript(t *testing.T, stdout string, exitCode int) (bin, argvFile string) {
	t.Helper()
	dir := t.TempDir()
	bin = filepath.Join(dir, "fake-claude.sh")
	argvFile = filepath.Join(dir, "argv.txt")
	script := "#!/bin/sh\n" +
		"for a in \"$@\"; do printf '%s\\n' \"$a\" >> " + argvFile + "; done\n" +
		"cat <<'STDOUT_EOF'\n" + stdout + "\nSTDOUT_EOF\n" +
		"exit " + itoa(exitCode) + "\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake claude script: %v", err)
	}
	return bin, argvFile
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
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
	bin, argvFile := fakeClaudeScript(t, stdout, 0)

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
	for _, want := range []string{"-p", "--strict-mcp-config", "--allowedTools", "--output-format", "json", "--mcp-config"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("argv missing %q: %v", want, argv)
		}
	}
	if !strings.Contains(joined, "mcp__"+ServerName+"__complete_agent_job") {
		t.Fatalf("allowedTools missing complete_agent_job: %v", argv)
	}
	// The mcp-config arg must carry job identity and the API token through
	// to the MCP server subprocess's env — that's the only place a job's
	// identity is authoritative (see JobContext's doc comment).
	var cfgArg string
	for i, a := range argv {
		if a == "--mcp-config" && i+1 < len(argv) {
			cfgArg = argv[i+1]
		}
	}
	if cfgArg == "" {
		t.Fatal("did not find --mcp-config value in argv")
	}
	var cfg mcpConfig
	if err := json.Unmarshal([]byte(cfgArg), &cfg); err != nil {
		t.Fatalf("mcp-config is not valid JSON: %v (%s)", err, cfgArg)
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

func TestClaudeInvoker_Run_ReturnsErrorWhenClaudeReportsIsError(t *testing.T) {
	stdout := `{"type":"result","subtype":"error_max_turns","is_error":true,"result":"ran out of turns"}`
	bin, _ := fakeClaudeScript(t, stdout, 0)
	inv := &ClaudeInvoker{ClaudeBin: bin, Self: "/bin/agent-worker"}
	err := inv.Run(context.Background(), JobEnvelope{JobID: 1})
	if err == nil {
		t.Fatal("expected an error when claude reports is_error=true")
	}
}

func TestClaudeInvoker_Run_NonZeroExitIsAnError(t *testing.T) {
	bin, _ := fakeClaudeScript(t, "", 1)
	inv := &ClaudeInvoker{ClaudeBin: bin, Self: "/bin/agent-worker"}
	err := inv.Run(context.Background(), JobEnvelope{JobID: 1})
	if err == nil {
		t.Fatal("expected an error for nonzero exit")
	}
}
