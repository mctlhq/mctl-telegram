package agentworker

import "testing"

func TestBuildMCPConfig_UsesJobToken(t *testing.T) {
	c := &ClaudeInvoker{Self: "/bin/self", APIBaseURL: "http://api", APIToken: "account-token"}
	cfg := c.buildMCPConfig(JobEnvelope{JobID: 1, Attempt: 1, ConversationID: 2, JobToken: "job-token"})
	if got := cfg.MCPServers[ServerName].Env["AGENT_API_TOKEN"]; got != "job-token" {
		t.Fatalf("AGENT_API_TOKEN = %q, want the job token", got)
	}
}

func TestBuildMCPConfig_FallsBackToAccountToken(t *testing.T) {
	c := &ClaudeInvoker{Self: "/bin/self", APIBaseURL: "http://api", APIToken: "account-token"}
	cfg := c.buildMCPConfig(JobEnvelope{JobID: 1, Attempt: 1, ConversationID: 2})
	if got := cfg.MCPServers[ServerName].Env["AGENT_API_TOKEN"]; got != "account-token" {
		t.Fatalf("AGENT_API_TOKEN = %q, want the account token", got)
	}
}
