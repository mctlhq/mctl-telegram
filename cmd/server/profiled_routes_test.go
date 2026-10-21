package main

import (
	"os"
	"regexp"
	"testing"
)

// The routes are assembled inline in main(), so this pins the wiring at the
// source: auth.MCPMiddleware, the only middleware that admits a credential
// carrying a tool profile, guards the MCP handler and nothing else. Any
// other route admitting a profiled token would hand the restricted client
// its full scopes there (internal/auth.Middleware).
func TestOnlyTheMCPHandlerAdmitsProfiledCredentials(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	calls := regexp.MustCompile(`auth\.MCPMiddleware\(`).FindAllIndex(src, -1)
	if len(calls) != 1 {
		t.Fatalf("auth.MCPMiddleware is called %d times in main.go, want exactly 1 (the MCP handler)", len(calls))
	}
	if !regexp.MustCompile(`mcpHandler := auth\.MCPMiddleware\(`).Match(src) {
		t.Fatal("the MCP handler is not wrapped by auth.MCPMiddleware: profiled clients would get 403 on /mcp")
	}
}
