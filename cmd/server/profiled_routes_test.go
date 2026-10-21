package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The routes are assembled inline in main(), so this pins the wiring at the
// source: auth.MCPMiddleware, the only middleware that admits a credential
// carrying a tool profile, guards the MCP handler and nothing else. Any
// other route admitting a profiled token would hand the restricted client
// its full scopes there (internal/auth.Middleware). The whole module is
// scanned, not only main.go, so a route mounted from another file or
// package is caught as well.
func TestOnlyTheMCPHandlerAdmitsProfiledCredentials(t *testing.T) {
	call := regexp.MustCompile(`\bauth\.MCPMiddleware\(`)
	var sites []string
	err := filepath.WalkDir("../..", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "vendor", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for range call.FindAllIndex(src, -1) {
			sites = append(sites, filepath.ToSlash(path))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scan module: %v", err)
	}
	if len(sites) != 1 || sites[0] != "../../cmd/server/main.go" {
		t.Fatalf("auth.MCPMiddleware call sites = %v, want exactly one, in cmd/server/main.go", sites)
	}
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`mcpHandler := auth\.MCPMiddleware\(`).Match(src) {
		t.Fatal("the MCP handler is not wrapped by auth.MCPMiddleware: profiled clients would get 403 on /mcp")
	}
}
