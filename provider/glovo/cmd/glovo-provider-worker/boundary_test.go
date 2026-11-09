package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// T15: the public server binary in the root module must not depend on the
// provider module or on the Temporal SDK.
func TestRootServerDoesNotImportProvider(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "cmd", "server", "main.go")); err != nil {
		t.Skip("root module not present")
	}
	cmd := exec.Command("go", "list", "-deps", "./cmd/server")
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Skipf("go list unavailable in this environment: %v", err)
	}
	for _, pkg := range strings.Fields(string(out)) {
		if strings.Contains(pkg, "mctl-telegram/provider/glovo") || strings.HasPrefix(pkg, "go.temporal.io") {
			t.Fatalf("cmd/server depends on %s", pkg)
		}
	}
	mod, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(mod), "temporal") {
		t.Fatal("root go.mod must not require Temporal")
	}
}
