package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const providerPrefix = "github.com/mctlhq/mctl-telegram/provider/glovo"

// forbiddenIn reports the entries of a `go list -deps` output the provider
// must not link: any Temporal package, or any mctl-telegram package outside
// the provider module.
func forbiddenIn(out string) []string {
	var bad []string
	for _, pkg := range strings.Fields(out) {
		switch {
		case strings.HasPrefix(pkg, "go.temporal.io/"):
			bad = append(bad, pkg)
		case strings.HasPrefix(pkg, "github.com/mctlhq/mctl-telegram/") && !strings.HasPrefix(pkg, providerPrefix):
			bad = append(bad, pkg)
		}
	}
	return bad
}

func goOut(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("go", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go %v: %v\n%s", args, err, out)
	}
	return string(out)
}

// T19: no Temporal and no root-module import in the provider module.
func TestProviderModuleBoundary(t *testing.T) {
	if bad := forbiddenIn(goOut(t, "../..", "list", "-deps", "./...")); len(bad) > 0 {
		t.Fatalf("forbidden dependencies: %v", bad)
	}
	if strings.Contains(goOut(t, "../..", "list", "-m", "all"), "go.temporal.io") {
		t.Fatal("the module graph must not contain go.temporal.io")
	}
}

// The detector itself: it must fire on planted imports.
func TestBoundaryDetectorFindsPlantedImports(t *testing.T) {
	out := "fmt\n" + providerPrefix + "/internal/obs\ngo.temporal.io/sdk/client\ngithub.com/mctlhq/mctl-telegram/internal/telegram\n"
	if got := forbiddenIn(out); len(got) != 2 {
		t.Fatalf("detector missed planted imports: %v", got)
	}
	if got := forbiddenIn("fmt\n" + providerPrefix + "/internal/obs\n"); len(got) != 0 {
		t.Fatalf("false positive: %v", got)
	}

	// And end to end on a real `go list`: a throwaway module that imports a
	// local stand-in for the Temporal SDK.
	dir := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("stub/go.mod", "module go.temporal.io/sdk\n\ngo 1.26\n")
	write("stub/client/client.go", "package client\n")
	write("app/go.mod", "module example.test/app\n\ngo 1.26\n\nrequire go.temporal.io/sdk v0.0.0\n\nreplace go.temporal.io/sdk => ../stub\n")
	write("app/main.go", "package main\n\nimport _ \"go.temporal.io/sdk/client\"\n\nfunc main() {}\n")
	if got := forbiddenIn(goOut(t, filepath.Join(dir, "app"), "list", "-deps", "./...")); len(got) == 0 {
		t.Fatal("a planted temporal import must be detected")
	}
}

// Retained from the #1258 draft: the public server binary does not link the
// provider, and the root go.mod has no Temporal requirement.
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
