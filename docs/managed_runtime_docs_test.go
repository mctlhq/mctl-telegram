package docs

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// docSection returns the text from the heading line containing start up to
// the next heading of the same or higher level.
func docSection(t *testing.T, doc, start string) string {
	t.Helper()
	i := strings.Index(doc, start)
	if i < 0 {
		t.Fatalf("section %q not found", start)
	}
	level := len(start) - len(strings.TrimLeft(start, "#"))
	rest := doc[i+len(start):]
	end := len(rest)
	re := regexp.MustCompile(`(?m)^#{1,` + string(rune('0'+level)) + `} `)
	if loc := re.FindStringIndex(rest); loc != nil {
		end = loc[0]
	}
	return rest[:end]
}

// requireInOrder fails unless every marker appears in sec, in the given order.
func requireInOrder(t *testing.T, sec string, markers []string) {
	t.Helper()
	prev := -1
	for _, m := range markers {
		idx := strings.Index(sec, m)
		if idx < 0 {
			t.Errorf("marker %q not found", m)
			continue
		}
		if idx <= prev {
			t.Errorf("marker %q is out of order", m)
		}
		prev = idx
	}
}

// Every env var the worker reads in poll mode is a table cell in
// agent-worker.md.
func TestAgentWorkerEnvTableComplete(t *testing.T) {
	src, err := os.ReadFile("../cmd/agent-worker/main.go")
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`(?:requireEnv|requiredEnvFloat|envFloat|envBoolStrict|envPositiveInt|envDuration|envConcurrency|os\.Getenv)\("([A-Z][A-Z0-9_]+)"`)
	names := map[string]bool{}
	for _, m := range re.FindAllStringSubmatch(string(src), -1) {
		if strings.HasPrefix(m[1], "AGENT_JOB_") {
			continue
		}
		names[m[1]] = true
	}
	if len(names) < 15 {
		t.Fatalf("found only %d env names in main.go; the scan is broken", len(names))
	}
	doc := readDoc(t, "agent-worker.md")
	for name := range names {
		if !strings.Contains(doc, "| `"+name+"` |") {
			t.Errorf("agent-worker.md has no table row for %s", name)
		}
	}
}

// Every MANAGED_* setting the server reads is in the runbook.
func TestRunbookManagedConfigComplete(t *testing.T) {
	src, err := os.ReadFile("../internal/config/config.go")
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, m := range regexp.MustCompile(`"(MANAGED_[A-Z_]+)"`).FindAllStringSubmatch(string(src), -1) {
		names[m[1]] = true
	}
	if len(names) == 0 {
		t.Fatal("no MANAGED_* names found in config.go")
	}
	doc := readDoc(t, "runbook.md")
	for name := range names {
		if !strings.Contains(doc, "| `"+name+"` |") {
			t.Errorf("runbook.md has no configuration row for %s", name)
		}
	}
}

func TestRunbookManagedRollbackOrder(t *testing.T) {
	sec := docSection(t, readDoc(t, "runbook.md"), "### Managed runtime rollback")
	requireInOrder(t, sec, []string{"`runtime: own`", "`replicaCount: 0`", "`revoke_worker_token`", "`MANAGED_RUNTIME_ENABLED: \"false\"`"})
}

func TestRunbookManagedActivationOrder(t *testing.T) {
	sec := docSection(t, readDoc(t, "runbook.md"), "### Managed runtime activation")
	requireInOrder(t, sec, []string{
		`MANAGED_RUNTIME_ENABLED: "true"`,
		"mctl-telegram-ai-gateway-run",
		"mint the pool token",
		"`SecretSynced`",
		"`replicaCount: 1`",
		"`runtime: managed`",
	})
	if !strings.Contains(sec, "agent-worker-managed-preview/api") {
		t.Error("activation section does not name agent-worker-managed-preview/api")
	}
}

// The consent version and sentence in spec.md are the ones in the code.
func TestSpecConsentTextMatchesCode(t *testing.T) {
	src, err := os.ReadFile("../internal/db/managed_runtime.go")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`ManagedConsentText\s*=\s*"((?:[^"\\]|\\.)*)"`).FindStringSubmatch(string(src))
	if m == nil {
		t.Fatal("ManagedConsentText not found in managed_runtime.go")
	}
	spec := readDoc(t, "assistants/spec.md")
	if !strings.Contains(spec, "managed-data-flow/v1") {
		t.Error("spec.md does not name managed-data-flow/v1")
	}
	if !strings.Contains(spec, m[1]) {
		t.Errorf("spec.md does not contain the consent text from the code: %q", m[1])
	}
}
