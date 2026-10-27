package docs

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

const matrixHeader = "| Host | Registration path | Allowlist entry today | Status | Evidence | Date observed |"

type matrixRow struct {
	host, status, evidence, date string
}

func readMatrix(t *testing.T) []matrixRow {
	t.Helper()
	data, err := os.ReadFile("platforms/compatibility.md")
	if err != nil {
		t.Fatalf("failed to read platforms/compatibility.md: %v", err)
	}
	lines := strings.Split(string(data), "\n")
	start := -1
	for i, l := range lines {
		if strings.TrimSpace(l) == matrixHeader {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatalf("matrix header not found")
	}
	var rows []matrixRow
	for _, l := range lines[start+2:] {
		l = strings.TrimSpace(l)
		if !strings.HasPrefix(l, "|") {
			break
		}
		cells := strings.Split(strings.Trim(l, "|"), "|")
		if len(cells) != 6 {
			t.Fatalf("row has %d cells, want 6: %s", len(cells), l)
		}
		rows = append(rows, matrixRow{
			host:     strings.TrimSpace(cells[0]),
			status:   strings.TrimSpace(cells[3]),
			evidence: strings.TrimSpace(cells[4]),
			date:     strings.TrimSpace(cells[5]),
		})
	}
	return rows
}

func TestCompatibilityMatrixRequiredHosts(t *testing.T) {
	counts := map[string]int{}
	for _, r := range readMatrix(t) {
		counts[r.host]++
	}
	required := []string{
		"Claude (hosted connector)", "Claude Code", "ChatGPT", "Cursor",
		"VS Code", "Windsurf", "Town", "MCP Inspector", "Cloudflare MCP portal",
	}
	for _, h := range required {
		if counts[h] != 1 {
			t.Errorf("host %q appears %d times, want exactly 1", h, counts[h])
		}
	}
	if len(counts) != len(required) {
		t.Errorf("matrix has %d hosts, want %d", len(counts), len(required))
	}
}

func TestCompatibilityMatrixStatusValues(t *testing.T) {
	for _, r := range readMatrix(t) {
		switch r.status {
		case "works", "works with caveats", "not tested":
		default:
			t.Errorf("host %q has invalid status %q", r.host, r.status)
		}
	}
}

func TestCompatibilityMatrixEvidence(t *testing.T) {
	link := regexp.MustCompile(`\]\([^)]+\)`)
	date := regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	for _, r := range readMatrix(t) {
		if r.status != "works" && r.status != "works with caveats" {
			continue
		}
		if !link.MatchString(r.evidence) {
			t.Errorf("host %q is %q without an evidence link", r.host, r.status)
		}
		if !date.MatchString(r.date) {
			t.Errorf("host %q is %q without an ISO date (got %q)", r.host, r.status, r.date)
		}
	}
}

func TestCompatibilityMatrixTownNotWorks(t *testing.T) {
	for _, r := range readMatrix(t) {
		if r.host == "Town" && r.status == "works" {
			t.Errorf("Town must not be %q: no token or tool call is proven", r.status)
		}
	}
}

func TestReadmeLinksCompatibilityMatrix(t *testing.T) {
	data, err := os.ReadFile("../README.md")
	if err != nil {
		t.Fatalf("failed to read README.md: %v", err)
	}
	if !strings.Contains(string(data), "docs/platforms/compatibility.md") {
		t.Error("README.md does not link docs/platforms/compatibility.md")
	}
}

func TestAdmissionRunbookEnvVarsExist(t *testing.T) {
	rb, err := os.ReadFile("runbooks/admitting-an-agent-platform.md")
	if err != nil {
		t.Fatalf("failed to read admission runbook: %v", err)
	}
	cfg, err := os.ReadFile("../internal/config/config.go")
	if err != nil {
		t.Fatalf("failed to read config.go: %v", err)
	}
	names := regexp.MustCompile(`OAUTH_[A-Z_]+|MCP_CLIENT_PROFILES`).FindAllString(string(rb), -1)
	if len(names) == 0 {
		t.Fatal("no env var names found in the runbook")
	}
	for _, n := range names {
		if !strings.Contains(string(cfg), `"`+n+`"`) {
			t.Errorf("env var %s named in runbook is not in internal/config/config.go", n)
		}
	}
}
