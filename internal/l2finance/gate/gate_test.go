//go:build l2finance

// Package gate aggregates the Finance Assistant L2 (#1244) results of the five
// tagged packages from one `go test -json` stream, checks them against a
// committed manifest and derives FINANCE_SECURITY_GATE by machine.
//
// harness_status (COMPLETE|INVALID) is reported separately from
// FINANCE_SECURITY_GATE (PASS|BLOCKED). A green go test exit code is never a
// security pass. The package contains only test sources.
package gate

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

const (
	outPass           = "PASS"
	outFailGap        = "FAIL/GAP"
	outNotImplemented = "NOT-IMPLEMENTED"
	outCannotObserve  = "CANNOT-OBSERVE"

	harnessComplete = "COMPLETE"
	harnessInvalid  = "INVALID"

	gatePass    = "PASS"
	gateBlocked = "BLOCKED"

	issuePass     = "COMPLETE_WITH_PASS"
	issueGaps     = "COMPLETE_WITH_GAPS_BLOCKED"
	issueIncomp   = "INCOMPLETE_BLOCKED"
	issueCannotOb = "CANNOT_OBSERVE_BLOCKED"
)

var (
	rowRe = regexp.MustCompile(`^\s*\S+:\d+: L2RESULT id=(\S+) outcome=(PASS|FAIL/GAP|NOT-IMPLEMENTED|CANNOT-OBSERVE) rev=([0-9a-f]{40}) evidence=(.*)$`)
	revRe = regexp.MustCompile(`^[0-9a-f]{40}$`)
	fixRe = regexp.MustCompile(`^fixture_id=(\S+)(?: |$)`)
)

type manifestRow struct {
	Key     string // <package>:<id>
	Kind    string // case|control|offline
	Fixture string // synthetic|none
	Missing bool
}

type row struct {
	Pkg, ID, Outcome, Rev, Evidence, Fixture string
}

func (r row) key() string { return r.Pkg + ":" + r.ID }

type result struct {
	Harness  string
	Gate     string
	Issue    string
	Problems []string
	Rows     []row // sorted by canonical ID
	Counts   map[string]int
	Rev      string
}

func parseManifest(r io.Reader) ([]manifestRow, error) {
	var out []manifestRow
	seen := map[string]bool{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 3 || len(f) > 4 || !strings.Contains(f[0], ":") {
			return nil, fmt.Errorf("malformed manifest line %q", line)
		}
		switch f[1] {
		case "case", "control", "offline":
		default:
			return nil, fmt.Errorf("manifest line %q: unknown kind", line)
		}
		if f[2] != "synthetic" && f[2] != "none" {
			return nil, fmt.Errorf("manifest line %q: unknown fixture requirement", line)
		}
		if len(f) == 4 && f[3] != "MISSING" {
			return nil, fmt.Errorf("manifest line %q: unknown marker", line)
		}
		if seen[f[0]] {
			return nil, fmt.Errorf("duplicate manifest line %q", f[0])
		}
		seen[f[0]] = true
		out = append(out, manifestRow{Key: f[0], Kind: f[1], Fixture: f[2], Missing: len(f) == 4})
	}
	return out, sc.Err()
}

type event struct {
	Action  string
	Package string
	Output  string
}

// evaluate is the whole aggregation. It never panics on malformed input.
func evaluate(man []manifestRow, stream io.Reader, pinnedRev string) result {
	res := result{Harness: harnessInvalid, Gate: gateBlocked, Issue: issueCannotOb, Rev: pinnedRev, Counts: map[string]int{}}
	problem := func(f string, a ...any) { res.Problems = append(res.Problems, fmt.Sprintf(f, a...)) }

	if !revRe.MatchString(pinnedRev) {
		problem("pinned revision %q is not a 40-hex sha", pinnedRev)
		return res
	}
	var rows []row
	events, failedPkgs, buildFailed, unclassified := 0, map[string]bool{}, false, 0
	counts := map[string]int{}
	sc := bufio.NewScanner(stream)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		var e event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			problem("unparseable JSON line in stream")
			continue
		}
		events++
		if e.Action == "fail" && e.Package != "" {
			failedPkgs[e.Package] = true
		}
		if strings.Contains(e.Output, "[build failed]") || strings.Contains(e.Output, "[setup failed]") {
			buildFailed = true
		}
		if !strings.Contains(e.Output, "L2RESULT") {
			continue
		}
		line := strings.TrimRight(e.Output, "\r\n")
		m := rowRe.FindStringSubmatch(line)
		if m == nil {
			unclassified++
			problem("unclassified L2RESULT line in %s: %q", e.Package, line)
			continue
		}
		r := row{Pkg: path.Base(e.Package), ID: m[1], Outcome: m[2], Rev: m[3], Evidence: m[4], Fixture: "missing"}
		if fm := fixRe.FindStringSubmatch(r.Evidence); fm != nil {
			r.Fixture = fm[1]
		}
		rows = append(rows, r)
		counts[r.key()]++
	}
	if err := sc.Err(); err != nil {
		problem("reading stream: %v", err)
	}
	if events == 0 {
		problem("empty stream: no go test JSON events")
		return res
	}
	if buildFailed {
		problem("a package failed to build or set up")
		return res
	}
	if len(rows) == 0 {
		problem("no L2RESULT rows observed")
		return res
	}

	// The stream is trustworthy enough to judge from here on.
	res.Issue = issueIncomp
	for p := range failedPkgs {
		problem("package %s reported Action=fail", p)
	}
	byKey := map[string]row{}
	for _, r := range rows {
		if counts[r.key()] > 1 {
			if _, dup := byKey[r.key()]; dup {
				continue
			}
			problem("duplicate canonical id %s (%d rows)", r.key(), counts[r.key()])
		}
		byKey[r.key()] = r
		if r.Rev != pinnedRev {
			problem("%s: rev %s differs from pinned %s", r.key(), r.Rev, pinnedRev)
		}
	}
	manByKey := map[string]manifestRow{}
	for _, m := range man {
		manByKey[m.Key] = m
		r, ok := byKey[m.Key]
		if !ok {
			if m.Missing {
				problem("missing emitter (MISSING in manifest): %s", m.Key)
			} else {
				problem("manifest id %s not emitted", m.Key)
			}
			continue
		}
		if m.Missing {
			problem("%s is marked MISSING but is emitted; update the manifest by review", m.Key)
		}
		if (m.Kind == "control" || m.Kind == "offline") && r.Outcome != outPass {
			problem("%s (%s) is %s, harness integrity rows must PASS", m.Key, m.Kind, r.Outcome)
		}
		switch m.Fixture {
		case "synthetic":
			if r.Fixture != "L2SYNTH-"+r.ID {
				problem("%s: fixture_id %q does not match the manifest requirement", m.Key, r.Fixture)
			}
		case "none":
			if r.Fixture != "none" {
				problem("%s: fixture_id %q, want none", m.Key, r.Fixture)
			}
		}
	}
	for k := range byKey {
		if _, ok := manByKey[k]; !ok {
			problem("row %s is not in the manifest", k)
		}
	}

	keys := make([]string, 0, len(byKey))
	for k := range byKey {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	allPass := true
	for _, k := range keys {
		r := byKey[k]
		res.Rows = append(res.Rows, r)
		res.Counts[r.Outcome]++
		if r.Outcome != outPass {
			allPass = false
		}
	}
	if len(res.Problems) > 0 {
		return res
	}
	res.Harness = harnessComplete
	if allPass {
		res.Gate, res.Issue = gatePass, issuePass
	} else {
		res.Issue = issueGaps
	}
	return res
}

func (r result) statusLines() string {
	return fmt.Sprintf("issue_outcome=%s\nharness_status=%s\nFINANCE_SECURITY_GATE=%s\n", r.Issue, r.Harness, r.Gate)
}

func (r result) markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "FINANCE_SECURITY_GATE=%s\n\n", r.Gate)
	fmt.Fprintf(&b, "- harness_status: `%s`\n- issue_outcome: `%s`\n- source revision: `%s`\n", r.Harness, r.Issue, r.Rev)
	fmt.Fprintf(&b, "- counts: PASS=%d, FAIL/GAP=%d, NOT-IMPLEMENTED=%d, CANNOT-OBSERVE=%d\n\n",
		r.Counts[outPass], r.Counts[outFailGap], r.Counts[outNotImplemented], r.Counts[outCannotObserve])
	if len(r.Problems) > 0 {
		b.WriteString("## Harness problems\n\n")
		for _, p := range r.Problems {
			fmt.Fprintf(&b, "- %s\n", strings.ReplaceAll(p, "|", "\\|"))
		}
		b.WriteString("\n")
	}
	if len(r.Rows) > 0 {
		b.WriteString("## Results\n\n| Canonical ID | Outcome | Fixture | Evidence |\n| --- | --- | --- | --- |\n")
		for _, x := range r.Rows {
			ev := strings.TrimSpace(strings.TrimPrefix(x.Evidence, "fixture_id="+x.Fixture))
			fmt.Fprintf(&b, "| `%s` | %s | `%s` | %s |\n", x.key(), x.Outcome, x.Fixture, strings.ReplaceAll(ev, "|", "\\|"))
		}
		b.WriteString("\n## Gap IDs (FAIL/GAP)\n\n")
		for _, x := range r.Rows {
			if x.Outcome == outFailGap {
				fmt.Fprintf(&b, "- `%s`\n", x.key())
			}
		}
	}
	return b.String()
}

// tuples is the reproducibility fingerprint compared across two runs.
func (r result) tuples() string {
	var b strings.Builder
	for _, x := range r.Rows {
		fmt.Fprintf(&b, "%s\t%s\t%s\t%s\t%s\n", x.Pkg, x.ID, x.Outcome, x.Fixture, x.Rev)
	}
	return b.String()
}

// TestL2FinanceGate is run by scripts/l2finance/run.sh. It exits non-zero
// only for harness_status=INVALID; a COMPLETE but BLOCKED gate exits zero.
func TestL2FinanceGate(t *testing.T) {
	path := os.Getenv("L2FINANCE_RESULTS_JSON")
	if path == "" {
		t.Skip("L2FINANCE_RESULTS_JSON not set")
	}
	mf, err := os.Open("testdata/manifest.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer mf.Close()
	man, err := parseManifest(mf)
	if err != nil {
		t.Fatalf("manifest: %v", err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open L2 finance results %q: %v", path, err)
	}
	defer f.Close()
	res := evaluate(man, f, os.Getenv("L2FINANCE_SOURCE_REV"))
	if p := os.Getenv("L2FINANCE_SUMMARY_MD"); p != "" {
		if err := os.WriteFile(p, []byte(res.markdown()), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if p := os.Getenv("L2FINANCE_TUPLES"); p != "" {
		if err := os.WriteFile(p, []byte(res.tuples()), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	fmt.Print(res.statusLines())
	if res.Harness == harnessInvalid {
		for _, p := range res.Problems {
			t.Errorf("%s", p)
		}
		t.Fatalf("harness_status=INVALID (%s)", res.Issue)
	}
}
