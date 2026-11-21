package docs

// The S2 gate check of the Personal Assistant threat model (#1323): S2 is
// the Phase 2 suite that gates enabling PA_WRITES_ENABLED on preview.
// docs/agent-runtime/pa-s2-manifest.yaml lists every S2 id as either
// pending (the slice and issue that will build it) or green (its tests and
// the mutation evidence that each guard is real), and this test keeps the
// manifest, the threat model and the test code in step.

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const s2ManifestPath = "agent-runtime/pa-s2-manifest.yaml"

// s2GateClosingEnv marks a run that is closing the S2 gate (P2-S14, the
// phase2_gate=closed mode): any pending id or open gap then fails the gate.
const s2GateClosingEnv = "PA_S2_GATE_CLOSING"

const (
	s2StatusGreen   = "green"
	s2StatusPending = "pending"
)

type s2Entry struct {
	// Status is green (covered, with tests and mutation evidence) or
	// pending (not built yet).
	Status string `yaml:"status"`
	// Slice is the Phase 2 slice that builds a pending id, or the one that
	// delivered a green id.
	Slice string `yaml:"slice"`
	// TrackedBy is the issue that owns a pending id. A green id carries
	// none: what is still open on it is a gap.
	TrackedBy string       `yaml:"tracked_by"`
	Note      string       `yaml:"note"`
	Tests     []string     `yaml:"tests"`
	Mutations []s2Mutation `yaml:"mutations"`
	Gaps      []paGap      `yaml:"gaps"`
}

// s2Mutation records one deliberate break of a guard and the tests it
// turned red.
type s2Mutation struct {
	ID string `yaml:"id"`
	// Guard is the guarded code as <file>:<line>, relative to the
	// repository root, at the commit the mutation ran on.
	Guard string `yaml:"guard"`
	// GuardText is text of the current tree that occurs exactly once in
	// the guard file and covers the guard line, so a record whose line has
	// drifted away from the guarded code fails instead of passing on a line
	// number that still exists. It may run onto the lines around the guard
	// when the guard line itself is not unique in its file.
	GuardText string   `yaml:"guard_text"`
	Mutation  string   `yaml:"mutation"`
	KilledBy  []string `yaml:"killed_by"`
	// Red is the evidence of the mutated run: it names every killing test
	// and reports FAIL. Green is the evidence of the restored run.
	Red   string `yaml:"red"`
	Green string `yaml:"green"`
}

var (
	s2SliceRe = regexp.MustCompile(`^P2-S[0-9]+$`)
	s2GuardRe = regexp.MustCompile(`^([a-z0-9_/.-]+\.go):([1-9][0-9]*)$`)
	// A go test result line: "FAIL\t<pkg>", "FAIL", or "ok  \t<pkg>".
	s2FailLineRe = regexp.MustCompile(`(?m)^FAIL(?:\s|$)`)
	s2OKLineRe   = regexp.MustCompile(`(?m)^ok\s+\S`)
)

// s2FailedTestRe matches the line go test prints for a failed test name,
// "--- FAIL: <name> (<time>)", and not one of a longer name.
func s2FailedTestRe(name string) *regexp.Regexp {
	return regexp.MustCompile(`(?m)^\s*--- FAIL: ` + regexp.QuoteMeta(name) + ` \(`)
}

// guardLines returns the lines of a repository file, for a guard
// reference. An error means the file could not be read.
type guardLines func(path string) ([]string, error)

// parseS2Manifest decodes the manifest strictly: an unknown field or a
// duplicate id is an error, not an entry that silently drops.
func parseS2Manifest(raw []byte) (map[string]s2Entry, error) {
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	var m map[string]s2Entry
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	if m == nil {
		return nil, fmt.Errorf("manifest has no entries")
	}
	return m, nil
}

// checkS2Manifest returns every disagreement between the threat model's
// S2 ids, the manifest, the test functions that exist (funcs, as
// "<package dir>.<TestFunc>") and the guarded files (lines). An empty
// result is the converged state.
func checkS2Manifest(ids []string, manifest map[string]s2Entry, funcs map[string]bool, lines guardLines) []string {
	var problems []string
	inModel := map[string]bool{}
	for _, id := range ids {
		inModel[id] = true
		if _, ok := manifest[id]; !ok {
			problems = append(problems, fmt.Sprintf("%s: an S2 row of the threat model missing from %s", id, s2ManifestPath))
		}
	}
	mapped := map[string]map[string]bool{}
	for id, e := range manifest {
		if !inModel[id] {
			problems = append(problems, fmt.Sprintf("%s: in the manifest but not an S2 id of the threat model", id))
		}
		mapped[id] = map[string]bool{}
		problems = append(problems, checkGaps(id, e.Gaps)...)
		problems = append(problems, checkTestRefs(id, e.Tests, funcs, mapped[id])...)
		if e.Slice != "" && !s2SliceRe.MatchString(e.Slice) {
			problems = append(problems, fmt.Sprintf("%s: slice %q is not P2-S<n>", id, e.Slice))
		}
		switch e.Status {
		case s2StatusPending:
			if e.Slice == "" {
				problems = append(problems, fmt.Sprintf("%s: pending without a slice", id))
			}
			if !paIssueRef.MatchString(e.TrackedBy) {
				problems = append(problems, fmt.Sprintf("%s: pending but not tracked by an issue (tracked_by %q, want #NNNN)", id, e.TrackedBy))
			}
			if len(e.Gaps) > 0 {
				problems = append(problems, fmt.Sprintf("%s: pending with gaps: the whole row is open, a gap belongs to a green id", id))
			}
		case s2StatusGreen:
			if len(e.Tests) == 0 {
				problems = append(problems, fmt.Sprintf("%s: green without a test", id))
			}
			if len(e.Mutations) == 0 {
				problems = append(problems, fmt.Sprintf("%s: green without a mutation record", id))
			}
			if e.TrackedBy != "" {
				problems = append(problems, fmt.Sprintf("%s: green but tracked_by %q: an open part of a green id is a gap", id, e.TrackedBy))
			}
		default:
			problems = append(problems, fmt.Sprintf("%s: status %q, want %s or %s", id, e.Status, s2StatusGreen, s2StatusPending))
		}
		problems = append(problems, checkS2Mutations(id, e, lines)...)
	}
	problems = append(problems, paSuiteS2.checkNameClaims(inModel, mapped, funcs)...)
	sort.Strings(problems)
	return problems
}

// checkS2Mutations validates the mutation records of one id.
func checkS2Mutations(id string, e s2Entry, lines guardLines) []string {
	var problems []string
	seen := map[string]bool{}
	for i, m := range e.Mutations {
		label := m.ID
		if strings.TrimSpace(m.ID) == "" {
			label = "#" + strconv.Itoa(i+1)
			problems = append(problems, fmt.Sprintf("%s: mutation %s without an id", id, label))
		} else if seen[m.ID] {
			problems = append(problems, fmt.Sprintf("%s: mutation %s listed twice", id, m.ID))
		}
		seen[m.ID] = true
		bad := func(format string, args ...any) {
			problems = append(problems, fmt.Sprintf("%s: mutation %s: ", id, label)+fmt.Sprintf(format, args...))
		}
		if g := s2GuardRe.FindStringSubmatch(m.Guard); g == nil {
			bad("guard %q is not <file>.go:<line>", m.Guard)
		} else if ls, err := lines(g[1]); err != nil {
			bad("guard file %s could not be read: %v", g[1], err)
		} else if line, _ := strconv.Atoi(g[2]); line > len(ls) {
			bad("guard line %d is past the end of %s (%d lines)", line, g[1], len(ls))
		} else if strings.TrimSpace(m.GuardText) != "" {
			if p := guardTextProblem(ls, line, m.GuardText); p != "" {
				bad("guard_text %q %s %s, which reads %q", m.GuardText, p, m.Guard, ls[line-1])
			}
		}
		if strings.TrimSpace(m.GuardText) == "" {
			bad("no guard_text")
		}
		if strings.TrimSpace(m.Mutation) == "" {
			bad("no mutation text")
		}
		if len(m.KilledBy) == 0 {
			bad("no killing test")
		}
		for _, k := range m.KilledBy {
			if !slices.Contains(e.Tests, k) {
				bad("killing test %s is not listed in the tests of %s", k, id)
			}
			name := k[strings.LastIndex(k, ".")+1:]
			if !s2FailedTestRe(name).MatchString(m.Red) {
				bad("red run does not name killing test %s in a \"--- FAIL: %s (\" line", name, name)
			}
		}
		if !s2FailLineRe.MatchString(m.Red) {
			bad("red run does not report FAIL")
		}
		if !s2OKLineRe.MatchString(m.Green) || strings.Contains(m.Green, "FAIL") {
			bad("green run does not report ok without FAIL")
		}
	}
	return problems
}

// guardTextProblem returns why text does not pin line (1-based) of a file
// with lines ls, or "" when it does: text must occur exactly once in the
// file, and that occurrence must cover the line.
func guardTextProblem(ls []string, line int, text string) string {
	file := strings.Join(ls, "\n")
	switch n := strings.Count(file, text); {
	case n > 1:
		return fmt.Sprintf("occurs %d times in the guard file, want once; it does not pin", n)
	case n == 1:
		start := strings.Count(file[:strings.Index(file, text)], "\n") + 1
		if end := start + strings.Count(text, "\n"); line >= start && line <= end {
			return ""
		}
	}
	return "is not on"
}

// openS2Items lists every pending id and every gap of the manifest,
// sorted.
func openS2Items(manifest map[string]s2Entry) []string {
	var out []string
	for id, e := range manifest {
		if e.Status != s2StatusGreen {
			out = append(out, fmt.Sprintf("%s: %s (slice %s, tracked by %s)", id, e.Status, e.Slice, e.TrackedBy))
		}
		for _, g := range e.Gaps {
			out = append(out, fmt.Sprintf("%s: gap %s (tracked by %s)", id, g.Half, g.TrackedBy))
		}
	}
	sort.Strings(out)
	return out
}

// s2ClosingProblems is the extra check of a closing run: nothing open.
func s2ClosingProblems(manifest map[string]s2Entry, closing bool) []string {
	if !closing {
		return nil
	}
	var out []string
	for _, o := range openS2Items(manifest) {
		out = append(out, fmt.Sprintf("%s is set but an S2 item is open: %s", s2GateClosingEnv, o))
	}
	return out
}

// repoGuardLines reads the lines of a file below root.
func repoGuardLines(root string) guardLines {
	return func(path string) ([]string, error) {
		f, err := os.Open(filepath.Join(root, filepath.FromSlash(path)))
		if err != nil {
			return nil, err
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
		var out []string
		for sc.Scan() {
			out = append(out, sc.Text())
		}
		if err := sc.Err(); err != nil {
			return nil, err
		}
		return out, nil
	}
}

// s2TreeProblems runs the S2 gate on the module below root and returns
// its problems and its open items. It reads s2GateClosingEnv itself, so
// the closing mode is tested through the same path the real gate takes.
func s2TreeProblems(t *testing.T, root string) (problems, open []string, ids int) {
	t.Helper()
	doc, err := os.ReadFile(filepath.Join(root, "docs", paThreatModelPath))
	if err != nil {
		t.Fatal(err)
	}
	modelIDs, err := paSuiteS2.threatModelIDs(doc)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "docs", s2ManifestPath))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := parseS2Manifest(raw)
	if err != nil {
		t.Fatalf("%s: %v", s2ManifestPath, err)
	}
	problems = checkS2Manifest(modelIDs, manifest, repoTestFuncs(t, root), repoGuardLines(root))
	problems = append(problems, s2ClosingProblems(manifest, paGateClosing(s2GateClosingEnv))...)
	return problems, openS2Items(manifest), len(modelIDs)
}

// TestPAS2Manifest is the gate check on the real tree.
func TestPAS2Manifest(t *testing.T) {
	problems, open, ids := s2TreeProblems(t, "..")
	t.Logf("S2: %d ids in the threat model, %d open items", ids, len(open))
	for _, o := range open {
		t.Logf("open S2 item: %s", o)
	}
	for _, p := range problems {
		t.Error(p)
	}
}

// s2TreeFixture is a small module with one green and one pending S2 id.
func s2TreeFixture(t *testing.T, guard string) string {
	return writeTree(t, map[string]string{
		"go.mod":                    "module example.com/x\n",
		"docs/" + paThreatModelPath: "- S2-A1: x\n- S2-A2: y\n",
		"docs/" + s2ManifestPath: `S2-A1:
  status: green
  tests: [x.TestS2A1_Thing]
  mutations:
    - id: M1
      guard: ` + guard + `
      guard_text: "func X()"
      mutation: "return nil"
      killed_by: [x.TestS2A1_Thing]
      red: "--- FAIL: TestS2A1_Thing (0.01s)\nFAIL\tx"
      green: "ok  \tx\t0.1s"
S2-A2:
  status: pending
  slice: P2-S2
  tracked_by: "#1"
`,
		"x/x.go":      "package x\n\nfunc X() {}\n",
		"x/x_test.go": "package x\n\nimport \"testing\"\n\nfunc TestS2A1_Thing(t *testing.T) {}\n",
	})
}

// TestPAS2GateClosingEnv proves the closing mode and the guard reads on a
// small tree: a pending id passes a normal run and fails a run with
// PA_S2_GATE_CLOSING set, and a guard past the end of its real file fails.
func TestPAS2GateClosingEnv(t *testing.T) {
	root := s2TreeFixture(t, "x/x.go:3")
	t.Setenv(s2GateClosingEnv, "")
	if p, open, _ := s2TreeProblems(t, root); len(p) != 0 || len(open) != 1 {
		t.Fatalf("normal run: problems %v, open %v; want none and one open item", p, open)
	}
	t.Setenv(s2GateClosingEnv, "1")
	p, _, _ := s2TreeProblems(t, root)
	if !slices.ContainsFunc(p, func(s string) bool {
		return strings.Contains(s, s2GateClosingEnv+" is set but an S2 item is open: S2-A2")
	}) {
		t.Fatalf("closing run: problems %v, want the pending id", p)
	}
	t.Setenv(s2GateClosingEnv, "")
	for guard, want := range map[string]string{
		"x/x.go:4":    "guard line 4 is past the end of x/x.go (3 lines)",
		"x/gone.go:1": "guard file x/gone.go could not be read",
	} {
		p, _, _ := s2TreeProblems(t, s2TreeFixture(t, guard))
		if !slices.ContainsFunc(p, func(s string) bool { return strings.Contains(s, want) }) {
			t.Errorf("guard %s: problems %v, want one containing %q", guard, p, want)
		}
	}
}

func TestRepoGuardLines(t *testing.T) {
	root := writeTree(t, map[string]string{
		"a.go":      "1\n2\n3\n",
		"no_eol.go": "1\n2",
		"empty.go":  "",
		"long.go":   strings.Repeat("x", 200<<10) + "\n2\n",
		"huge.go":   strings.Repeat("x", 2<<20) + "\n",
	})
	lines := repoGuardLines(root)
	for path, want := range map[string]int{"a.go": 3, "no_eol.go": 2, "empty.go": 0, "long.go": 2} {
		if ls, err := lines(path); err != nil || len(ls) != want {
			t.Errorf("%s: %d lines, %v; want %d", path, len(ls), err, want)
		}
	}
	if ls, _ := lines("a.go"); !slices.Equal(ls, []string{"1", "2", "3"}) {
		t.Errorf("a.go: lines %q, want [1 2 3]", ls)
	}
	// A file that cannot be read, or not to the end, is an error, never a
	// count: could not observe is not observed short.
	for _, path := range []string{"gone.go", "huge.go"} {
		if ls, err := lines(path); err == nil {
			t.Errorf("%s: %d lines and no error, want an error", path, len(ls))
		}
	}
}

// s2Fixture is the converged fixture of TestPAS2ManifestCheckDetects.
type s2Fixture struct {
	ids   []string
	m     map[string]s2Entry
	funcs map[string]bool
	// files maps a path to its line count; a negative count is a file
	// that cannot be read. Line n of a file reads "line n", except lines 10
	// and 12 of internal/x/x.go, which hold the guards.
	files map[string]int
	// target is the mutation record mutate edits; mutated records that
	// mutate ran.
	target  int
	mutated bool
}

func newS2Fixture() *s2Fixture {
	return &s2Fixture{
		ids: []string{"S2-A1", "S2-A2"},
		m: map[string]s2Entry{
			"S2-A1": {
				Status: s2StatusGreen,
				Slice:  "P2-S7",
				Tests:  []string{"internal/x.TestS2A1_Thing", "internal/x.TestCovers"},
				Mutations: []s2Mutation{{
					ID:        "M1",
					Guard:     "internal/x/x.go:10",
					GuardText: "return nil // guard M1",
					Mutation:  "return nil",
					KilledBy:  []string{"internal/x.TestS2A1_Thing"},
					Red:       "--- FAIL: TestS2A1_Thing (0.01s)\nFAIL\tinternal/x",
					Green:     "ok  \tinternal/x\t0.1s",
				}, {
					ID:        "M2",
					Guard:     "internal/x/x.go:12",
					GuardText: "\treturn err // guard M2\nline 13",
					Mutation:  "return err -> return nil",
					KilledBy:  []string{"internal/x.TestS2A1_Thing", "internal/x.TestCovers"},
					Red:       "--- FAIL: TestS2A1_Thing (0.01s)\n--- FAIL: TestCovers (0.00s)\nFAIL\nFAIL\tinternal/x\t0.2s\nFAIL",
					Green:     "ok  \tinternal/x\t0.1s",
				}},
			},
			"S2-A2": {Status: s2StatusPending, Slice: "P2-S2", TrackedBy: "#1320"},
		},
		funcs: map[string]bool{
			"internal/x.TestS2A1_Thing": true,
			"internal/x.TestCovers":     true,
			"internal/y.TestUnrelated":  true,
		},
		files: map[string]int{"internal/x/x.go": 20},
	}
}

func (f *s2Fixture) lines(path string) ([]string, error) {
	n, ok := f.files[path]
	if !ok {
		return nil, fmt.Errorf("open %s: no such file", path)
	}
	if n < 0 {
		return nil, fmt.Errorf("read %s: permission denied", path)
	}
	out := make([]string, n)
	for i := range out {
		out[i] = "line " + strconv.Itoa(i+1)
	}
	if path == "internal/x/x.go" {
		out[9], out[11] = "\treturn nil // guard M1", "\treturn err // guard M2"
	}
	return out, nil
}

func (f *s2Fixture) check() []string { return checkS2Manifest(f.ids, f.m, f.funcs, f.lines) }

// green returns the green entry S2-A1 for editing; set stores it back.
func (f *s2Fixture) green() s2Entry { return f.m["S2-A1"] }
func (f *s2Fixture) set(e s2Entry)  { f.m["S2-A1"] = e }

// mutate edits the mutation record of S2-A1 that the case targets
// (f.target): each malformed-record case runs against the first record and
// against a later one, so a check that stops at the first record fails.
func (f *s2Fixture) mutate(edit func(*s2Mutation)) {
	e := f.green()
	ms := slices.Clone(e.Mutations)
	edit(&ms[f.target])
	f.mutated = true
	e.Mutations = ms
	f.set(e)
}

// TestPAS2ManifestCheckDetects proves the check both ways on a small
// fixture: green when converged, red on each kind of break.
func TestPAS2ManifestCheckDetects(t *testing.T) {
	if p := newS2Fixture().check(); len(p) != 0 {
		t.Fatalf("converged fixture reported: %v", p)
	}
	if p := s2ClosingProblems(map[string]s2Entry{"S2-A1": newS2Fixture().green()}, true); len(p) != 0 {
		t.Fatalf("closing run on a fully green manifest reported: %v", p)
	}
	cases := []struct {
		name    string
		breakIt func(f *s2Fixture)
		want    string
	}{
		// The manifest and the threat model.
		{"manifest id not a threat model row", func(f *s2Fixture) {
			f.m["S2-Z9"] = s2Entry{Status: s2StatusPending, Slice: "P2-S2", TrackedBy: "#1320"}
		}, "S2-Z9: in the manifest but not an S2 id"},
		{"id removed from the threat model", func(f *s2Fixture) { f.ids = f.ids[:1] },
			"S2-A2: in the manifest but not an S2 id"},
		{"threat model row missing from the manifest", func(f *s2Fixture) { delete(f.m, "S2-A2") },
			"S2-A2: an S2 row of the threat model missing"},
		{"new threat model row", func(f *s2Fixture) { f.ids = append(f.ids, "S2-A3") },
			"S2-A3: an S2 row of the threat model missing"},
		{"unknown status", func(f *s2Fixture) {
			f.m["S2-A2"] = s2Entry{Status: "done", Slice: "P2-S2", TrackedBy: "#1320"}
		}, `S2-A2: status "done"`},
		{"no status", func(f *s2Fixture) {
			f.m["S2-A2"] = s2Entry{Slice: "P2-S2", TrackedBy: "#1320"}
		}, `S2-A2: status ""`},
		// Test names.
		{"test claims an id not in the threat model", func(f *s2Fixture) { f.funcs["internal/x.TestS2Q7_Ghost"] = true },
			"claims S2-Q7, which is not an S2 id"},
		{"test claims a pending id it is not listed under", func(f *s2Fixture) { f.funcs["internal/x.TestS2A2_Early"] = true },
			"claims S2-A2 but the manifest does not list it"},
		{"test claims an id it is not listed under", func(f *s2Fixture) {
			e := f.green()
			e.Tests = []string{"internal/x.TestCovers"}
			e.Mutations = nil
			f.set(e)
		}, "claims S2-A1 but the manifest does not list it"},
		{"test claims an id missing from the manifest", func(f *s2Fixture) { delete(f.m, "S2-A1") },
			"claims S2-A1 but the manifest does not list it"},
		// Test references.
		{"referenced test does not exist", func(f *s2Fixture) {
			delete(f.funcs, "internal/x.TestCovers")
			f.funcs["internal/x.TestCoversRenamed"] = true
		}, "S2-A1: test internal/x.TestCovers does not exist"},
		{"pending id lists a test that does not exist", func(f *s2Fixture) {
			e := f.m["S2-A2"]
			e.Tests = []string{"internal/x.TestGone"}
			f.m["S2-A2"] = e
		}, "S2-A2: test internal/x.TestGone does not exist"},
		{"malformed test reference", func(f *s2Fixture) {
			e := f.green()
			e.Tests = append(slices.Clone(e.Tests), "TestCovers")
			f.set(e)
		}, `S2-A1: "TestCovers" is not`},
		{"test listed twice", func(f *s2Fixture) {
			e := f.green()
			e.Tests = append(slices.Clone(e.Tests), "internal/x.TestCovers")
			f.set(e)
		}, "S2-A1: test internal/x.TestCovers listed twice"},
		// Green ids.
		{"green without a test", func(f *s2Fixture) {
			delete(f.funcs, "internal/x.TestS2A1_Thing")
			e := f.green()
			e.Tests = nil
			e.Mutations = nil
			f.set(e)
		}, "S2-A1: green without a test"},
		{"green without a mutation record", func(f *s2Fixture) {
			e := f.green()
			e.Mutations = nil
			f.set(e)
		}, "S2-A1: green without a mutation record"},
		{"green with tracked_by", func(f *s2Fixture) {
			e := f.green()
			e.TrackedBy = "#1321"
			f.set(e)
		}, `S2-A1: green but tracked_by "#1321"`},
		{"malformed slice", func(f *s2Fixture) {
			e := f.green()
			e.Slice = "S7"
			f.set(e)
		}, `S2-A1: slice "S7" is not P2-S<n>`},
		{"slice with trailing text", func(f *s2Fixture) {
			e := f.green()
			e.Slice = "P2-S7x"
			f.set(e)
		}, `S2-A1: slice "P2-S7x" is not P2-S<n>`},
		// Malformed mutation records.
		{"mutation without an id", func(f *s2Fixture) { f.mutate(func(m *s2Mutation) { m.ID = "" }) },
			"S2-A1: mutation #1 without an id"},
		{"mutation id twice", func(f *s2Fixture) {
			e := f.green()
			e.Mutations = append(slices.Clone(e.Mutations), e.Mutations[0])
			f.set(e)
		}, "S2-A1: mutation M1 listed twice"},
		{"guard without a line", func(f *s2Fixture) { f.mutate(func(m *s2Mutation) { m.Guard = "internal/x/x.go" }) },
			`guard "internal/x/x.go" is not <file>.go:<line>`},
		{"guard line zero", func(f *s2Fixture) { f.mutate(func(m *s2Mutation) { m.Guard = "internal/x/x.go:0" }) },
			"is not <file>.go:<line>"},
		{"guard that is prose", func(f *s2Fixture) { f.mutate(func(m *s2Mutation) { m.Guard = "the taint read" }) },
			"is not <file>.go:<line>"},
		{"guard file missing", func(f *s2Fixture) { f.mutate(func(m *s2Mutation) { m.Guard = "internal/x/gone.go:3" }) },
			"guard file internal/x/gone.go could not be read"},
		{"guard file unreadable", func(f *s2Fixture) {
			f.files["internal/x/x.go"] = -1
		}, "guard file internal/x/x.go could not be read"},
		{"guard line past the end", func(f *s2Fixture) { f.mutate(func(m *s2Mutation) { m.Guard = "internal/x/x.go:21" }) },
			"guard line 21 is past the end"},
		{"no guard_text", func(f *s2Fixture) { f.mutate(func(m *s2Mutation) { m.GuardText = " " }) },
			"mutation M1: no guard_text"},
		{"no guard_text on a malformed guard", func(f *s2Fixture) {
			f.mutate(func(m *s2Mutation) { m.Guard, m.GuardText = "the taint read", "" })
		}, "mutation M1: no guard_text"},
		{"guard_text missing from the guard line", func(f *s2Fixture) {
			f.mutate(func(m *s2Mutation) { m.GuardText = "return tainted, nil" })
		}, `mutation M1: guard_text "return tainted, nil" is not on internal/x/x.go:`},
		{"guard line drifted to another line", func(f *s2Fixture) {
			f.mutate(func(m *s2Mutation) { m.Guard = "internal/x/x.go:11" })
		}, `is not on internal/x/x.go:11, which reads "line 11"`},
		{"guard_text twice in the guard file", func(f *s2Fixture) {
			f.mutate(func(m *s2Mutation) { m.GuardText = "return" })
		}, `guard_text "return" occurs 2 times in the guard file, want once`},
		{"multi-line guard_text that ends before the guard line", func(f *s2Fixture) {
			f.mutate(func(m *s2Mutation) { m.Guard, m.GuardText = "internal/x/x.go:13", "line 11\n\treturn err // guard M2" })
		}, `is not on internal/x/x.go:13`},
		{"multi-line guard_text that starts after the guard line", func(f *s2Fixture) {
			f.mutate(func(m *s2Mutation) { m.Guard, m.GuardText = "internal/x/x.go:10", "line 11\n\treturn err // guard M2" })
		}, `is not on internal/x/x.go:10`},
		{"no mutation text", func(f *s2Fixture) { f.mutate(func(m *s2Mutation) { m.Mutation = " " }) },
			"mutation M1: no mutation text"},
		{"no killing test", func(f *s2Fixture) { f.mutate(func(m *s2Mutation) { m.KilledBy = nil }) },
			"mutation M1: no killing test"},
		{"killing test not listed under the id", func(f *s2Fixture) {
			f.mutate(func(m *s2Mutation) { m.KilledBy = []string{"internal/y.TestUnrelated"} })
		}, "killing test internal/y.TestUnrelated is not listed in the tests of S2-A1"},
		{"killing test that does not exist", func(f *s2Fixture) {
			f.mutate(func(m *s2Mutation) { m.KilledBy = []string{"internal/x.TestS2A1_Gone"} })
		}, "killing test internal/x.TestS2A1_Gone is not listed"},
		{"red run empty", func(f *s2Fixture) { f.mutate(func(m *s2Mutation) { m.Red = "" }) },
			"red run does not report FAIL"},
		{"red run that passed", func(f *s2Fixture) {
			f.mutate(func(m *s2Mutation) { m.Red = "--- PASS: TestS2A1_Thing (0.01s)\nok\tinternal/x" })
		}, "red run does not report FAIL"},
		{"red run not naming the killing test", func(f *s2Fixture) {
			f.mutate(func(m *s2Mutation) { m.Red = "--- FAIL: TestOther (0.01s)\nFAIL\tinternal/x" })
		}, "red run does not name killing test TestS2A1_Thing"},
		{"red run naming only a longer test name", func(f *s2Fixture) {
			f.mutate(func(m *s2Mutation) {
				m.Red = "--- FAIL: TestS2A1_ThingElse (0.01s)\n--- FAIL: TestCovers (0.00s)\nFAIL\tinternal/x"
			})
		}, "red run does not name killing test TestS2A1_Thing"},
		{"red run naming the test outside a FAIL line", func(f *s2Fixture) {
			f.mutate(func(m *s2Mutation) {
				m.Red = "TestS2A1_Thing TestCovers should fail\n--- FAIL: TestOther (0.01s)\nFAIL\tinternal/x"
			})
		}, "red run does not name killing test TestS2A1_Thing"},
		{"red run with FAIL only inside a word", func(f *s2Fixture) {
			f.mutate(func(m *s2Mutation) {
				m.Red = "--- FAIL: TestS2A1_Thing (0.01s)\n--- FAIL: TestCovers (0.00s)\nFAILED to restore"
			})
		}, "red run does not report FAIL"},
		{"green run empty", func(f *s2Fixture) { f.mutate(func(m *s2Mutation) { m.Green = "" }) },
			"green run does not report ok"},
		{"green run that failed", func(f *s2Fixture) { f.mutate(func(m *s2Mutation) { m.Green = "FAIL\tinternal/x" }) },
			"green run does not report ok"},
		{"green run with ok only inside a word", func(f *s2Fixture) { f.mutate(func(m *s2Mutation) { m.Green = "broken token" }) },
			"green run does not report ok"},
		{"green run that reports ok and a FAIL", func(f *s2Fixture) {
			f.mutate(func(m *s2Mutation) {
				m.Green = "--- FAIL: TestS2A1_Thing (0.01s)\nok  \tinternal/y\t0.1s\nFAIL\tinternal/x"
			})
		}, "green run does not report ok without FAIL"},
		{"malformed mutation on a pending id", func(f *s2Fixture) {
			e := f.m["S2-A2"]
			e.Mutations = []s2Mutation{{ID: "P1"}}
			f.m["S2-A2"] = e
		}, "S2-A2: mutation P1: guard"},
		// Pending ids.
		{"pending without a slice", func(f *s2Fixture) {
			f.m["S2-A2"] = s2Entry{Status: s2StatusPending, TrackedBy: "#1320"}
		}, "S2-A2: pending without a slice"},
		{"pending without tracked_by", func(f *s2Fixture) {
			f.m["S2-A2"] = s2Entry{Status: s2StatusPending, Slice: "P2-S2"}
		}, "S2-A2: pending but not tracked by an issue"},
		{"pending tracked by prose", func(f *s2Fixture) {
			f.m["S2-A2"] = s2Entry{Status: s2StatusPending, Slice: "P2-S2", TrackedBy: "later"}
		}, "S2-A2: pending but not tracked by an issue"},
		{"pending with a malformed slice", func(f *s2Fixture) {
			f.m["S2-A2"] = s2Entry{Status: s2StatusPending, Slice: "slice 2", TrackedBy: "#1320"}
		}, `S2-A2: slice "slice 2" is not P2-S<n>`},
		{"pending with two slices", func(f *s2Fixture) {
			f.m["S2-A2"] = s2Entry{Status: s2StatusPending, Slice: "P2-S5/P2-S11", TrackedBy: "#1320"}
		}, `S2-A2: slice "P2-S5/P2-S11" is not P2-S<n>`},
		{"pending with gaps", func(f *s2Fixture) {
			f.m["S2-A2"] = s2Entry{Status: s2StatusPending, Slice: "P2-S2", TrackedBy: "#1320",
				Gaps: []paGap{{Half: "x", TrackedBy: "#1320"}}}
		}, "S2-A2: pending with gaps"},
		// Gaps.
		{"gap without tracked_by", func(f *s2Fixture) {
			e := f.green()
			e.Gaps = []paGap{{Half: "card gate"}}
			f.set(e)
		}, `S2-A1: gap "card gate" is not tracked by an issue`},
		{"gap without a half", func(f *s2Fixture) {
			e := f.green()
			e.Gaps = []paGap{{TrackedBy: "#1321"}}
			f.set(e)
		}, "S2-A1: a gap without a half"},
	}
	for _, tc := range cases {
		for target := range newS2Fixture().green().Mutations {
			f := newS2Fixture()
			f.target = target
			tc.breakIt(f)
			if target > 0 && !f.mutated {
				continue // the case does not edit a record: one run is enough
			}
			want := tc.want
			if f.mutated {
				id := f.green().Mutations[target].ID
				if id == "" {
					id = "#" + strconv.Itoa(target+1)
				}
				want = strings.NewReplacer("mutation M1", "mutation "+id, "mutation #1", "mutation "+id).Replace(want)
			}
			t.Run(fmt.Sprintf("%s/record %d", tc.name, target+1), func(t *testing.T) {
				got := f.check()
				if !slices.ContainsFunc(got, func(p string) bool { return strings.Contains(p, want) }) {
					t.Fatalf("problems %v, want one containing %q", got, want)
				}
			})
		}
	}
	// The closing mode: a pending id or a gap fails a closing run, and the
	// same manifest passes a run that is not closing.
	for name, m := range map[string]map[string]s2Entry{
		"pending id": newS2Fixture().m,
		"open gap": {"S2-A1": func() s2Entry {
			e := newS2Fixture().green()
			e.Gaps = []paGap{{Half: "card gate", TrackedBy: "#1321"}}
			return e
		}()},
	} {
		t.Run("closing with "+name, func(t *testing.T) {
			if p := s2ClosingProblems(m, false); len(p) != 0 {
				t.Fatalf("a run that is not closing reported %v", p)
			}
			if p := s2ClosingProblems(m, true); len(p) == 0 || !strings.Contains(p[0], s2GateClosingEnv+" is set but an S2 item is open") {
				t.Fatalf("closing run reported %v, want an open item", p)
			}
		})
	}
}

func TestPAS2ThreatModelRows(t *testing.T) {
	for name, tc := range map[string]struct{ doc, want string }{
		"indented row":             {"- S2-A1: x\n  - S2-A2: y\n", "S2-A2"},
		"bold row":                 {"- S2-A1: x\n- **S2-A2**: y\n", "S2-A2"},
		"table cell":               {"- S2-A1: x\n| S2-A2 | y |\n", "S2-A2"},
		"prose":                    {"- S2-A1: x\nSee S2-A2 below.\n", "S2-A2"},
		"unicode dash":             {"- S2-A1: x\n- S2\u2011A2: y\n", "S2\u2011A2"},
		"en dash":                  {"- S2-A1: x\n- S2\u2013A2: y\n", "S2\u2013A2"},
		"no digit":                 {"- S2-A1: x\n- S2-Z: z\n", "S2-Z"},
		"letter tail":              {"- S2-A1: x\n- S2-A2b: y\n", "S2-A2b"},
		"underscore":               {"- S2-A1: x\n- S2_A2: y\n", "S2_A2"},
		"minus sign":               {"- S2-A1: x\n- S2\u2212A2: y\n", "S2\u2212A2"},
		"hyphen bullet":            {"- S2-A1: x\n- S2\u2043A2: y\n", "S2\u2043A2"},
		"small hyphen-minus":       {"- S2-A1: x\n- S2\uFE63A2: y\n", "S2\uFE63A2"},
		"standalone underscore id": {"- S2-A1: x\nsee S2_I8 there\n", "S2_I8"},
		"at the start of the text": {"S2_I8 first\n- S2-A1: x\n", "S2_I8"},
		"after punctuation":        {"- S2-A1: x\n(S2-A2) and -S2-A3\n", "S2-A2, S2-A3"},
		"italic row":               {"- S2-A1: x\n- _S2-A2_: y\n", "S2-A2"},
		"bold underscore row":      {"- S2-A1: x\n- __S2-A2__: y\n", "S2-A2"},
	} {
		if _, err := paSuiteS2.threatModelIDs([]byte(tc.doc)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err %v, want one naming %s", name, err, tc.want)
		}
	}
	// An identifier that holds the suite name after a letter, digit or
	// underscore is not a mention: PA_S2_GATE_CLOSING is not the id S2_GATE.
	for name, doc := range map[string]string{
		"env name":       "- S2-A1: x\nSet PA_S2_GATE_CLOSING=1 to close.\n",
		"letter prefix":  "- S2-A1: x\nthe XS2-A9 part\n",
		"digit prefix":   "- S2-A1: x\nversion 1S2-A9\n",
		"in a code span": "- S2-A1: x\n`PA_S2_GATE_CLOSING`\n",
	} {
		if ids, err := paSuiteS2.threatModelIDs([]byte(doc)); err != nil || !slices.Equal(ids, []string{"S2-A1"}) {
			t.Errorf("%s: ids %v, err %v; want [S2-A1] and no error", name, ids, err)
		}
	}
	// The S1 suite shares the check.
	if _, err := paSuiteS1.threatModelIDs([]byte("- S1-A1: x\n- _S1-N5_: y\n")); err == nil || !strings.Contains(err.Error(), "S1-N5") {
		t.Errorf("S1: an italic row accepted: err %v, want one naming S1-N5", err)
	}
	if _, err := paSuiteS1.threatModelIDs([]byte("- S1-A1: x\n- S1\u2011A2: y\n")); err == nil {
		t.Error("S1: a row with a Unicode dash accepted")
	}
	if _, err := paSuiteS2.threatModelIDs([]byte("- S2-A1: x\n- S2-A1: y\n")); err == nil {
		t.Error("repeated threat model id accepted")
	}
	if _, err := paSuiteS2.threatModelIDs([]byte("- S1-A1: only S1 rows here\n")); err == nil {
		t.Error("a threat model with no S2 row accepted")
	}
	// The S2 suite reads S2 rows only, and S1 rows only S1.
	doc := []byte("- S1-A1: x\n- S2-A1: y, see S1-A1\n")
	if ids, err := paSuiteS2.threatModelIDs(doc); err != nil || !slices.Equal(ids, []string{"S2-A1"}) {
		t.Errorf("S2 ids %v %v, want [S2-A1]", ids, err)
	}
	if ids, err := paSuiteS1.threatModelIDs(doc); err != nil || !slices.Equal(ids, []string{"S1-A1"}) {
		t.Errorf("S1 ids %v %v, want [S1-A1]", ids, err)
	}
}

func TestS2NameClaims(t *testing.T) {
	for name, want := range map[string][]string{
		"TestS2I6_TaintSurvivesTurnsSummaryAndEviction": {"S2-I6"},
		"TestS2I10_TaintReadErrorMeansTainted":          {"S2-I10"},
		"TestApproval_S2A1A3_ReplayAndArgs":             {"S2-A1", "S2-A3"},
		"TestS2_A1_UnderscoreEscape":                    {"S2-A1"},
		"TestApproval_S2_A1A3_Underscore":               {"S2-A1", "S2-A3"},
		"TestS2_Plain":                                  nil,
		"TestS1E1E2_CheckURLLayer":                      nil,
		"TestAuthenticate_HS256Refused":                 nil,
		"TestVerifyAssertionES256":                      nil,
	} {
		if got := paSuiteS2.nameClaims(name); !slices.Equal(got, want) {
			t.Errorf("%s claims %v, want %v", name, got, want)
		}
	}
}

func TestParseS2ManifestStrict(t *testing.T) {
	if _, err := parseS2Manifest([]byte("S2-A1:\n  status: pending\nS2-A1:\n  status: green\n")); err == nil {
		t.Error("duplicate id accepted")
	}
	if _, err := parseS2Manifest([]byte("S2-A1:\n  status: pending\n  owner: \"#1\"\n")); err == nil {
		t.Error("unknown field accepted")
	}
	if _, err := parseS2Manifest([]byte("S2-A1:\n  status: green\n  mutations:\n    - id: M1\n      killed: [a.TestX]\n")); err == nil {
		t.Error("unknown mutation field accepted")
	}
	for name, raw := range map[string]string{"empty": "", "comments only": "# nothing\n", "null": "null\n"} {
		if _, err := parseS2Manifest([]byte(raw)); err == nil {
			t.Errorf("%s manifest accepted", name)
		}
	}
}

func TestOpenS2Items(t *testing.T) {
	got := openS2Items(map[string]s2Entry{
		"S2-B1": {Status: s2StatusPending, Slice: "P2-S2", TrackedBy: "#1320"},
		"S2-A1": {Status: s2StatusGreen, Gaps: []paGap{{Half: "a", TrackedBy: "#1321"}}},
		"S2-C1": {Status: s2StatusGreen},
	})
	want := []string{"S2-A1: gap a (tracked by #1321)", "S2-B1: pending (slice P2-S2, tracked by #1320)"}
	if !slices.Equal(got, want) {
		t.Fatalf("open items %v, want %v", got, want)
	}
}
