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
	Guard    string   `yaml:"guard"`
	Mutation string   `yaml:"mutation"`
	KilledBy []string `yaml:"killed_by"`
	// Red is the evidence of the mutated run: it names every killing test
	// and reports FAIL. Green is the evidence of the restored run.
	Red   string `yaml:"red"`
	Green string `yaml:"green"`
}

var (
	s2SliceRe = regexp.MustCompile(`^P2-S[0-9]+$`)
	s2GuardRe = regexp.MustCompile(`^([a-z0-9_/.-]+\.go):([1-9][0-9]*)$`)
)

// guardLines returns the number of lines of a repository file, for a
// guard reference. An error means the file could not be read.
type guardLines func(path string) (int, error)

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
		} else if n, err := lines(g[1]); err != nil {
			bad("guard file %s could not be read: %v", g[1], err)
		} else if line, _ := strconv.Atoi(g[2]); line > n {
			bad("guard line %d is past the end of %s (%d lines)", line, g[1], n)
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
			if !strings.Contains(m.Red, name) {
				bad("red run does not name killing test %s", name)
			}
		}
		if !strings.Contains(m.Red, "FAIL") {
			bad("red run does not report FAIL")
		}
		if !strings.Contains(m.Green, "ok") || strings.Contains(m.Green, "FAIL") {
			bad("green run does not report ok without FAIL")
		}
	}
	return problems
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

// repoGuardLines counts the lines of a file below root.
func repoGuardLines(root string) guardLines {
	return func(path string) (int, error) {
		f, err := os.Open(filepath.Join(root, filepath.FromSlash(path)))
		if err != nil {
			return 0, err
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
		n := 0
		for sc.Scan() {
			n++
		}
		if err := sc.Err(); err != nil {
			return 0, err
		}
		return n, nil
	}
}

// TestPAS2Manifest is the gate check on the real tree.
func TestPAS2Manifest(t *testing.T) {
	doc, err := os.ReadFile(paThreatModelPath)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := paSuiteS2.threatModelIDs(doc)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(s2ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := parseS2Manifest(raw)
	if err != nil {
		t.Fatalf("%s: %v", s2ManifestPath, err)
	}
	for _, p := range checkS2Manifest(ids, manifest, repoTestFuncs(t, ".."), repoGuardLines("..")) {
		t.Error(p)
	}
	open := openS2Items(manifest)
	t.Logf("S2: %d ids in the threat model, %d open items", len(ids), len(open))
	for _, o := range open {
		t.Logf("open S2 item: %s", o)
	}
	for _, p := range s2ClosingProblems(manifest, os.Getenv(s2GateClosingEnv) != "") {
		t.Error(p)
	}
}

// s2Fixture is the converged fixture of TestPAS2ManifestCheckDetects.
type s2Fixture struct {
	ids   []string
	m     map[string]s2Entry
	funcs map[string]bool
	files map[string]int
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
					ID:       "M1",
					Guard:    "internal/x/x.go:10",
					Mutation: "return nil",
					KilledBy: []string{"internal/x.TestS2A1_Thing"},
					Red:      "--- FAIL: TestS2A1_Thing (0.01s)\nFAIL\tinternal/x",
					Green:    "ok  \tinternal/x\t0.1s",
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

func (f *s2Fixture) lines(path string) (int, error) {
	n, ok := f.files[path]
	if !ok {
		return 0, fmt.Errorf("open %s: no such file", path)
	}
	if n < 0 {
		return 0, fmt.Errorf("read %s: permission denied", path)
	}
	return n, nil
}

func (f *s2Fixture) check() []string { return checkS2Manifest(f.ids, f.m, f.funcs, f.lines) }

// green returns the green entry S2-A1 for editing; set stores it back.
func (f *s2Fixture) green() s2Entry { return f.m["S2-A1"] }
func (f *s2Fixture) set(e s2Entry)  { f.m["S2-A1"] = e }

// mutate edits the first mutation record of S2-A1.
func (f *s2Fixture) mutate(edit func(*s2Mutation)) {
	e := f.green()
	ms := slices.Clone(e.Mutations)
	edit(&ms[0])
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
		{"green run empty", func(f *s2Fixture) { f.mutate(func(m *s2Mutation) { m.Green = "" }) },
			"green run does not report ok"},
		{"green run that failed", func(f *s2Fixture) { f.mutate(func(m *s2Mutation) { m.Green = "FAIL\tinternal/x" }) },
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
		t.Run(tc.name, func(t *testing.T) {
			f := newS2Fixture()
			tc.breakIt(f)
			got := f.check()
			if !slices.ContainsFunc(got, func(p string) bool { return strings.Contains(p, tc.want) }) {
				t.Fatalf("problems %v, want one containing %q", got, tc.want)
			}
		})
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
	for name, doc := range map[string]string{
		"indented row": "- S2-A1: x\n  - S2-A2: y\n",
		"bold row":     "- S2-A1: x\n- **S2-A2**: y\n",
		"table cell":   "- S2-A1: x\n| S2-A2 | y |\n",
		"prose":        "- S2-A1: x\nSee S2-A2 below.\n",
	} {
		if _, err := paSuiteS2.threatModelIDs([]byte(doc)); err == nil || !strings.Contains(err.Error(), "S2-A2") {
			t.Errorf("%s: err %v, want one naming S2-A2", name, err)
		}
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
