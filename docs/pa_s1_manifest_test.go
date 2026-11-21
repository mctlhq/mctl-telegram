package docs

// The S1 gate check of the Personal Assistant threat model ("Gate
// evidence", #1317): docs/agent-runtime/pa-s1-manifest.yaml maps every S1
// test id to the test functions that cover it, and this test keeps the
// manifest, the threat model and the test code in step.

import (
	"bytes"
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const s1ManifestPath = "agent-runtime/pa-s1-manifest.yaml"

type s1Entry struct {
	Note  string   `yaml:"note"`
	Tests []string `yaml:"tests"`
	// Gaps are the parts of the row that have no guard yet, so no test
	// can cover them. Each names the issue that will build it. The gate
	// accepts an id with gaps only while they are tracked, and refuses any
	// gap when PA_S1_GATE_CLOSING is set.
	Gaps []s1Gap `yaml:"gaps"`
}

type s1Gap = paGap

// s1GateClosingEnv marks a run that is closing the S1 gate (#1317 or the
// preview gate of #1318): any listed gap then fails the gate.
const s1GateClosingEnv = "PA_S1_GATE_CLOSING"

// threatModelS1IDs returns the S1 ids of the threat model, in order. A
// repeated id is an error.
func threatModelS1IDs(doc []byte) ([]string, error) {
	return paSuiteS1.threatModelIDs(doc)
}

// parseS1Manifest decodes the manifest strictly: an unknown field or a
// duplicate id is an error, not an entry that silently drops.
func parseS1Manifest(raw []byte) (map[string]s1Entry, error) {
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	var m map[string]s1Entry
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	return m, nil
}

// s1NameClaims returns the S1 ids a test function name claims.
func s1NameClaims(name string) []string {
	return paSuiteS1.nameClaims(name)
}

// checkS1Manifest returns every disagreement between the threat model's
// ids, the manifest and the test functions that exist (funcs, as
// "<package dir>.<TestFunc>"). An empty result is the converged state.
func checkS1Manifest(ids []string, manifest map[string]s1Entry, funcs map[string]bool) []string {
	var problems []string
	inModel := map[string]bool{}
	for _, id := range ids {
		inModel[id] = true
		e, ok := manifest[id]
		if !ok || len(e.Tests) == 0 {
			problems = append(problems, fmt.Sprintf("%s: no test mapped in %s", id, s1ManifestPath))
		}
	}
	mapped := map[string]map[string]bool{}
	for id, e := range manifest {
		if !inModel[id] {
			problems = append(problems, fmt.Sprintf("%s: in the manifest but not an S1 id of the threat model", id))
		}
		mapped[id] = map[string]bool{}
		problems = append(problems, checkGaps(id, e.Gaps)...)
		problems = append(problems, checkTestRefs(id, e.Tests, funcs, mapped[id])...)
	}
	problems = append(problems, paSuiteS1.checkNameClaims(inModel, mapped, funcs)...)
	sort.Strings(problems)
	return problems
}

// TestPAS1Manifest is the gate check on the real tree.
func TestPAS1Manifest(t *testing.T) {
	doc, err := os.ReadFile(paThreatModelPath)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := threatModelS1IDs(doc)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(s1ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := parseS1Manifest(raw)
	if err != nil {
		t.Fatalf("%s: %v", s1ManifestPath, err)
	}
	for _, p := range checkS1Manifest(ids, manifest, repoTestFuncs(t, "..")) {
		t.Error(p)
	}
	gaps := openS1Gaps(manifest)
	for _, g := range gaps {
		t.Logf("open S1 gap: %s", g)
	}
	if os.Getenv(s1GateClosingEnv) != "" {
		for _, g := range gaps {
			t.Errorf("%s is set but an S1 gap is open: %s", s1GateClosingEnv, g)
		}
	}
}

// openS1Gaps lists every gap of the manifest as "S1-XX: half (tracked by
// #NNNN)", sorted.
func openS1Gaps(manifest map[string]s1Entry) []string {
	var out []string
	for id, e := range manifest {
		for _, g := range e.Gaps {
			out = append(out, fmt.Sprintf("%s: %s (tracked by %s)", id, g.Half, g.TrackedBy))
		}
	}
	sort.Strings(out)
	return out
}

// TestPAS1ManifestCheckDetects proves the check both ways on a small
// fixture: green when converged, red on each kind of break.
func TestPAS1ManifestCheckDetects(t *testing.T) {
	ids := []string{"S1-A1", "S1-A2"}
	funcs := map[string]bool{
		"internal/x.TestX_S1A1_Thing": true,
		"internal/x.TestCovers":       true,
		"internal/y.TestUnrelated":    true,
	}
	converged := func() map[string]s1Entry {
		return map[string]s1Entry{
			"S1-A1": {Tests: []string{"internal/x.TestX_S1A1_Thing"}},
			"S1-A2": {Tests: []string{"internal/x.TestCovers"}},
		}
	}
	if p := checkS1Manifest(ids, converged(), funcs); len(p) != 0 {
		t.Fatalf("converged fixture reported: %v", p)
	}
	cases := []struct {
		name   string
		mutate func(ids []string, m map[string]s1Entry, f map[string]bool) []string
		want   string
	}{
		{"id with no mapping", func(ids []string, m map[string]s1Entry, f map[string]bool) []string {
			delete(m, "S1-A2")
			return ids
		}, "S1-A2: no test mapped"},
		{"id with an empty list", func(ids []string, m map[string]s1Entry, f map[string]bool) []string {
			m["S1-A2"] = s1Entry{}
			return ids
		}, "S1-A2: no test mapped"},
		{"new threat model id", func(ids []string, m map[string]s1Entry, f map[string]bool) []string {
			return append(ids, "S1-A3")
		}, "S1-A3: no test mapped"},
		{"renamed test", func(ids []string, m map[string]s1Entry, f map[string]bool) []string {
			delete(f, "internal/x.TestCovers")
			f["internal/x.TestCoversRenamed"] = true
			return ids
		}, "S1-A2: test internal/x.TestCovers does not exist"},
		{"test moved to another package", func(ids []string, m map[string]s1Entry, f map[string]bool) []string {
			m["S1-A2"] = s1Entry{Tests: []string{"internal/y.TestCovers"}}
			return ids
		}, "S1-A2: test internal/y.TestCovers does not exist"},
		{"malformed reference", func(ids []string, m map[string]s1Entry, f map[string]bool) []string {
			m["S1-A2"] = s1Entry{Tests: []string{"TestCovers"}}
			return ids
		}, `S1-A2: "TestCovers" is not`},
		{"duplicate reference", func(ids []string, m map[string]s1Entry, f map[string]bool) []string {
			m["S1-A2"] = s1Entry{Tests: []string{"internal/x.TestCovers", "internal/x.TestCovers"}}
			return ids
		}, "listed twice"},
		{"manifest id not in the threat model", func(ids []string, m map[string]s1Entry, f map[string]bool) []string {
			m["S1-Z9"] = s1Entry{Tests: []string{"internal/x.TestCovers"}}
			return ids
		}, "S1-Z9: in the manifest but not an S1 id"},
		{"id removed from the threat model", func(ids []string, m map[string]s1Entry, f map[string]bool) []string {
			return ids[:1]
		}, "S1-A2: in the manifest but not an S1 id"},
		{"test claims an unknown id", func(ids []string, m map[string]s1Entry, f map[string]bool) []string {
			f["internal/x.TestX_S1Q7_Ghost"] = true
			return ids
		}, "claims S1-Q7, which is not an S1 id"},
		{"test claims an id it is not mapped to", func(ids []string, m map[string]s1Entry, f map[string]bool) []string {
			f["internal/x.TestX_S1A2_Unlisted"] = true
			return ids
		}, "claims S1-A2 but the manifest does not list it"},
		{"test mapped under the wrong id", func(ids []string, m map[string]s1Entry, f map[string]bool) []string {
			m["S1-A1"] = s1Entry{Tests: []string{"internal/x.TestCovers"}}
			m["S1-A2"] = s1Entry{Tests: []string{"internal/x.TestX_S1A1_Thing"}}
			return ids
		}, "claims S1-A1 but the manifest does not list it"},
		{"gap without tracked_by", func(ids []string, m map[string]s1Entry, f map[string]bool) []string {
			m["S1-A2"] = s1Entry{Tests: []string{"internal/x.TestCovers"}, Gaps: []s1Gap{{Half: "principal disable"}}}
			return ids
		}, `S1-A2: gap "principal disable" is not tracked by an issue`},
		{"gap tracked by prose", func(ids []string, m map[string]s1Entry, f map[string]bool) []string {
			m["S1-A2"] = s1Entry{Tests: []string{"internal/x.TestCovers"}, Gaps: []s1Gap{{Half: "principal disable", TrackedBy: "later"}}}
			return ids
		}, "is not tracked by an issue"},
		{"gap without a half", func(ids []string, m map[string]s1Entry, f map[string]bool) []string {
			m["S1-A2"] = s1Entry{Tests: []string{"internal/x.TestCovers"}, Gaps: []s1Gap{{TrackedBy: "#1"}}}
			return ids
		}, "S1-A2: a gap without a half"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := converged()
			f := map[string]bool{}
			for k, v := range funcs {
				f[k] = v
			}
			got := checkS1Manifest(tc.mutate(slices.Clone(ids), m, f), m, f)
			if !slices.ContainsFunc(got, func(p string) bool { return strings.Contains(p, tc.want) }) {
				t.Fatalf("problems %v, want one containing %q", got, tc.want)
			}
		})
	}
}

func TestS1NameClaims(t *testing.T) {
	for name, want := range map[string][]string{
		"TestS1E1E2_CheckURLLayer":                    {"S1-E1", "S1-E2"},
		"TestLinking_S1L13_TGIdentityMustBePrincipal": {"S1-L13"},
		"TestConversations_S1I2_S1I3":                 {"S1-I2", "S1-I3"},
		"TestRunLoop_S1R1NonASCIIReply":               {"S1-R1"},
		"TestDispatch_S1C7Fenced":                     {"S1-C7"},
		"TestConversations_S1X_State":                 nil,
		"TestDispatch_HappyPath":                      nil,
	} {
		if got := s1NameClaims(name); !slices.Equal(got, want) {
			t.Errorf("%s claims %v, want %v", name, got, want)
		}
	}
}

func TestParseS1ManifestStrict(t *testing.T) {
	if _, err := parseS1Manifest([]byte("S1-A1:\n  tests: [a.TestX]\nS1-A1:\n  tests: [a.TestY]\n")); err == nil {
		t.Error("duplicate id accepted")
	}
	if _, err := parseS1Manifest([]byte("S1-A1:\n  test: [a.TestX]\n")); err == nil {
		t.Error("unknown field accepted")
	}
	if _, err := threatModelS1IDs([]byte("- S1-A1: x\n- S1-A1: y\n")); err == nil {
		t.Error("repeated threat model id accepted")
	}
	if _, err := threatModelS1IDs([]byte("no rows here\n")); err == nil {
		t.Error("a threat model with no S1 row accepted")
	}
	for name, doc := range map[string]string{
		"indented row": "- S1-A1: x\n  - S1-A2: y\n",
		"bold row":     "- S1-A1: x\n- **S1-A2**: y\n",
		"table cell":   "- S1-A1: x\n| S1-A2 | y |\n",
	} {
		if _, err := threatModelS1IDs([]byte(doc)); err == nil || !strings.Contains(err.Error(), "S1-A2") {
			t.Errorf("%s: err %v, want one naming S1-A2", name, err)
		}
	}
	if ids, err := threatModelS1IDs([]byte("- S1-A1: x, see also S1-A1\n")); err != nil || !slices.Equal(ids, []string{"S1-A1"}) {
		t.Errorf("a mention of a row id: %v %v", ids, err)
	}
}

func TestOpenS1Gaps(t *testing.T) {
	got := openS1Gaps(map[string]s1Entry{
		"S1-B1": {Gaps: []s1Gap{{Half: "b", TrackedBy: "#2"}}},
		"S1-A1": {Gaps: []s1Gap{{Half: "a", TrackedBy: "#1"}}},
		"S1-C1": {},
	})
	want := []string{"S1-A1: a (tracked by #1)", "S1-B1: b (tracked by #2)"}
	if !slices.Equal(got, want) {
		t.Fatalf("open gaps %v, want %v", got, want)
	}
}
