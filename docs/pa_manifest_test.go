package docs

// Shared parts of the Personal Assistant suite gates (S1 #1317, S2 #1323):
// reading a suite's rows out of the threat model, reading the test ids a
// test function name claims, indexing the module's test functions, and the
// checks on gaps, test references and name claims that both manifests use.
// The S1 gate is pa_s1_manifest_test.go, the S2 gate pa_s2_manifest_test.go.

import (
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

const paThreatModelPath = "agent-runtime/personal-assistant-threat-model.md"

// paSuite is one security suite of the threat model, named by its prefix
// ("S1", "S2").
type paSuite struct {
	name string
	// A row of the suite: "- S1-L1: ...".
	rowRe *regexp.Regexp
	// Anything written as the suite name, a dash of any kind (or an
	// underscore) and a word: "S1-L1", "S1\u2011L1", "S1-Z". Each must be a
	// row id, so a row written in another shape (indented, bold, a table
	// cell, a Unicode dash, an id without a digit) cannot drop out of the
	// gate unseen.
	mentionRe *regexp.Regexp
	// An id claimed by a test function name: TestS1E1E2_...,
	// TestLinking_S1L13_... or TestS1_E1_... . A group without a digit
	// (S1X_State) claims nothing.
	nameRe *regexp.Regexp
}

func newPASuite(name string) paSuite {
	q := regexp.QuoteMeta(name)
	return paSuite{
		name:      name,
		rowRe:     regexp.MustCompile(`(?m)^- (` + q + `-[A-Z]+[0-9]+):`),
		mentionRe: regexp.MustCompile(q + `[\p{Pd}_][\p{L}\p{N}]*`),
		nameRe:    regexp.MustCompile(q + `_?((?:[A-Z][0-9]+)+)`),
	}
}

var (
	paSuiteS1 = newPASuite("S1")
	paSuiteS2 = newPASuite("S2")

	// A tracking reference: an issue number of this repository.
	paIssueRef = regexp.MustCompile(`^#[0-9]+$`)
	paPartRe   = regexp.MustCompile(`[A-Z][0-9]+`)
	paTestRef  = regexp.MustCompile(`^[a-z0-9_/.-]+\.Test[A-Za-z0-9_]*$`)
)

// paGap is a part of a row that has no guard yet, so no test can cover it.
// It names the issue that will build it.
type paGap struct {
	Half      string `yaml:"half"`
	TrackedBy string `yaml:"tracked_by"`
}

// threatModelIDs returns the suite's ids of the threat model, in order. A
// repeated id, a model with no row of the suite, and a mention of a suite
// id that is not a parsed row are errors.
func (s paSuite) threatModelIDs(doc []byte) ([]string, error) {
	var ids []string
	for _, m := range s.rowRe.FindAllSubmatch(doc, -1) {
		id := string(m[1])
		if slices.Contains(ids, id) {
			return nil, fmt.Errorf("threat model lists %s twice", id)
		}
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("threat model lists no %s id: the row pattern no longer matches", s.name)
	}
	var stray []string
	for _, m := range s.mentionRe.FindAll(doc, -1) {
		if id := string(m); !slices.Contains(ids, id) && !slices.Contains(stray, id) {
			stray = append(stray, id)
		}
	}
	if len(stray) > 0 {
		return nil, fmt.Errorf("threat model mentions %s, which is not a row of the form \"- %s-XX: ...\"", strings.Join(stray, ", "), s.name)
	}
	return ids, nil
}

// nameClaims returns the suite ids a test function name claims.
func (s paSuite) nameClaims(name string) []string {
	var out []string
	for _, m := range s.nameRe.FindAllStringSubmatch(name, -1) {
		for _, p := range paPartRe.FindAllString(m[1], -1) {
			out = append(out, s.name+"-"+p)
		}
	}
	return out
}

// checkGaps validates the gaps of one id.
func checkGaps(id string, gaps []paGap) []string {
	var problems []string
	halves := map[string]bool{}
	for _, g := range gaps {
		switch {
		case strings.TrimSpace(g.Half) == "":
			problems = append(problems, fmt.Sprintf("%s: a gap without a half", id))
		case !paIssueRef.MatchString(g.TrackedBy):
			problems = append(problems, fmt.Sprintf("%s: gap %q is not tracked by an issue (tracked_by %q, want #NNNN)", id, g.Half, g.TrackedBy))
		case halves[g.Half]:
			problems = append(problems, fmt.Sprintf("%s: gap %q listed twice", id, g.Half))
		}
		halves[g.Half] = true
	}
	return problems
}

// checkTestRefs validates the test references of one id against the test
// functions that exist, and records each in mapped.
func checkTestRefs(id string, refs []string, funcs, mapped map[string]bool) []string {
	var problems []string
	for _, ref := range refs {
		switch {
		case !paTestRef.MatchString(ref):
			problems = append(problems, fmt.Sprintf("%s: %q is not <package dir>.<TestFunc>", id, ref))
		case !hasKey(funcs, ref):
			problems = append(problems, fmt.Sprintf("%s: test %s does not exist", id, ref))
		case !funcs[ref]:
			problems = append(problems, fmt.Sprintf("%s: test %s is left out of CI's build by a build constraint or file name, so it is not evidence", id, ref))
		case mapped[ref]:
			problems = append(problems, fmt.Sprintf("%s: test %s listed twice", id, ref))
		}
		mapped[ref] = true
	}
	return problems
}

func hasKey(m map[string]bool, k string) bool {
	_, ok := m[k]
	return ok
}

// paGateClosing reports whether env, a suite's closing variable, is set:
// the run is closing that suite's gate, so any open item fails it.
func paGateClosing(env string) bool { return os.Getenv(env) != "" }

// checkNameClaims reports every test function whose name claims a suite
// id that is not a row of the threat model, or that the manifest does not
// list under that id.
func (s paSuite) checkNameClaims(inModel map[string]bool, mapped map[string]map[string]bool, funcs map[string]bool) []string {
	var problems []string
	for ref := range funcs {
		name := ref[strings.LastIndex(ref, ".")+1:]
		for _, id := range s.nameClaims(name) {
			switch {
			case !inModel[id]:
				problems = append(problems, fmt.Sprintf("test %s claims %s, which is not an %s id of the threat model", ref, id, s.name))
			case !mapped[id][ref]:
				problems = append(problems, fmt.Sprintf("test %s claims %s but the manifest does not list it there", ref, id))
			}
		}
	}
	return problems
}

// ciBuild is the build CI runs the suites in (build.yml: go test -race
// ./... on ubuntu-latest, no build tags). A test file it excludes is not
// gate evidence.
var ciBuild = func() build.Context {
	c := build.Default
	c.GOOS, c.GOARCH, c.CgoEnabled = "linux", "amd64", true
	c.BuildTags, c.ToolTags = nil, nil
	return c
}()

// repoTestFuncs indexes every top-level Test function of the module below
// root as "<package dir>.<TestFunc>". The value is true when CI's build
// includes the file and false when a build constraint or a file name
// suffix leaves it out: such a test still counts for the name claims, but
// is not evidence. A file that does not parse fails the test: an
// unreadable tree is not an empty one.
func repoTestFuncs(t *testing.T, root string) map[string]bool {
	t.Helper()
	funcs := map[string]bool{}
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", ".worktrees", "vendor", "node_modules", "testdata":
				return filepath.SkipDir
			}
			// A nested module is not this module's test code.
			if path != root {
				if _, err := os.Stat(filepath.Join(path, "go.mod")); err == nil {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, filepath.Dir(path))
		if err != nil {
			return err
		}
		inCI, err := ciBuild.MatchFile(filepath.Dir(path), filepath.Base(path))
		if err != nil {
			return err
		}
		pkg := filepath.ToSlash(rel)
		names, dot := testingImport(f)
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || !strings.HasPrefix(fn.Name.Name, "Test") || !isTestingT(fn, names, dot) {
				continue
			}
			funcs[pkg+"."+fn.Name.Name] = inCI
		}
		return nil
	})
	if err != nil {
		t.Fatalf("index test functions: %v", err)
	}
	if len(funcs) == 0 {
		t.Fatal("no test functions found: the walk is not looking at the module")
	}
	return funcs
}

// testingImport returns the names a file imports package testing under,
// and whether it dot-imports it.
func testingImport(f *ast.File) (names map[string]bool, dot bool) {
	names = map[string]bool{}
	for _, imp := range f.Imports {
		if imp.Path.Value != `"testing"` {
			continue
		}
		switch {
		case imp.Name == nil:
			names["testing"] = true
		case imp.Name.Name == ".":
			dot = true
		default:
			names[imp.Name.Name] = true
		}
	}
	return names, dot
}

// isTestingT reports whether fn has the signature func(*testing.T), with
// testing imported under one of names, or dot-imported.
func isTestingT(fn *ast.FuncDecl, names map[string]bool, dot bool) bool {
	ps := fn.Type.Params.List
	if len(ps) != 1 || len(ps[0].Names) > 1 {
		return false
	}
	star, ok := ps[0].Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	switch x := star.X.(type) {
	case *ast.SelectorExpr:
		id, ok := x.X.(*ast.Ident)
		return ok && names[id.Name] && x.Sel.Name == "T"
	case *ast.Ident:
		return dot && x.Name == "T"
	}
	return false
}

// writeTree writes files (path relative to a new temporary directory ->
// content) and returns the directory.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for path, content := range files {
		full := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestRepoTestFuncs(t *testing.T) {
	root := writeTree(t, map[string]string{
		"go.mod": "module example.com/x\n",
		"a/plain_test.go": "package a\n\nimport \"testing\"\n\n" +
			"func TestPlain(t *testing.T) {}\n" +
			"func TestS2_A1_Underscore(t *testing.T) {}\n" +
			"func TestNotATest(b *testing.B) {}\n" +
			"func helper(t *testing.T) {}\n",
		"a/alias_test.go":       "package a\n\nimport tt \"testing\"\n\nfunc TestAlias(t *tt.T) {}\n",
		"a/dot_test.go":         "package a\n\nimport . \"testing\"\n\nfunc TestDot(t *T) {}\n",
		"a/other_test.go":       "package a\n\nimport tt \"testing\"\n\ntype T struct{}\n\nfunc TestOtherT(t *T) {}\nfunc TestWrongPkg(t *testing.T) {}\nvar _ tt.T\n",
		"a/tagged_test.go":      "//go:build smoke\n\npackage a\n\nimport \"testing\"\n\nfunc TestTagged(t *testing.T) {}\n",
		"a/win_windows_test.go": "package a\n\nimport \"testing\"\n\nfunc TestWindowsOnly(t *testing.T) {}\n",
		"a/linux_test.go":       "//go:build linux && !windows\n\npackage a\n\nimport \"testing\"\n\nfunc TestLinux(t *testing.T) {}\n",
		"nested/go.mod":         "module example.com/nested\n",
		"nested/n_test.go":      "package n\n\nimport \"testing\"\n\nfunc TestNested(t *testing.T) {}\n",
	})
	got := repoTestFuncs(t, root)
	want := map[string]bool{
		"a.TestPlain":            true,
		"a.TestS2_A1_Underscore": true,
		"a.TestAlias":            true,
		"a.TestDot":              true,
		"a.TestLinux":            true,
		"a.TestTagged":           false,
		"a.TestWindowsOnly":      false,
	}
	if len(got) != len(want) {
		t.Errorf("indexed %v, want %v", got, want)
	}
	for k, v := range want {
		if g, ok := got[k]; !ok || g != v {
			t.Errorf("%s: indexed %v (present %v), want %v", k, g, ok, v)
		}
	}
}

func TestCheckTestRefsBuildConstraint(t *testing.T) {
	funcs := map[string]bool{"a.TestTagged": false, "a.TestPlain": true}
	got := checkTestRefs("S2-A1", []string{"a.TestTagged", "a.TestPlain"}, funcs, map[string]bool{})
	if len(got) != 1 || !strings.Contains(got[0], "a.TestTagged is left out of CI's build") {
		t.Fatalf("problems %v, want one for the tagged test only", got)
	}
}
