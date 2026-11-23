package pa

// phase2_inert_test.go keeps the Phase 2 primitives (P2-S1) out of the
// running service: S1-I1 holds because the run loop's tool set comes from
// the Phase 1 pin, and nothing but the catalog's own loader touches the
// Phase 2 pin, the write-aware Authorize or the write gate.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"maps"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/pa/catalog"
)

// phase2Idents are the Phase 2 identifiers runtime code may not use, with
// the only "<module-relative file>:<enclosing func>" allowed to. A method
// is named with its receiver type ("Surface.Authorize"), so another func
// or method called Authorize in the same file is not allowed.
var phase2Idents = map[string]map[string]bool{
	"LoadPinPhase2":   {},
	"ValidatePhase2":  {"internal/pa/catalog/pin.go:LoadPinPhase2": true},
	"pinPhase2JSON":   {"internal/pa/catalog/pin.go:LoadPinPhase2": true},
	"AuthorizeWrites": {"internal/pa/catalog/surface.go:Surface.Authorize": true},
}

// phase2PinFile is the Phase 2 pin, module-relative. Only phase2PinEmbedder
// may embed it: a second //go:embed of the file would give runtime code a
// copy of the Phase 2 pin that none of the identifiers above names.
const (
	phase2PinFile     = "internal/pa/catalog/pin_phase2.json"
	phase2PinEmbedder = "internal/pa/catalog/pin.go"
)

// phase2Package is the write gate; no runtime package imports it yet.
const phase2Package = "github.com/mctlhq/mctl-telegram/internal/pa/gate"

// TestNoRuntimePhase2Use walks every non-test Go file of the module and
// fails on any use of a Phase 2 identifier outside its allowlist and on any
// import of the gate package outside the package itself.
func TestNoRuntimePhase2Use(t *testing.T) {
	root := moduleRoot(t)
	fset := token.NewFileSet()
	checked, sawLoader := 0, false
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			if path != root && (strings.HasPrefix(name, ".") || name == "vendor" || name == "testdata" || name == "node_modules") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution|parser.ParseComments)
		if err != nil {
			return err
		}
		checked++
		if rel == "internal/pa/catalog/pin.go" {
			sawLoader = true
		}
		for _, v := range phase2Violations(fset, f, rel) {
			t.Error(v)
		}
		for _, v := range phase2EmbedViolations(fset, f, rel) {
			t.Error(v)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked < 50 || !sawLoader {
		t.Fatalf("parsed %d files (loader seen: %v): the walk did not cover the module", checked, sawLoader)
	}
}

func phase2Violations(fset *token.FileSet, f *ast.File, rel string) []string {
	var out []string
	if !strings.HasPrefix(rel, "internal/pa/gate/") {
		for _, imp := range f.Imports {
			if p, _ := strconv.Unquote(imp.Path.Value); p == phase2Package {
				out = append(out, fmt.Sprintf("%s: imports %s", fset.Position(imp.Pos()), phase2Package))
			}
		}
	}
	for _, decl := range f.Decls {
		enclosing := ""
		declared := map[*ast.Ident]bool{}
		switch d := decl.(type) {
		case *ast.FuncDecl:
			enclosing = d.Name.Name
			if r := receiverType(d); r != "" {
				enclosing = r + "." + enclosing
			}
			declared[d.Name] = true
		case *ast.GenDecl:
			for _, s := range d.Specs {
				if vs, ok := s.(*ast.ValueSpec); ok {
					for _, n := range vs.Names {
						declared[n] = true
					}
				}
			}
		}
		key := rel + ":" + enclosing
		ast.Inspect(decl, func(n ast.Node) bool {
			id, ok := n.(*ast.Ident)
			if !ok || declared[id] {
				return true
			}
			if allow, ok := phase2Idents[id.Name]; ok && !allow[key] {
				out = append(out, fmt.Sprintf("%s: %s uses %s; Phase 2 is not wired at runtime (P2-S1)", fset.Position(id.Pos()), describe(enclosing), id.Name))
			}
			return true
		})
	}
	return out
}

// receiverType is the receiver's type name of a method ("Surface" for
// func (s *Surface) ...), or "" for a plain func.
func receiverType(d *ast.FuncDecl) string {
	if d.Recv == nil || len(d.Recv.List) == 0 {
		return ""
	}
	t := d.Recv.List[0].Type
	if st, ok := t.(*ast.StarExpr); ok {
		t = st.X
	}
	switch x := t.(type) {
	case *ast.IndexExpr:
		t = x.X
	case *ast.IndexListExpr:
		t = x.X
	}
	if id, ok := t.(*ast.Ident); ok {
		return id.Name
	}
	return "?"
}

// phase2EmbedViolations reports every //go:embed directive in a file other
// than phase2PinEmbedder whose patterns reach phase2PinFile: the file
// itself, a glob that matches it, or a directory above it (embedding a
// directory embeds the files below it). f must be parsed with comments.
func phase2EmbedViolations(fset *token.FileSet, f *ast.File, rel string) []string {
	if rel == phase2PinEmbedder {
		return nil
	}
	dir := path.Dir(rel)
	target := phase2PinFile
	if dir != "." {
		if !strings.HasPrefix(target, dir+"/") {
			return nil // go:embed cannot reach outside its package directory
		}
		target = strings.TrimPrefix(target, dir+"/")
	}
	var out []string
	for _, cg := range f.Comments {
		for _, c := range cg.List {
			args, ok := strings.CutPrefix(c.Text, "//go:embed")
			if !ok || (args != "" && args[0] != ' ' && args[0] != '\t') {
				continue
			}
			for _, pat := range embedPatterns(args) {
				if embedReaches(pat, target) {
					out = append(out, fmt.Sprintf("%s: //go:embed %s reaches %s; only %s embeds the Phase 2 pin (P2-S1)", fset.Position(c.Pos()), pat, phase2PinFile, phase2PinEmbedder))
				}
			}
		}
	}
	return out
}

// embedPatterns splits a //go:embed argument list: space-separated
// patterns, each optionally a Go string literal.
func embedPatterns(args string) []string {
	var out []string
	for _, f := range strings.Fields(args) {
		if u, err := strconv.Unquote(f); err == nil {
			f = u
		}
		out = append(out, strings.TrimPrefix(f, "all:"))
	}
	return out
}

// embedReaches reports whether an embed pattern matches target or one of
// its parent directories.
func embedReaches(pat, target string) bool {
	parts := strings.Split(target, "/")
	for i := range parts {
		if ok, _ := path.Match(pat, strings.Join(parts[:i+1], "/")); ok {
			return true
		}
	}
	return false
}

// TestPhase2EmbedViolations_Detects proves the embed check both ways.
func TestPhase2EmbedViolations_Detects(t *testing.T) {
	parse := func(src string) (*token.FileSet, *ast.File) {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, "x.go", src, parser.SkipObjectResolution|parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		return fset, f
	}
	bad := map[string]struct{ rel, src string }{
		"same file name":   {"internal/pa/catalog/listing.go", "package catalog\nimport _ \"embed\"\n//go:embed pin_phase2.json\nvar x []byte"},
		"quoted":           {"internal/pa/catalog/listing.go", "package catalog\nimport _ \"embed\"\n//go:embed \"pin_phase2.json\"\nvar x []byte"},
		"glob":             {"internal/pa/catalog/listing.go", "package catalog\nimport \"embed\"\n//go:embed *.json\nvar x embed.FS"},
		"second pattern":   {"internal/pa/catalog/listing.go", "package catalog\nimport \"embed\"\n//go:embed pin.json pin_*.json\nvar x embed.FS"},
		"parent directory": {"internal/pa/doc.go", "package pa\nimport \"embed\"\n//go:embed catalog\nvar x embed.FS"},
		"all: prefix":      {"internal/pa/doc.go", "package pa\nimport \"embed\"\n//go:embed all:catalog/*\nvar x embed.FS"},
	}
	for name, c := range bad {
		fset, f := parse(c.src)
		if v := phase2EmbedViolations(fset, f, c.rel); len(v) == 0 {
			t.Errorf("%s: not reported", name)
		}
	}
	good := map[string]struct{ rel, src string }{
		"the loader itself":       {phase2PinEmbedder, "package catalog\nimport _ \"embed\"\n//go:embed pin_phase2.json\nvar pinPhase2JSON []byte"},
		"the Phase 1 pin":         {"internal/pa/catalog/listing.go", "package catalog\nimport _ \"embed\"\n//go:embed pin.json\nvar x []byte"},
		"a sibling directory":     {"internal/pa/doc.go", "package pa\nimport \"embed\"\n//go:embed connector\nvar x embed.FS"},
		"another package":         {"internal/ui/assets.go", "package ui\nimport \"embed\"\n//go:embed *.json\nvar x embed.FS"},
		"a comment that mentions": {"internal/pa/catalog/listing.go", "package catalog\n// not a directive: go:embed pin_phase2.json\nvar x []byte"},
	}
	for name, c := range good {
		fset, f := parse(c.src)
		if v := phase2EmbedViolations(fset, f, c.rel); len(v) != 0 {
			t.Errorf("%s: reported %v", name, v)
		}
	}
}

// TestPhase2Violations_Detects proves the checker both ways.
func TestPhase2Violations_Detects(t *testing.T) {
	bad := map[string]string{
		"call":         `func f() { _, _ = catalog.LoadPinPhase2() }`,
		"method value": `func f(p *catalog.Pin) { g := p.ValidatePhase2; _ = g }`,
		"pkg var":      `var g = catalog.LoadPinPhase2`,
		"authorize":    `func f(s *catalog.Surface) { _, _ = s.AuthorizeWrites("x", time.Time{}, true) }`,
		"gate import":  "import _ \"" + phase2Package + "\"",
		// A func or method named Authorize other than Surface.Authorize
		// is not on the allowlist.
		"plain Authorize": `func Authorize(s *catalog.Surface) { _, _ = s.AuthorizeWrites("x", time.Time{}, true) }`,
		"other receiver":  `type T struct{}; func (T) Authorize(s *catalog.Surface) { _, _ = s.AuthorizeWrites("x", time.Time{}, true) }`,
	}
	for name, src := range bad {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, "x.go", "package pa\n"+src, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		// surface.go is the file Surface.Authorize lives in: the same
		// source there is still refused.
		for _, rel := range []string{"internal/pa/runloop.go", "internal/pa/catalog/surface.go"} {
			if v := phase2Violations(fset, f, rel); len(v) == 0 {
				t.Errorf("%s in %s: not reported", name, rel)
			}
		}
	}
	// Surface.Authorize itself, in surface.go, is allowed.
	{
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, "surface.go", "package catalog\nfunc (s *Surface) Authorize(tool string, now time.Time) (Grant, error) { return s.AuthorizeWrites(tool, now, false) }", parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		if v := phase2Violations(fset, f, "internal/pa/catalog/surface.go"); len(v) != 0 {
			t.Errorf("allowlisted Surface.Authorize reported: %v", v)
		}
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "pin.go", "package catalog\nvar pinPhase2JSON []byte\nfunc LoadPinPhase2() (*Pin, error) { p, _ := ParsePin(pinPhase2JSON); return p, p.ValidatePhase2() }", parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	if v := phase2Violations(fset, f, "internal/pa/catalog/pin.go"); len(v) != 0 {
		t.Errorf("allowlisted loader reported: %v", v)
	}
}

// TestRunLoopToolSetIsPhase1Reads is S1-I1 under P2-S1: the run loop
// admits exactly the Phase 1 pin's reads, so no write or disclosure of the
// Phase 2 pin can enter a job's tool set.
func TestRunLoopToolSetIsPhase1Reads(t *testing.T) {
	h := newRunLoopHarness(t)
	p1, err := catalog.LoadPin()
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for server, sp := range p1.Servers {
		for name, pt := range sp.Tools {
			if pt.Class != catalog.ClassRead || pt.Tier != catalog.TierAuto {
				t.Fatalf("Phase 1 pin holds a non-read %s/%s", server, name)
			}
			want = append(want, server+"/"+name)
		}
	}
	slices.Sort(want)
	got := slices.Sorted(maps.Keys(h.loop.readTools))
	if !slices.Equal(got, want) {
		t.Fatalf("run loop tools = %v, want the Phase 1 reads %v", got, want)
	}
	p2, err := catalog.LoadPinPhase2()
	if err != nil {
		t.Fatal(err)
	}
	for server, sp := range p2.Servers {
		for name, pt := range sp.Tools {
			if pt.Class != catalog.ClassRead && h.loop.readTools[server+"/"+name] {
				t.Errorf("run loop admits the Phase 2 %s %s/%s", pt.Class, server, name)
			}
		}
	}
}
