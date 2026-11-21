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
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/pa/catalog"
)

// phase2Idents are the Phase 2 identifiers runtime code may not use, with
// the only "<module-relative file>:<enclosing func>" allowed to.
var phase2Idents = map[string]map[string]bool{
	"LoadPinPhase2":   {},
	"ValidatePhase2":  {"internal/pa/catalog/pin.go:LoadPinPhase2": true},
	"pinPhase2JSON":   {"internal/pa/catalog/pin.go:LoadPinPhase2": true},
	"AuthorizeWrites": {"internal/pa/catalog/surface.go:Authorize": true},
}

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
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
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

// TestPhase2Violations_Detects proves the checker both ways.
func TestPhase2Violations_Detects(t *testing.T) {
	bad := map[string]string{
		"call":         `func f() { _, _ = catalog.LoadPinPhase2() }`,
		"method value": `func f(p *catalog.Pin) { g := p.ValidatePhase2; _ = g }`,
		"pkg var":      `var g = catalog.LoadPinPhase2`,
		"authorize":    `func f(s *catalog.Surface) { _, _ = s.AuthorizeWrites("x", time.Time{}, true) }`,
		"gate import":  "import _ \"" + phase2Package + "\"",
	}
	for name, src := range bad {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, "x.go", "package pa\n"+src, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		if v := phase2Violations(fset, f, "internal/pa/runloop.go"); len(v) == 0 {
			t.Errorf("%s: not reported", name)
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
