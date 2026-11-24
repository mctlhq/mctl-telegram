package pa

// phase2_inert_test.go keeps the Phase 2 primitives (P2-S1) behind one
// switch. The write path is built in one function, cmd/server's
// buildPAWrites (P2-S14), and only after that function saw
// PA_WRITES_ENABLED read true: nothing else touches the Phase 2 pin, the
// card emitter, the write executor or the run loop's approve-tier tools,
// and nothing in that function does before its flag check. With the
// switch off S1-I1 holds as before: the run loop's tool set is the Phase 1
// pin's reads.

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
	"LoadPinPhase2":   {phase2Constructor: true},
	"ValidatePhase2":  {"internal/pa/catalog/pin.go:LoadPinPhase2": true},
	"pinPhase2JSON":   {"internal/pa/catalog/pin.go:LoadPinPhase2": true},
	"AuthorizeWrites": {"internal/pa/catalog/surface.go:Surface.Authorize": true},
	// The approval card emitter (#1320 slice P2-S5) and the write executor
	// (P2-S4) are built by the write path's constructor only: without a
	// card emitter the tool route never takes the card path
	// (connector.DispatcherConfig.Cards is nil), and without an executor
	// nothing dispatches an approved call.
	"NewCards":         {phase2Constructor: true},
	"NewWriteExecutor": {phase2Constructor: true},
	// The approve-tier tools the run loop may sign into a claim: the
	// field's declaration, the loop reading it, the constructor that
	// builds the set, and buildPA handing that set to the loop.
	"ApproveTools": {
		phase2Constructor: true, "cmd/server/pa_wiring.go:buildPA": true,
		"internal/pa/runloop.go:": true, "internal/pa/runloop.go:NewRunLoop": true,
	},
}

// phase2Constructor is the one function that builds the write path, as
// "<module-relative file>:<func>". phase2GateViolations requires its
// check of PA_WRITES_ENABLED to stand before every Phase 2 identifier in
// it.
const (
	phase2Constructor = "cmd/server/pa_writes.go:buildPAWrites"
	// phase2FlagReader is the function whose result the constructor's
	// check tests; cmd/server's tests prove it reads PA_WRITES_ENABLED and
	// that unreadable is off.
	phase2FlagReader = "paWritesEnabled"
)

// phase2PinFile is the Phase 2 pin, module-relative. Only phase2PinEmbedder
// may embed it: a second //go:embed of the file would give runtime code a
// copy of the Phase 2 pin that none of the identifiers above names.
const (
	phase2PinFile     = "internal/pa/catalog/pin_phase2.json"
	phase2PinEmbedder = "internal/pa/catalog/pin.go"
)

// phase2Package is the write gate. Outside the package itself only
// phase2GateImporters import it.
const phase2Package = "github.com/mctlhq/mctl-telegram/internal/pa/gate"

// phase2GateImporters are the files allowed to import the gate: the card
// emitter, which calls gate.Decide for an approve-tier call and which
// only the write path's constructor builds (NewCards above).
var phase2GateImporters = map[string]bool{
	"internal/pa/connector/card.go": true,
}

// TestNoRuntimePhase2Use walks every non-test Go file of the module and
// fails on any use of a Phase 2 identifier outside its allowlist and on any
// import of the gate package outside the package itself.
func TestNoRuntimePhase2Use(t *testing.T) {
	root := moduleRoot(t)
	fset := token.NewFileSet()
	checked, sawLoader, sawConstructor := 0, false, false
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
		gated, v := phase2GateViolations(fset, f, rel)
		sawConstructor = sawConstructor || gated
		for _, v := range v {
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
	// The constructor not being found is not "no violation": the flag
	// check was then never looked at.
	if !sawConstructor {
		t.Fatalf("%s was not found: its flag check was not verified", phase2Constructor)
	}
}

// phase2GateViolations checks the write path's constructor in f: among its
// top-level statements there is
//
//	on, ... := paWritesEnabled(...)
//	...
//	if !on { return nil, nil }
//
// with no other assignment to on anywhere in the function, and every
// Phase 2 identifier of the function stands after that if statement. So
// the constructor cannot reach the Phase 2 pin, the card emitter or the
// executor on a path where the flag did not read true. found reports
// whether f holds the constructor at all.
func phase2GateViolations(fset *token.FileSet, f *ast.File, rel string) (found bool, out []string) {
	for _, decl := range f.Decls {
		d, ok := decl.(*ast.FuncDecl)
		if !ok || d.Recv != nil || d.Body == nil || rel+":"+d.Name.Name != phase2Constructor {
			continue
		}
		found = true
		fail := func(pos token.Pos, msg string) {
			out = append(out, fmt.Sprintf("%s: %s %s (P2-S14)", fset.Position(pos), d.Name.Name, msg))
		}
		const flag = "on"
		var read, gate ast.Stmt
		for _, st := range d.Body.List {
			if as, ok := st.(*ast.AssignStmt); ok && read == nil && len(as.Lhs) > 0 && len(as.Rhs) == 1 && as.Tok == token.DEFINE {
				id, _ := as.Lhs[0].(*ast.Ident)
				call, _ := as.Rhs[0].(*ast.CallExpr)
				if id != nil && id.Name == flag && call != nil {
					if fn, ok := call.Fun.(*ast.Ident); ok && fn.Name == phase2FlagReader {
						read = st
					}
				}
				continue
			}
			if is, ok := st.(*ast.IfStmt); ok && read != nil && gate == nil && isFlagGate(is, flag) {
				gate = st
			}
		}
		if read == nil || gate == nil {
			fail(d.Pos(), "has no `"+flag+", ... := "+phase2FlagReader+"(...)` followed by `if !"+flag+" { return nil, nil }` at its top level")
			continue
		}
		ast.Inspect(d.Body, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.AssignStmt:
				if ast.Stmt(x) == read {
					return true
				}
				for _, l := range x.Lhs {
					if id, ok := l.(*ast.Ident); ok && id.Name == flag {
						fail(x.Pos(), "assigns "+flag+" a second time")
					}
				}
			case *ast.IncDecStmt, *ast.UnaryExpr:
				// &on would let it change without an assignment.
				if u, ok := x.(*ast.UnaryExpr); ok && u.Op == token.AND {
					if id, ok := u.X.(*ast.Ident); ok && id.Name == flag {
						fail(u.Pos(), "takes the address of "+flag)
					}
				}
			case *ast.Ident:
				if _, ok := phase2Idents[x.Name]; ok && x.Pos() < gate.End() {
					fail(x.Pos(), "uses "+x.Name+" before its check of the writes flag")
				}
			}
			return true
		})
	}
	return found, out
}

// isFlagGate reports whether is is exactly `if !flag { return nil, nil }`:
// no init statement, no else, nothing else in the body.
func isFlagGate(is *ast.IfStmt, flag string) bool {
	if is.Init != nil || is.Else != nil || len(is.Body.List) != 1 {
		return false
	}
	not, ok := is.Cond.(*ast.UnaryExpr)
	if !ok || not.Op != token.NOT {
		return false
	}
	if id, ok := not.X.(*ast.Ident); !ok || id.Name != flag {
		return false
	}
	ret, ok := is.Body.List[0].(*ast.ReturnStmt)
	if !ok || len(ret.Results) != 2 {
		return false
	}
	for _, r := range ret.Results {
		if id, ok := r.(*ast.Ident); !ok || id.Name != "nil" {
			return false
		}
	}
	return true
}

// TestPhase2GateViolations_Detects proves the constructor check both ways.
func TestPhase2GateViolations_Detects(t *testing.T) {
	const rel = "cmd/server/pa_writes.go"
	run := func(body string) (bool, []string) {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, "pa_writes.go", "package main\nfunc buildPAWrites(pt *paTools) (*paWrites, error) {\n"+body+"\n}", parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		return phase2GateViolations(fset, f, rel)
	}
	const gate = "on, err := paWritesEnabled(pt.flags)\nif err != nil { log(err) }\nif !on { return nil, nil }\n"
	const use = "pin, err := catalog.LoadPinPhase2()\n_ = connector.NewCards\n_ = connector.NewWriteExecutor\nreturn build(pin), err"
	if found, v := run(gate + use); !found || len(v) != 0 {
		t.Errorf("the gated constructor: found %v, reported %v", found, v)
	}
	bad := map[string]string{
		"no flag check":         use,
		"flag read, no return":  "on, err := paWritesEnabled(pt.flags)\n_ = on\n" + use,
		"check after the pin":   "pin, err := catalog.LoadPinPhase2()\n" + gate + "return build(pin), err",
		"check inverted":        "on, err := paWritesEnabled(pt.flags)\nif on { return nil, nil }\n" + use,
		"check with an else":    "on, err := paWritesEnabled(pt.flags)\nif !on { return nil, nil } else { _ = err }\n" + use,
		"check does not return": "on, err := paWritesEnabled(pt.flags)\nif !on { log(err) }\n" + use,
		"check nested":          "on, err := paWritesEnabled(pt.flags)\nif pt != nil { if !on { return nil, nil } }\n" + use,
		"another reader":        "on, err := somethingElse(pt.flags)\nif !on { return nil, nil }\n" + use,
		"flag forced on":        gate + "on = true\n" + use,
		"flag forced before":    "on, err := paWritesEnabled(pt.flags)\non = true\nif !on { return nil, nil }\n" + use,
		"flag redeclared":       "on, err := paWritesEnabled(pt.flags)\non, ok := true, false\n_ = ok\nif !on { return nil, nil }\n" + use,
		"flag by address":       "on, err := paWritesEnabled(pt.flags)\nset(&on)\nif !on { return nil, nil }\n" + use,
		"executor before check": "_ = connector.NewWriteExecutor\n" + gate + use,
	}
	for name, body := range bad {
		if found, v := run(body); !found || len(v) == 0 {
			t.Errorf("%s: found %v, not reported", name, found)
		}
	}
	// A file without the constructor: nothing is found, which the walk
	// treats as a failure of its own.
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "x.go", "package main\nfunc other() {}", parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	if found, _ := phase2GateViolations(fset, f, rel); found {
		t.Error("a file without the constructor reported it found")
	}
}

func phase2Violations(fset *token.FileSet, f *ast.File, rel string) []string {
	var out []string
	if !strings.HasPrefix(rel, "internal/pa/gate/") && !phase2GateImporters[rel] {
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
		"cards":        `func f() { _, _ = connector.NewCards(connector.CardConfig{}) }`,
		"executor":     `func f() { _, _ = connector.NewWriteExecutor(connector.WriteConfig{}) }`,
		"approve set":  `func f(c *RunLoopConfig) { c.ApproveTools = nil }`,
		// The constructor's name in another file is not the constructor.
		"constructor name": `func buildPAWrites() { _, _ = catalog.LoadPinPhase2() }`,
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
	// The write path's constructor, in its own file, is allowed.
	{
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, "pa_writes.go", "package main\nfunc buildPAWrites() { _, _ = catalog.LoadPinPhase2(); _ = connector.NewCards; _ = connector.NewWriteExecutor; _ = pa.RunLoopConfig{ApproveTools: nil} }", parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		if v := phase2Violations(fset, f, "cmd/server/pa_writes.go"); len(v) != 0 {
			t.Errorf("allowlisted constructor reported: %v", v)
		}
		if v := phase2Violations(fset, f, "cmd/server/pa_tools.go"); len(v) == 0 {
			t.Error("the constructor's body in another file: not reported")
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
