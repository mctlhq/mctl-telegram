package pa

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// triggerCallAllowlist names the functions in this package that may call
// .Trigger(): audit helpers that record how a run started. Empty today.
// Adding an entry is a reviewed decision, because every other caller would
// be gate code branching on the trigger (ADR 0011).
var triggerCallAllowlist = map[string]bool{}

// TestNoTriggerCalls makes the trigger-hiding guarantee mechanical rather
// than a convention: no non-test code in this package calls .Trigger()
// outside the allowlist, so tiering, approval and limits code cannot read it
// even through the whole ExecutionContext.
func TestNoTriggerCalls(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	checked := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		checked++
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || triggerCallAllowlist[fn.Name.Name] {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Trigger" {
					t.Errorf("%s: %s calls .Trigger(); gate code must take a Policy", fset.Position(call.Pos()), fn.Name.Name)
				}
				return true
			})
		}
	}
	if checked == 0 {
		t.Fatal("no source files parsed: the check would pass vacuously")
	}
}
