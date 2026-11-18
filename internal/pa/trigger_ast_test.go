package pa

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// triggerMethodAllowlist names the places outside this package's own
// definition that may use the Trigger method: audit helpers that record how
// a run started. Keys are "<module-relative file>:<enclosing func>". Empty
// today. Adding an entry is a reviewed decision, because every other user
// would be gate code branching on the trigger (ADR 0011).
var triggerMethodAllowlist = map[string]bool{}

// triggerFieldAllowlist names the functions that may touch the unexported
// trigger field: the constructor that sets it, the accessor, and Valid.
var triggerFieldAllowlist = map[string]bool{
	"internal/pa/context.go:NewInteractive": true,
	"internal/pa/context.go:Trigger":        true,
	"internal/pa/context.go:Valid":          true,
}

// TestNoTriggerCalls makes the trigger-hiding guarantee mechanical rather
// than a convention. Across every non-test Go file of the module, and the
// whole file (function bodies, package-level var initialisers, method
// values, method expressions), it flags:
//
//   - any selector .Trigger -- a call, a method value (f := ec.Trigger) or a
//     method expression (ExecutionContext.Trigger) -- outside
//     triggerMethodAllowlist;
//   - any selector .trigger (the field) outside triggerFieldAllowlist.
//
// It is syntactic, so it also flags an unrelated type's Trigger; such a use
// needs an allowlist entry, which is the point: the reviewer sees it.
func TestNoTriggerCalls(t *testing.T) {
	root := moduleRoot(t)
	fset := token.NewFileSet()
	checked, sawDefinition := 0, false
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
		if rel == "internal/pa/context.go" {
			sawDefinition = true
		}
		for _, decl := range f.Decls {
			enclosing := ""
			if fn, ok := decl.(*ast.FuncDecl); ok {
				enclosing = fn.Name.Name
				// The method's own declaration name is an Ident, not a
				// selector, so declaring Trigger is not a use of it.
			}
			key := rel + ":" + enclosing
			ast.Inspect(decl, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				switch sel.Sel.Name {
				case "Trigger":
					if !triggerMethodAllowlist[key] {
						t.Errorf("%s: %s uses .Trigger; gate code must take a Policy", fset.Position(sel.Pos()), describe(enclosing))
					}
				case "trigger":
					if !triggerFieldAllowlist[key] {
						t.Errorf("%s: %s reads the trigger field; only NewInteractive, Trigger and Valid may", fset.Position(sel.Pos()), describe(enclosing))
					}
				}
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked < 50 || !sawDefinition {
		t.Fatalf("parsed %d files (definition seen: %v): the walk did not cover the module, so the check would pass vacuously", checked, sawDefinition)
	}
}

func describe(enclosing string) string {
	if enclosing == "" {
		return "a package-level declaration"
	}
	return enclosing
}

// moduleRoot walks up from the package directory to the directory holding
// go.mod.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		} else if !errors.Is(err, fs.ErrNotExist) {
			t.Fatal(err)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above the test directory")
		}
		dir = parent
	}
}
