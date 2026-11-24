// Copyright 2025 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package safetext

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const templatesFile = "templates.go"

// fieldUsers are the only declarations that may touch the fields of Text
// and Template (s and parts) or build a non-empty one, keyed by
// "Receiver.Name" for methods. Everything else in the package goes through
// them. tpl is allowed only in templates.go.
var fieldUsers = map[string]bool{
	"tpl":             true,
	"Template.String": true,
	"Text.String":     true,
	"Text.Parts":      true,
	"Text.Part":       true,
	"ServerText":      true,
	"Render":          true,
	// The language half (lang.go): pick or join translations of texts
	// that are already safe.
	"Template.In": true,
	"Text.In":     true,
	"WithRussian": true,
	// The approval card (card.go): registry templates around two values
	// that are neutralised like model text.
	"Card": true,
	// The /permissions screens (permission.go): registry templates around
	// values held to a plain alphabet.
	"PermissionScreen": true,
	"PermissionList":   true,
}

// guardedFields are the unexported fields of Text and Template. Any
// selector or literal key with one of these names counts, whatever its
// type: the scan has no type information, so it fails closed.
var guardedFields = map[string]bool{"s": true, "parts": true, "ru": true}

// unwrapType strips parentheses and pointer stars, so (Text), *Text and
// (*Text) all name Text.
func unwrapType(e ast.Expr) ast.Expr {
	for {
		switch x := e.(type) {
		case *ast.ParenExpr:
			e = x.X
		case *ast.StarExpr:
			e = x.X
		default:
			return e
		}
	}
}

func namesGuardedType(e ast.Expr) bool {
	id, ok := unwrapType(e).(*ast.Ident)
	return ok && (id.Name == "Text" || id.Name == "Template")
}

// mentionsGuardedType reports whether a type expression names Text or
// Template anywhere (*Text, []Template, struct{ Text }, ...).
func mentionsGuardedType(e ast.Expr) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && (id.Name == "Text" || id.Name == "Template") {
			found = true
		}
		return !found
	})
	return found
}

// declKey names a top-level declaration as fieldUsers does; "" for
// anything but a function or method.
func declKey(d ast.Decl) string {
	fn, ok := d.(*ast.FuncDecl)
	if !ok {
		return ""
	}
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return fn.Name.Name
	}
	if id, ok := unwrapType(fn.Recv.List[0].Type).(*ast.Ident); ok {
		return id.Name + "." + fn.Name.Name
	}
	return "?." + fn.Name.Name
}

// scanTemplates returns one finding per way f could build a Text or a
// Template from anything but Render, ServerText and the literal registry.
// Every top-level declaration is checked on its own, so the allowance of
// one function never carries over to the next. Outside fieldUsers:
//   - any selector .s or .parts, read or write (t.s = x, &t.s,
//     copy(t.parts, x), for t.s = range ...);
//   - any composite literal with a key s or parts, of any type, any
//     non-empty Text or Template literal, and any positional literal whose
//     type is elided ([]Text{{p}}, map[int]Template{0: {s}});
//
// and anywhere in the file:
//   - a conversion to Text or Template, or to a pointer to one
//     ((*Text)(&struct{ parts []string }{x}));
//   - a type declaration that mentions Text or Template (type T = Text,
//     type P *Text, type W struct{ Text }), other than their own;
//   - a struct type with a field named s or parts, other than Text and
//     Template themselves: inside this package it is assignable to them
//     (return struct{ parts []string }{p} is a Text);
//   - a generic declaration (mk[T ~struct{ s string }]), since a type
//     parameter can stand for either type without naming it;
//   - an import of unsafe or reflect;
//   - a call to tpl outside templates.go, or whose argument is not a string
//     literal.
func scanTemplates(fset *token.FileSet, f *ast.File, file string) []string {
	var out []string
	report := func(n ast.Node, what string) {
		out = append(out, fset.Position(n.Pos()).String()+": "+what)
	}
	for _, imp := range f.Imports {
		if p, err := strconv.Unquote(imp.Path.Value); err == nil && (p == "unsafe" || p == "reflect") {
			report(imp, "import "+imp.Path.Value)
		}
	}
	for _, d := range f.Decls {
		key := declKey(d)
		if key == "tpl" && file != templatesFile {
			report(d, "tpl declared outside "+templatesFile)
		}
		trusted := fieldUsers[key] && (key != "tpl" || file == templatesFile)
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Type.TypeParams != nil {
			report(fn, "generic function")
		}
		ast.Inspect(d, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.TypeSpec:
				if x.TypeParams != nil {
					report(x, "generic type")
				}
				if (x.Name.Name == "Text" || x.Name.Name == "Template") && x.Assign == 0 {
					return false // the two declarations themselves
				}
				if mentionsGuardedType(x.Type) {
					report(x, "type over Template or Text")
				}
			case *ast.StructType:
				// A struct with the same fields is assignable to Text or
				// Template inside this package, with no conversion.
				for _, fld := range x.Fields.List {
					for _, nm := range fld.Names {
						if guardedFields[nm.Name] {
							report(nm, "struct type with a field "+nm.Name)
						}
					}
				}
			case *ast.SelectorExpr:
				if !trusted && guardedFields[x.Sel.Name] {
					report(x, "use of ."+x.Sel.Name+" outside "+key)
				}
			case *ast.CompositeLit:
				if trusted {
					return true
				}
				if x.Type != nil && namesGuardedType(x.Type) && len(x.Elts) > 0 {
					report(x, "non-empty Template or Text literal")
					return true
				}
				if x.Type == nil && len(x.Elts) > 0 {
					// An elided type ([]Text{{p}}) hides what is built.
					if _, keyed := x.Elts[0].(*ast.KeyValueExpr); !keyed {
						report(x, "positional literal with elided type")
						return true
					}
				}
				for _, e := range x.Elts {
					if kv, ok := e.(*ast.KeyValueExpr); ok {
						if id, ok := kv.Key.(*ast.Ident); ok && guardedFields[id.Name] {
							report(kv, "literal key "+id.Name)
						}
					}
				}
			case *ast.CallExpr:
				if namesGuardedType(x.Fun) {
					report(x, "conversion to Template or Text")
					return true
				}
				id, ok := x.Fun.(*ast.Ident)
				if !ok || id.Name != "tpl" {
					return true
				}
				if file != templatesFile {
					report(x, "tpl called outside "+templatesFile)
				}
				// The English text and, optionally, its Russian translation.
				if len(x.Args) < 1 || len(x.Args) > 2 || x.Ellipsis.IsValid() {
					report(x, "tpl needs one or two arguments")
				}
				for _, a := range x.Args {
					if lit, ok := a.(*ast.BasicLit); !ok || lit.Kind != token.STRING {
						report(x, "tpl argument is not a string literal")
					}
				}
			}
			return true
		})
	}
	return out
}

// TestTemplatesAreLiteralRegistry: every Template in production code is a
// string literal registered in templates.go, so ServerText cannot carry
// model text past Render.
func TestTemplatesAreLiteralRegistry(t *testing.T) {
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
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		checked++
		for _, finding := range scanTemplates(fset, f, name) {
			t.Errorf("Template not from the literal registry: %s", finding)
		}
	}
	if checked == 0 {
		t.Fatal("no source files parsed: the check would pass vacuously")
	}
}

// TestTemplatesGuardDetects: each bad source is one way to build a Text or
// Template outside Render, ServerText and the registry, and gives exactly
// want findings; each good source gives none. The cases after the first
// block are the gaps found in review of #1333 (#1337).
func TestTemplatesGuardDetects(t *testing.T) {
	const pkg = "package safetext; "
	bad := []struct {
		file, src string
		want      int
	}{
		{"render.go", pkg + `func f(s string) Template { return Template{s: s} }`, 1},
		{"render.go", pkg + `func f(s string) Template { return Template{s} }`, 1},
		{"render.go", pkg + `var x = tpl("hi")`, 1},
		{templatesFile, pkg + `func tpl(s string) Template { return Template{s: s} }; func f(s string) Template { return tpl(s) }`, 1},
		{templatesFile, pkg + `func tpl(s string) Template { return Template{s: s} }; var x = tpl("a" + "b")`, 1},
		// The Russian argument is held to the same rule as the English.
		{templatesFile, pkg + `func tpl(s string, ru ...string) Template { return Template{s: s} }; var y = "b"; var x = tpl("a", y)`, 1},
		{templatesFile, pkg + `func tpl(s string, ru ...string) Template { return Template{s: s} }; var x = tpl("a", "b", "c")`, 1},
		{templatesFile, pkg + `func tpl(s string, ru ...string) Template { return Template{s: s} }; var ys = []string{"b"}; var x = tpl("a", ys...)`, 2},
		{"render.go", pkg + `func f(t *Template, s string) { t.ru = s }`, 1},
		{"render.go", pkg + `func f(s string) Template { var t Template; t.s = s; return t }`, 1},
		{"render.go", pkg + `func f(s string) Template { return Template(struct{ s string }{s}) }`, 2},
		{"render.go", pkg + `func f(s string) Template { return (Template)(struct{ s string }{s}) }`, 2},
		{"render.go", pkg + `func f(s string) Text { return Text{parts: []string{s}} }`, 1},
		{"render.go", pkg + `func f(s string) Text { return Text{[]string{s}} }`, 1},
		{"render.go", pkg + `func f(t *Text, s string) { t.parts = []string{s} }`, 1},
		{"render.go", pkg + `func f(t Text, s string) { t.parts[0] = s }`, 1},
		{"render.go", pkg + `type T = Template`, 1},
		{"render.go", pkg + `type X Text`, 1},

		// #1337: the allowance of Render no longer leaks into the
		// declarations after it.
		{"render.go", pkg + `func Render(m string) Text { return Text{} }; var x = Text{parts: []string{"a"}}`, 1},
		{"render.go", pkg + `func Render(m string) Text { return Text{} }; func f(t *Text, s string) { t.parts = []string{s} }`, 1},
		// #1337: writes that are not plain assignments.
		{"render.go", pkg + `func f(t Text, s []string) { copy(t.parts, s) }`, 1},
		{"render.go", pkg + `func f(t *Template, s string) { p := &t.s; *p = s }`, 1},
		{"render.go", pkg + `func f(t *Template, xs []string) { for _, t.s = range xs {} }`, 1},
		// #1337: a generic builder (generic function, and its keyed literal).
		{"render.go", pkg + `func mk[T ~struct{ s string }](s string) T { return T{s: s} }; var x = mk[Template]("a")`, 3},
		{"render.go", pkg + `type box[T any] struct{ v T }`, 1},
		// #1337: unsafe (import, and the pointer conversion).
		{"render.go", pkg + `import "unsafe"; func f(p unsafe.Pointer) Text { return *(*Text)(p) }`, 2},
		{"render.go", pkg + `import "reflect"; var _ = reflect.TypeOf(0)`, 1},
		// A pointer conversion needs no unsafe.
		{"render.go", pkg + `func f(s string) *Text { return (*Text)(&struct{ parts []string }{[]string{s}}) }`, 2},
		{"render.go", pkg + `type P *Text`, 1},
		{"render.go", pkg + `type W struct{ Text }; func f(s string) (w W) { w.parts = []string{s}; return }`, 2},
		// Reading a field outside the accessors, and builder names on the
		// wrong receiver or in the wrong file.
		{"render.go", pkg + `func f(t Template) string { return t.s }`, 1},
		// #1356 review: assignability and elided literal types.
		{"render.go", pkg + `func f(s string) Text { return struct{ parts []string }{[]string{s}} }`, 1},
		{"render.go", pkg + `func f(s string) Text { return []Text{{[]string{s}}}[0] }`, 1},
		{"render.go", pkg + `func f(s string) Template { return map[int]Template{0: {s}}[0] }`, 1},
		{"render.go", pkg + `type X struct{}; func (X) Render(s string) Text { return Text{parts: []string{s}} }`, 1},
		{"render.go", pkg + `func tpl(s string) Template { return Template{s: s} }`, 2},
	}
	for i, b := range bad {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, b.file, b.src, 0)
		if err != nil {
			t.Fatalf("bad %d: %v", i, err)
		}
		if got := scanTemplates(fset, f, b.file); len(got) != b.want {
			t.Errorf("bad %d (%s): want %d findings, got %v", i, b.src, b.want, got)
		}
	}
	good := []struct{ file, src string }{
		{templatesFile, pkg + `func tpl(s string) Template { return Template{s: s} }; var x = tpl("hi"); func (t Template) String() string { return t.s }`},
		{"render.go", pkg + `var z = Template{}; var e = Text{}; func f() (Text, error) { return Text{}, nil }`},
		{"render.go", pkg + `func Render(m string) Text { return Text{parts: fit(m)} }; func ServerText(t Template) Text { return Text{parts: split(t.s)} }`},
		{"render.go", pkg + `func (t Text) String() string { return join(t.parts) }; func (t Text) Parts() int { return len(t.parts) }; func (t Text) Part(i int) string { return t.parts[i] }`},
		{"render.go", pkg + `type span struct{ start, end int }; func f(sp span) int { return sp.end - sp.start }; var u = UserText{tokens: nil}`},
	}
	for i, g := range good {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, g.file, g.src, 0)
		if err != nil {
			t.Fatalf("good %d: %v", i, err)
		}
		if got := scanTemplates(fset, f, g.file); len(got) != 0 {
			t.Errorf("good %d: unexpected findings %v", i, got)
		}
	}
}
