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

package output

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

const templatesFile = "templates.go"

// scanTemplates returns one finding per Template built from anything but a
// string literal in templates.go: a Template{...} literal anywhere except
// inside tpl, a call to tpl outside templates.go, or a tpl argument that is
// not a string literal.
func scanTemplates(fset *token.FileSet, f *ast.File, file string) []string {
	var out []string
	report := func(n ast.Node, what string) {
		out = append(out, fset.Position(n.Pos()).String()+": "+what)
	}
	var inTpl *ast.FuncDecl
	for _, d := range f.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Name.Name == "tpl" && file == templatesFile {
			inTpl = fn
		}
	}
	isTemplateType := func(e ast.Expr) bool {
		id, ok := e.(*ast.Ident)
		return ok && id.Name == "Template"
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.FuncDecl:
			if x == inTpl {
				return false // the one place a Template is built from a string
			}
		case *ast.CompositeLit:
			if isTemplateType(x.Type) && len(x.Elts) > 0 {
				report(x, "Template literal outside tpl")
			}
		case *ast.CallExpr:
			id, ok := x.Fun.(*ast.Ident)
			if !ok || id.Name != "tpl" {
				return true
			}
			if file != templatesFile {
				report(x, "tpl called outside "+templatesFile)
			}
			if len(x.Args) != 1 {
				report(x, "tpl needs one argument")
			} else if lit, ok := x.Args[0].(*ast.BasicLit); !ok || lit.Kind != token.STRING {
				report(x, "tpl argument is not a string literal")
			}
		}
		return true
	})
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

func TestTemplatesGuardDetects(t *testing.T) {
	bad := []struct{ file, src string }{
		{"render.go", `package output; func f(s string) Template { return Template{s: s} }`},
		{"render.go", `package output; func f(s string) Template { return Template{s} }`},
		{"render.go", `package output; var x = tpl("hi")`},
		{templatesFile, `package output; func tpl(s string) Template { return Template{s: s} }; func f(s string) Template { return tpl(s) }`},
		{templatesFile, `package output; func tpl(s string) Template { return Template{s: s} }; var x = tpl("a" + "b")`},
	}
	for i, b := range bad {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, b.file, b.src, 0)
		if err != nil {
			t.Fatalf("bad %d: %v", i, err)
		}
		if got := scanTemplates(fset, f, b.file); len(got) != 1 {
			t.Errorf("bad %d: want 1 finding, got %v", i, got)
		}
	}
	good := []struct{ file, src string }{
		{templatesFile, `package output; func tpl(s string) Template { return Template{s: s} }; var x = tpl("hi")`},
		{"render.go", `package output; func f(t Template) string { return t.s }; var z = Template{}`},
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
