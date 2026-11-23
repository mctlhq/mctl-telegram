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

// sendPartsCallers are the only declarations in package output that may
// name sendParts. It takes a raw []string, so any other caller could send
// text that never went through safetext.Render or safetext.ServerText.
var sendPartsCallers = map[string]bool{"Sender.SendFrom": true, "Sender.sendParts": true}

// scanSendParts returns one finding per use of sendParts (a call, a method
// value or a plain identifier) outside sendPartsCallers. Each top-level
// declaration is checked on its own.
func scanSendParts(fset *token.FileSet, f *ast.File) []string {
	var out []string
	for _, d := range f.Decls {
		key := ""
		if fn, ok := d.(*ast.FuncDecl); ok {
			key = fn.Name.Name
			if fn.Recv != nil && len(fn.Recv.List) > 0 {
				t := fn.Recv.List[0].Type
				if st, ok := t.(*ast.StarExpr); ok {
					t = st.X
				}
				if id, ok := t.(*ast.Ident); ok {
					key = id.Name + "." + key
				}
			}
		}
		if sendPartsCallers[key] {
			continue
		}
		ast.Inspect(d, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && id.Name == "sendParts" {
				out = append(out, fset.Position(id.Pos()).String()+": sendParts used outside SendFrom")
			}
			return true
		})
	}
	return out
}

// TestSendPartsOnlyFromSendFrom: production code reaches sendParts only
// through SendFrom, which takes a safetext.Text.
func TestSendPartsOnlyFromSendFrom(t *testing.T) {
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
		for _, finding := range scanSendParts(fset, f) {
			t.Error(finding)
		}
	}
	if checked == 0 {
		t.Fatal("no source files parsed: the check would pass vacuously")
	}
}

func TestSendPartsGuardDetects(t *testing.T) {
	bad := []string{
		`package output; func (s *Sender) Other(p []string) error { return s.sendParts(nil, 1, p, nil, 0, nil) }`,
		`package output; func f(s *Sender, p []string) error { return s.sendParts(nil, 1, p, nil, 0, nil) }`,
		`package output; var send = (*Sender).sendParts`,
		`package output; func (x *Other) SendFrom(s *Sender) { _ = s.sendParts }`,
	}
	for i, src := range bad {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, "x.go", src, 0)
		if err != nil {
			t.Fatalf("bad %d: %v", i, err)
		}
		if got := scanSendParts(fset, f); len(got) != 1 {
			t.Errorf("bad %d: want 1 finding, got %v", i, got)
		}
	}
	good := `package output; func (s *Sender) SendFrom(p []string) error { return s.sendParts(nil, 1, p, nil, 0, nil) }; func (s *Sender) sendParts() {}`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "x.go", good, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := scanSendParts(fset, f); len(got) != 0 {
		t.Errorf("good: unexpected findings %v", got)
	}
}
