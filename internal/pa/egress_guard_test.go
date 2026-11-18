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

package pa

// Static guard for threat model T9: every outbound HTTP request the
// Personal Assistant makes to a catalog server goes through
// internal/pa/egress. Production code anywhere under internal/pa, outside
// the egress package, must not reach for an unguarded client: the default
// client or transport, the package-level http.Get/Post/Head/PostForm
// helpers, or a hand-built http.Client or http.Transport.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// guardExempt lists files allowed to build their own HTTP client, with the
// reason. Paths are relative to internal/pa.
var guardExempt = map[string]string{
	// The Telegram Bot API client (getWebhookInfo) talks to the fixed Bot
	// API host with the bot token, not to a catalog MCP server, so T9's
	// per-server allowlist does not describe it. #1313 makes that client
	// bounded on its own. If the file is not on this branch yet, the entry
	// exempts nothing.
	"webhookinfo.go": "Bot API client (#1313), not catalog egress",
}

var forbiddenHTTPSelectors = map[string]bool{
	"DefaultClient":    true,
	"DefaultTransport": true,
	"Get":              true,
	"Post":             true,
	"Head":             true,
	"PostForm":         true,
}

// scanHTTPUse returns one finding per unguarded use of net/http in f.
func scanHTTPUse(fset *token.FileSet, f *ast.File) []string {
	httpNames := map[string]bool{}
	for _, imp := range f.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil || path != "net/http" {
			continue
		}
		name := "http"
		if imp.Name != nil {
			name = imp.Name.Name
		}
		if name == "_" {
			continue
		}
		httpNames[name] = true
	}
	if len(httpNames) == 0 {
		return nil
	}
	isHTTP := func(e ast.Expr, sels ...string) (string, bool) {
		sel, ok := e.(*ast.SelectorExpr)
		if !ok {
			return "", false
		}
		id, ok := sel.X.(*ast.Ident)
		if !ok || !httpNames[id.Name] {
			return "", false
		}
		for _, s := range sels {
			if sel.Sel.Name == s {
				return s, true
			}
		}
		return "", false
	}
	var out []string
	report := func(n ast.Node, what string) {
		out = append(out, fset.Position(n.Pos()).String()+": "+what)
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.SelectorExpr:
			if id, ok := x.X.(*ast.Ident); ok && httpNames[id.Name] && forbiddenHTTPSelectors[x.Sel.Name] {
				report(x, "http."+x.Sel.Name)
			}
		case *ast.CompositeLit:
			if s, ok := isHTTP(x.Type, "Client", "Transport"); ok {
				report(x, "http."+s+"{} literal")
			}
		case *ast.CallExpr:
			if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "new" && len(x.Args) == 1 {
				if s, ok := isHTTP(x.Args[0], "Client", "Transport"); ok {
					report(x, "new(http."+s+")")
				}
			}
		}
		return true
	})
	return out
}

func TestPAEgressGuard(t *testing.T) {
	fset := token.NewFileSet()
	var findings []string
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path == "egress" || d.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if _, ok := guardExempt[filepath.ToSlash(path)]; ok {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if perr != nil {
			return perr
		}
		findings = append(findings, scanHTTPUse(fset, f)...)
		return nil
	})
	if err != nil {
		t.Fatalf("walk internal/pa: %v", err)
	}
	for _, f := range findings {
		t.Errorf("unguarded HTTP use under internal/pa (use internal/pa/egress): %s", f)
	}
}

// The guard is only a guard if it fires: each forbidden form is detected,
// including under an import alias, and ordinary net/http use is not.
func TestPAEgressGuardDetects(t *testing.T) {
	bad := map[string]string{
		"default client":    `package x; import "net/http"; var c = http.DefaultClient`,
		"default transport": `package x; import "net/http"; var t = http.DefaultTransport`,
		"get":               `package x; import "net/http"; func f() { http.Get("https://a") }`,
		"post":              `package x; import "net/http"; func f() { http.Post("https://a", "", nil) }`,
		"head":              `package x; import "net/http"; func f() { http.Head("https://a") }`,
		"postform":          `package x; import "net/http"; func f() { http.PostForm("https://a", nil) }`,
		"client literal":    `package x; import "net/http"; var c = &http.Client{}`,
		"transport literal": `package x; import "net/http"; var t = http.Transport{}`,
		"new client":        `package x; import "net/http"; var c = new(http.Client)`,
		"aliased":           `package x; import h "net/http"; var c = h.Client{Timeout: 1}`,
		"method value":      `package x; import "net/http"; var g = http.Get`,
	}
	for name, src := range bad {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, name+".go", src, 0)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := scanHTTPUse(fset, f); len(got) != 1 {
			t.Errorf("%s: want 1 finding, got %v", name, got)
		}
	}
	good := []string{
		`package x; import "net/http"; func f(c *http.Client, r *http.Request) { c.Do(r) }`,
		`package x; import "net/http"; var _ = http.MethodGet; var _ = http.StatusOK`,
		`package x; import "net/http"; func f(w http.ResponseWriter) { w.WriteHeader(200) }`,
		`package x; type http struct{ Client int }; var c = http.Client`,
	}
	for i, src := range good {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, "good.go", src, 0)
		if err != nil {
			t.Fatalf("good %d: %v", i, err)
		}
		if got := scanHTTPUse(fset, f); len(got) != 0 {
			t.Errorf("good %d: unexpected findings %v", i, got)
		}
	}
}
