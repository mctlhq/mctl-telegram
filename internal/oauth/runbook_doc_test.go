package oauth

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

// TestRunbookDocumentsCallbackReasons is T15: every reason* const declared in
// server.go must appear in docs/runbook.md's rejection-reasons table, so a
// new const added on this side of the deliberate internal/web/internal/oauth
// duplication cannot silently drift from the documentation. Also asserts the
// startup headline "auth provider init failed" (cmd/server/main.go) is
// documented. Modelled on troubleshooting_doc_test.go.
func TestRunbookDocumentsCallbackReasons(t *testing.T) {
	reasons := declaredReasons(t)

	data, err := os.ReadFile("../../docs/runbook.md")
	if err != nil {
		t.Fatalf("failed to read docs/runbook.md: %v", err)
	}
	content := string(data)

	if !strings.Contains(content, `id="connectrejectionreasons"`) {
		t.Error(`docs/runbook.md missing anchor: id="connectrejectionreasons"`)
	}

	for name, reason := range reasons {
		if !strings.Contains(content, "`"+reason+"`") {
			t.Errorf("docs/runbook.md does not mention %s (%q)", name, reason)
		}
	}

	const startupHeadline = "auth provider init failed"
	if !strings.Contains(content, startupHeadline) {
		t.Errorf("docs/runbook.md does not mention the startup headline %q", startupHeadline)
	}
}

// declaredReasons parses server.go and returns the value of every top-level
// string const whose name starts with "reason", so the test follows the
// const block itself instead of a hand-maintained copy of it. A parse that
// finds none is a failed read, not an empty vocabulary.
func declaredReasons(t *testing.T) map[string]string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "server.go", nil, 0)
	if err != nil {
		t.Fatalf("parse server.go: %v", err)
	}
	out := map[string]string{}
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs := spec.(*ast.ValueSpec)
			for i, name := range vs.Names {
				if !strings.HasPrefix(name.Name, "reason") || i >= len(vs.Values) {
					continue
				}
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				v, err := strconv.Unquote(lit.Value)
				if err != nil {
					t.Fatalf("unquote %s: %v", name.Name, err)
				}
				out[name.Name] = v
			}
		}
	}
	if len(out) == 0 {
		t.Fatalf("found no reason* consts in server.go; the parse or the naming convention changed")
	}
	return out
}
