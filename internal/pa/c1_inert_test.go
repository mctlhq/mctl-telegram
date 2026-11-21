package pa

// c1_inert_test.go keeps the production implementations of #1318 slice C1
// out of the running service until slice C2 wires them: the tools runtime
// config, the OAuth token and revocation client, the Messenger with its
// web_app button and the tg account source. Each identifier below may be
// used only in the files that declare or implement it. Slice C2 removes an
// entry when it wires that piece behind PA_ENABLED.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// c1Idents maps each C1 identifier to the module-relative files allowed to
// name it.
var c1Idents = map[string]map[string]bool{
	"LoadPATools":       {"internal/config/config_pa_tools.go": true},
	"NewOAuthClient":    {"internal/pa/linking/oauthclient.go": true},
	"OAuthClient":       {"internal/pa/linking/oauthclient.go": true},
	"BotMessenger":      {"internal/pa/linking/messenger.go": true},
	"SendConnectButton": {"internal/pa/linking/messenger.go": true},
	"IdentityAccounts":  {"internal/pa/connector/identity.go": true},
	"SendWebApp":        {"internal/pa/output/sender.go": true, "internal/pa/linking/messenger.go": true},
	"WebAppURL":         {"internal/pa/output/sender.go": true},
	"TextConnectOpen":   {"internal/pa/output/safetext/templates.go": true, "internal/pa/linking/messenger.go": true},
	"LabelConnect":      {"internal/pa/output/safetext/templates.go": true, "internal/pa/linking/messenger.go": true},
}

// TestC1SymbolsNotWiredAtRuntime walks every non-test Go file of the module
// and fails on any use of a C1 identifier outside its files.
func TestC1SymbolsNotWiredAtRuntime(t *testing.T) {
	root := moduleRoot(t)
	fset := token.NewFileSet()
	checked := 0
	seen := map[string]bool{}
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
		for _, v := range c1Violations(fset, f, rel, seen) {
			t.Error(v)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked < 50 {
		t.Fatalf("parsed %d files: the walk did not cover the module", checked)
	}
	// Every identifier must still exist where it is allowed, or the entry
	// guards nothing.
	for id := range c1Idents {
		if !seen[id] {
			t.Errorf("%s is not found in its allowed files: update c1Idents", id)
		}
	}
}

// c1Violations reports every identifier of c1Idents in f outside its
// allowed files, and marks those it sees in an allowed file.
func c1Violations(fset *token.FileSet, f *ast.File, rel string, seen map[string]bool) []string {
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		id, ok := n.(*ast.Ident)
		if !ok {
			return true
		}
		allow, ok := c1Idents[id.Name]
		if !ok {
			return true
		}
		if allow[rel] {
			seen[id.Name] = true
			return true
		}
		out = append(out, fmt.Sprintf("%s: uses %s; slice C1 code is not wired at runtime until C2 (#1318)", fset.Position(id.Pos()), id.Name))
		return true
	})
	return out
}

// TestC1Violations_Detects proves the checker both ways.
func TestC1Violations_Detects(t *testing.T) {
	bad := map[string]string{
		"config call":    `func f(c *config.Config) { _, _ = config.LoadPATools(c, os.Getenv) }`,
		"oauth client":   `func f() { _, _ = linking.NewOAuthClient(nil, nil) }`,
		"messenger":      `var m = linking.BotMessenger{}`,
		"web app send":   `func f(s *output.Sender) { _ = s.SendWebApp(nil, 1, safetext.Text{}, safetext.Template{}, "") }`,
		"web app config": `var c = output.Config{WebAppURL: "x"}`,
		"identity":       `var a linking.AccountSource = connector.IdentityAccounts{}`,
		"template":       `var x = safetext.TextConnectOpen`,
	}
	for name, src := range bad {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, "x.go", "package server\n"+src, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		if v := c1Violations(fset, f, "cmd/server/pa_wiring.go", map[string]bool{}); len(v) == 0 {
			t.Errorf("%s: not reported", name)
		}
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "messenger.go", "package linking\nfunc (m BotMessenger) SendConnectButton() error { return m.Sender.SendWebApp(nil, 1, safetext.ServerText(safetext.TextConnectOpen), safetext.LabelConnect, \"\") }", parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	if v := c1Violations(fset, f, "internal/pa/linking/messenger.go", map[string]bool{}); len(v) != 0 {
		t.Errorf("allowed file reported: %v", v)
	}
}
