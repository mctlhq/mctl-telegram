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
// the egress package, must not reach for an unguarded client or socket:
//
//   - http.DefaultClient, http.DefaultTransport, and the package-level
//     http.Get/Post/Head/PostForm helpers;
//   - an http.Client or http.Transport built by hand: a composite literal,
//     new(...), or a zero value declared by value (var c http.Client, a
//     struct field or parameter of type http.Client) whose methods then run
//     with the default transport;
//   - raw dials: net.Dial, net.DialTimeout, tls.Dial, tls.DialWithDialer,
//     and a net.Dialer built by hand;
//   - libraries that fall back to their own client: golang.org/x/oauth2
//     (http.DefaultClient unless the context carries oauth2.HTTPClient),
//     github.com/mark3labs/mcp-go/client and its transport package (a fresh
//     client unless transport.WithHTTPClient is passed), and
//     net/http/httputil.
//
// A file that genuinely needs one of these goes into guardExempt with a
// reason. A file exempted to use oauth2 or mcp-go must still hand those
// libraries an egress client: via ctx = context.WithValue(ctx,
// oauth2.HTTPClient, c) for oauth2, and transport.WithHTTPClient(c) for
// mcp-go. The exemption covers the import, not a bypass of the policy.

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

// guardExempt lists files allowed to build their own client, each with the
// reason. Paths are relative to internal/pa. An entry without a reason fails
// TestPAEgressGuardExemptionsHaveReasons.
var guardExempt = map[string]string{
	// The Telegram Bot API client (getWebhookInfo) talks to the fixed Bot
	// API host with the bot token, not to a catalog MCP server, so T9's
	// per-server allowlist does not describe it. #1313 makes that client
	// bounded on its own. If the file is not on this branch yet, the entry
	// exempts nothing.
	"webhookinfo.go": "Bot API client (#1313), not catalog egress",
}

// forbiddenSelectors maps an import path to the package-level identifiers
// that may not be referenced from it.
var forbiddenSelectors = map[string]map[string]bool{
	"net/http": {
		"DefaultClient": true, "DefaultTransport": true,
		"Get": true, "Post": true, "Head": true, "PostForm": true,
	},
	"net":        {"Dial": true, "DialTimeout": true},
	"crypto/tls": {"Dial": true, "DialWithDialer": true},
	// netsafe.Client is a public-address client without the per-server
	// allowlist; PurposeAddr and Unwrap stay usable.
	modulePath + "/internal/netsafe": {"Client": true},
}

// forbiddenTypes maps an import path to the types that may not be built by
// hand or declared by value.
var forbiddenTypes = map[string]map[string]bool{
	"net/http": {"Client": true, "Transport": true},
	"net":      {"Dialer": true},
}

// forbiddenImports are import paths (and everything below them) whose use
// falls back to an unguarded client.
//
// The list comes from a sweep of go.mod and internal/ (#1330 review): every
// direct dependency and every in-repo package that builds its own
// http.Client, falls back to http.DefaultClient, or dials a socket. Not
// listed: github.com/jackc/pgx and modernc.org/sqlite (database
// connections from operator config, not catalog egress) and
// github.com/gotd/td/tg (types only).
var forbiddenImports = []string{
	// Third-party clients that default to their own or the default client.
	"golang.org/x/oauth2",                     // http.DefaultClient unless ctx carries oauth2.HTTPClient
	"github.com/coreos/go-oidc",               // oidc.NewProvider: oauth2 ctx client, else DefaultClient
	"github.com/mark3labs/mcp-go/client",      // own client unless transport.WithHTTPClient
	"github.com/coder/websocket",              // websocket.Dial: DefaultClient unless opts.HTTPClient
	"golang.org/x/net/http2",                  // its own Transport and dialer
	"golang.org/x/net/websocket",              // dials directly
	"golang.org/x/net/proxy",                  // dialers by design
	"net/http/httputil",                       // reverse proxy on DefaultTransport
	"github.com/gotd/td/telegram",             // MTProto client, dials Telegram DCs
	"github.com/prometheus/client_golang/api", // HTTP API client
	// In-repo packages that build or default to their own client or dial.
	modulePath + "/internal/mcpprobe",          // MCP probe client
	modulePath + "/internal/oauth/cimd",        // defaults to netsafe.Client
	modulePath + "/internal/agentworker",       // http.DefaultClient fallback
	modulePath + "/internal/assistantregistry", // http.DefaultClient fallback
	modulePath + "/internal/workctx",           // http.DefaultClient fallback
	modulePath + "/internal/botapi",            // http.DefaultClient fallback
	modulePath + "/internal/bot",               // long-poll client
	modulePath + "/internal/auth/k8ssa",        // JWKS client
	modulePath + "/internal/auth/telegramoidc", // go-oidc provider client
	modulePath + "/internal/glovo/authn",       // JWKS client
	modulePath + "/internal/glovo/mctlapi",     // API client
	modulePath + "/internal/events",            // Valkey dialer
	modulePath + "/internal/telegram",          // MTProto pool and media fetch client
	modulePath + "/internal/localbridgetest",   // test client with cookie jar
}

const modulePath = "github.com/mctlhq/mctl-telegram"

// watchedForDotImport reports whether a dot-import of path would hide a
// watched identifier from the selector checks.
func watchedForDotImport(path string) bool {
	_, sel := forbiddenSelectors[path]
	_, typ := forbiddenTypes[path]
	return sel || typ
}

func importForbidden(path string) bool {
	for _, p := range forbiddenImports {
		if path == p || strings.HasPrefix(path, p+"/") {
			return true
		}
	}
	return false
}

// scanHTTPUse returns one finding per unguarded client, socket or library
// use in f.
func scanHTTPUse(fset *token.FileSet, f *ast.File) []string {
	var out []string
	report := func(n ast.Node, what string) {
		out = append(out, fset.Position(n.Pos()).String()+": "+what)
	}
	local := map[string]string{} // local package name -> import path
	for _, imp := range f.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		if importForbidden(path) {
			report(imp, "import "+strconv.Quote(path))
		} else if imp.Name != nil && imp.Name.Name == "." && watchedForDotImport(path) {
			// A dot-import makes Client, Get, Dial ... bare identifiers the
			// selector checks cannot see.
			report(imp, "dot-import "+strconv.Quote(path))
		}
		name := path[strings.LastIndexByte(path, '/')+1:]
		if path == "crypto/tls" {
			name = "tls"
		}
		if imp.Name != nil {
			name = imp.Name.Name
		}
		if name == "_" || name == "." {
			continue
		}
		local[name] = path
	}
	// pkgSel resolves e to (import path, selector) when it is pkg.Name.
	pkgSel := func(e ast.Expr) (string, string, bool) {
		sel, ok := e.(*ast.SelectorExpr)
		if !ok {
			return "", "", false
		}
		id, ok := sel.X.(*ast.Ident)
		if !ok {
			return "", "", false
		}
		path, ok := local[id.Name]
		if !ok {
			return "", "", false
		}
		return path, sel.Sel.Name, true
	}
	// isForbiddenType reports a by-value forbidden type, looking through
	// containers that hold values ([N]T, []T, map[K]V, chan T, (T)). A
	// pointer is not looked through: *http.Client is the allowed form.
	var isForbiddenType func(e ast.Expr) (string, bool)
	isForbiddenType = func(e ast.Expr) (string, bool) {
		switch x := e.(type) {
		case *ast.ArrayType:
			return isForbiddenType(x.Elt)
		case *ast.MapType:
			if t, ok := isForbiddenType(x.Key); ok {
				return t, true
			}
			return isForbiddenType(x.Value)
		case *ast.ChanType:
			return isForbiddenType(x.Value)
		case *ast.ParenExpr:
			return isForbiddenType(x.X)
		}
		path, name, ok := pkgSel(e)
		if ok && forbiddenTypes[path][name] {
			return path + "." + name, true
		}
		return "", false
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.SelectorExpr:
			if path, name, ok := pkgSel(x); ok && forbiddenSelectors[path][name] {
				report(x, path+"."+name)
			}
		case *ast.CompositeLit:
			if t, ok := isForbiddenType(x.Type); ok {
				report(x, t+"{} literal")
			}
		case *ast.CallExpr:
			if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "new" && len(x.Args) == 1 {
				if t, ok := isForbiddenType(x.Args[0]); ok {
					report(x, "new("+t+")")
				}
			}
		case *ast.ValueSpec:
			// var c http.Client: a usable zero value on the default transport.
			if t, ok := isForbiddenType(x.Type); ok {
				report(x, "var of type "+t)
			}
		case *ast.TypeSpec:
			// type C = http.Client, type C http.Client: a by-value client
			// under another name.
			if t, ok := isForbiddenType(x.Type); ok {
				report(x, "type over "+t)
			}
		case *ast.Field:
			// A struct field, parameter or result of type http.Client by
			// value. A pointer (*http.Client) is how an egress client is
			// passed around and is fine.
			if t, ok := isForbiddenType(x.Type); ok {
				report(x, "field of type "+t)
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
		"default client":             `package x; import "net/http"; var c = http.DefaultClient`,
		"default transport":          `package x; import "net/http"; var t = http.DefaultTransport`,
		"get":                        `package x; import "net/http"; func f() { http.Get("https://a") }`,
		"post":                       `package x; import "net/http"; func f() { http.Post("https://a", "", nil) }`,
		"head":                       `package x; import "net/http"; func f() { http.Head("https://a") }`,
		"postform":                   `package x; import "net/http"; func f() { http.PostForm("https://a", nil) }`,
		"client literal":             `package x; import "net/http"; var c = &http.Client{}`,
		"transport literal":          `package x; import "net/http"; var t = http.Transport{}`,
		"new client":                 `package x; import "net/http"; var c = new(http.Client)`,
		"aliased":                    `package x; import h "net/http"; var c = h.Client{Timeout: 1}`,
		"method value":               `package x; import "net/http"; var g = http.Get`,
		"zero-value var":             `package x; import "net/http"; func f(u string) { var c http.Client; c.Get(u) }`,
		"struct field":               `package x; import "net/http"; type s struct{ c http.Client }`,
		"transport field":            `package x; import "net/http"; type s struct{ t http.Transport }`,
		"param by value":             `package x; import "net/http"; func f(c http.Client) {}`,
		"net.Dial":                   `package x; import "net"; func f() { net.Dial("tcp", "a:443") }`,
		"net.DialTimeout":            `package x; import "net"; func f() { net.DialTimeout("tcp", "a:443", 0) }`,
		"tls.Dial":                   `package x; import "crypto/tls"; func f() { tls.Dial("tcp", "a:443", nil) }`,
		"tls.DialWithDialer":         `package x; import "crypto/tls"; func f() { tls.DialWithDialer(nil, "tcp", "a:443", nil) }`,
		"net.Dialer literal":         `package x; import "net"; var d = &net.Dialer{}`,
		"httputil":                   `package x; import "net/http/httputil"; var _ = httputil.NewSingleHostReverseProxy`,
		"oauth2":                     `package x; import "golang.org/x/oauth2"; func f(c *oauth2.Config) { c.Exchange(nil, "") }`,
		"oauth2 subpackage":          `package x; import "golang.org/x/oauth2/clientcredentials"; var _ clientcredentials.Config`,
		"mcp-go transport":           `package x; import "github.com/mark3labs/mcp-go/client/transport"; var _ = transport.NewStreamableHTTP`,
		"mcp-go client":              `package x; import "github.com/mark3labs/mcp-go/client"; var _ = client.NewStreamableHttpClient`,
		"aliased oauth2":             `package x; import o "golang.org/x/oauth2"; var _ o.Config`,
		"go-oidc":                    `package x; import "github.com/coreos/go-oidc/v3/oidc"; var _ = oidc.NewProvider`,
		"coder websocket":            `package x; import "github.com/coder/websocket"; var _ = websocket.Dial`,
		"x/net http2":                `package x; import "golang.org/x/net/http2"; var _ http2.Transport`,
		"x/net websocket":            `package x; import "golang.org/x/net/websocket"; var _ = websocket.Dial`,
		"x/net proxy":                `package x; import "golang.org/x/net/proxy"; var _ = proxy.FromEnvironment`,
		"gotd telegram":              `package x; import "github.com/gotd/td/telegram"; var _ telegram.Options`,
		"prometheus api":             `package x; import "github.com/prometheus/client_golang/api"; var _ api.Config`,
		"internal mcpprobe":          `package x; import "github.com/mctlhq/mctl-telegram/internal/mcpprobe"; var _ = mcpprobe.X`,
		"internal oauth/cimd":        `package x; import "github.com/mctlhq/mctl-telegram/internal/oauth/cimd"; var _ = cimd.X`,
		"internal agentworker":       `package x; import "github.com/mctlhq/mctl-telegram/internal/agentworker"; var _ = agentworker.X`,
		"internal assistantregistry": `package x; import "github.com/mctlhq/mctl-telegram/internal/assistantregistry"; var _ = assistantregistry.X`,
		"internal workctx":           `package x; import "github.com/mctlhq/mctl-telegram/internal/workctx"; var _ = workctx.X`,
		"internal botapi":            `package x; import "github.com/mctlhq/mctl-telegram/internal/botapi"; var _ = botapi.X`,
		"internal bot":               `package x; import "github.com/mctlhq/mctl-telegram/internal/bot"; var _ = bot.X`,
		"internal auth/k8ssa":        `package x; import "github.com/mctlhq/mctl-telegram/internal/auth/k8ssa"; var _ = k8ssa.X`,
		"internal auth/telegramoidc": `package x; import "github.com/mctlhq/mctl-telegram/internal/auth/telegramoidc"; var _ = telegramoidc.X`,
		"internal glovo/authn":       `package x; import "github.com/mctlhq/mctl-telegram/internal/glovo/authn"; var _ = authn.X`,
		"internal glovo/mctlapi":     `package x; import "github.com/mctlhq/mctl-telegram/internal/glovo/mctlapi"; var _ = mctlapi.X`,
		"internal events":            `package x; import "github.com/mctlhq/mctl-telegram/internal/events"; var _ = events.X`,
		"internal telegram":          `package x; import "github.com/mctlhq/mctl-telegram/internal/telegram"; var _ = telegram.X`,
		"internal localbridgetest":   `package x; import "github.com/mctlhq/mctl-telegram/internal/localbridgetest"; var _ = localbridgetest.X`,
		"netsafe.Client":             `package x; import "github.com/mctlhq/mctl-telegram/internal/netsafe"; var _ = netsafe.Client`,
		"dot http":                   `package x; import . "net/http"`,
		"dot net":                    `package x; import . "net"`,
		"dot tls":                    `package x; import . "crypto/tls"`,
		"dot netsafe":                `package x; import . "github.com/mctlhq/mctl-telegram/internal/netsafe"`,
		"type alias":                 `package x; import "net/http"; type C = http.Client`,
		"defined type":               `package x; import "net/http"; type C http.Transport`,
		"slice var":                  `package x; import "net/http"; var cs []http.Client`,
		"array field":                `package x; import "net/http"; type s struct{ cs [2]http.Client }`,
		"map value":                  `package x; import "net/http"; var m map[string]http.Client`,
		"map key":                    `package x; import "net"; var m map[net.Dialer]int`,
		"chan param":                 `package x; import "net/http"; func f(c chan http.Transport) {}`,
		"paren type":                 `package x; import "net/http"; var c (http.Client)`,
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
		`package x; import "net/http"; type s struct{ c *http.Client }; func f(c *http.Client, t *http.Transport) {}`,
		`package x; import "net/http"; var c *http.Client`,
		`package x; import "net"; func f(ip net.IP, a net.Addr) { _ = net.ParseIP("1.1.1.1") }`,
		`package x; import "crypto/tls"; var _ = tls.VersionTLS12; var c *tls.Config`,
		`package x; import "github.com/mark3labs/mcp-go/mcp"; var _ mcp.Tool`,
		`package x; import "net/http"; var cs []*http.Client; var m map[string]*http.Client; type P = *http.Client`,
		`package x; import "github.com/mctlhq/mctl-telegram/internal/netsafe"; var _ = netsafe.PublicAddr; var _ = netsafe.Unwrap`,
		`package x; import "github.com/mctlhq/mctl-telegram/internal/telegramx"; var _ = telegramx.A`,
		`package x; import . "strings"; var _ = ToLower`,
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

func TestPAEgressGuardExemptionsHaveReasons(t *testing.T) {
	for file, reason := range guardExempt {
		if strings.TrimSpace(reason) == "" {
			t.Errorf("guardExempt[%q] has no reason", file)
		}
	}
}
