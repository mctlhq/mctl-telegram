package mcpprobe

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// credentialish matches the field and parameter names an OAuth client
// credential travels under. It is built from fragments so that this file's
// own source does not contain the literal it forbids.
var credentialish = regexp.MustCompile(`(?i)client[_-]?` + "secret" + `|client[_-]?credential`)

// TestOptionsCannotAcceptAClientCredential proves the probe has no way to be
// handed an OAuth client credential in the first place.
//
// This is the structural replacement for grepping the source. A grep asserts
// that today's code does not mention a string; this asserts that the API has
// no place to put one, which stays true as the implementation changes and
// fails loudly when someone adds the field.
func TestOptionsCannotAcceptAClientCredential(t *testing.T) {
	typ := reflect.TypeOf(Options{})
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		if credentialish.MatchString(name) {
			t.Errorf("Options.%s can carry an OAuth client credential", name)
		}
	}
	// Token is the one credential the probe accepts, and it is a bearer for
	// the resource, never a client credential for a token exchange. Pin its
	// role so a later change cannot repurpose it quietly.
	field, ok := typ.FieldByName("Token")
	if !ok {
		t.Fatal("Options.Token is gone; the bearer contract changed")
	}
	if field.Type.Kind() != reflect.String {
		t.Errorf("Options.Token is %s, want a plain string bearer", field.Type)
	}
}

// TestReportCannotCarryAClientCredential walks the whole report tree.
func TestReportCannotCarryAClientCredential(t *testing.T) {
	seen := map[reflect.Type]bool{}
	var walk func(typ reflect.Type, path string)
	walk = func(typ reflect.Type, path string) {
		if seen[typ] {
			return
		}
		seen[typ] = true
		switch typ.Kind() {
		case reflect.Ptr, reflect.Slice, reflect.Array:
			walk(typ.Elem(), path+"[]")
		case reflect.Map:
			walk(typ.Elem(), path+".value")
		case reflect.Struct:
			for i := 0; i < typ.NumField(); i++ {
				f := typ.Field(i)
				// A boolean named for a credential is a classification, not
				// a carrier: RequiresClientCredential says the server wants
				// one, and a bool has nowhere to put it. Only a field that
				// could actually hold a value is a finding.
				if canHoldAValue(f.Type) &&
					(credentialish.MatchString(f.Name) || credentialish.MatchString(f.Tag.Get("json"))) {
					t.Errorf("%s.%s is a %s that can carry an OAuth client credential", path, f.Name, f.Type)
				}
				walk(f.Type, path+"."+f.Name)
			}
		}
	}
	walk(reflect.TypeOf(Report{}), "Report")
}

// canHoldAValue reports whether a type could store a credential. Booleans
// and numbers cannot; strings, byte slices and anything open-ended can.
func canHoldAValue(typ reflect.Type) bool {
	switch typ.Kind() {
	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64:
		return false
	case reflect.Ptr, reflect.Slice, reflect.Array:
		return canHoldAValue(typ.Elem())
	}
	return true
}

// TestProbeNeverSendsACredentialOnTheWire is the behavioural half: across a
// full run against a server that demands a client credential, every request
// the probe made is inspected. None may carry one, in any form, and none may
// reach a token or registration endpoint.
func TestProbeNeverSendsACredentialOnTheWire(t *testing.T) {
	surface, mcpURL := newAuthSurface(t, func(a *authSurface) {
		a.authMethods = []string{"client_" + "secret_basic"}
	})

	// Run the full probe, not just the OAuth half, so the transport is
	// covered as well as discovery.
	report, err := Run(context.Background(), Options{
		URL: mcpURL, Mode: ModeModern, Token: "bearer-for-the-resource",
		Source: SourceInProcess,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	for _, r := range surface.recorded() {
		if credentialish.MatchString(r.body) {
			t.Errorf("%s %s carried a client credential in its body", r.method, r.path)
		}
		for name, values := range r.header {
			if credentialish.MatchString(name) {
				t.Errorf("%s %s carried header %s", r.method, r.path, name)
			}
			for _, v := range values {
				if credentialish.MatchString(v) {
					t.Errorf("%s %s header %s carried a client credential", r.method, r.path, name)
				}
			}
		}
		if strings.Contains(r.path, "/oauth/token") ||
			strings.Contains(r.path, "/oauth/register") ||
			strings.Contains(r.path, "/oauth/authorize") {
			t.Errorf("probe contacted an authorization endpoint: %s %s", r.method, r.path)
		}
	}

	// And the finding still lands in the report, which is the useful half.
	if !report.OAuth.AuthorizationServer.RequiresClientCredential {
		t.Error("the credential requirement was not reported")
	}

	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// The advertised method list is echoed verbatim, so the report does
	// mention the method's name. What it must never contain is a value: the
	// probe holds no credential to leak.
	var round map[string]any
	if err := json.Unmarshal(encoded, &round); err != nil {
		t.Fatalf("round-trip: %v", err)
	}
	if strings.Contains(string(encoded), "bearer-for-the-resource") {
		t.Error("the report leaked the bearer token")
	}
}

// TestProbeDoesNotPersistAnything guards the third verb in the claim: the
// probe holds no state on disk, so there is nowhere for a credential to be
// written even accidentally.
func TestProbeDoesNotPersistAnything(t *testing.T) {
	dir := t.TempDir()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })

	_, url := newFake(t, func(f *fakeServer) { f.modern = true })
	if _, err := Run(context.Background(), Options{
		URL: url, Mode: ModeModern, Token: "a-token", Source: SourceInProcess, SkipOAuth: true,
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}

	entries, err := filepath.Glob(filepath.Join(dir, "*"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("probe wrote %v; it must hold no state on disk", entries)
	}
}

// TestPackageIntroducesNoDeprecatedTransport is the narrow textual check that
// a type walk cannot express: the spike must not grow a second transport or
// bake in a deployment's hostname. Everything else about credentials is
// covered structurally above.
func TestPackageIntroducesNoDeprecatedTransport(t *testing.T) {
	forbidden := map[string]*regexp.Regexp{
		"a legacy SSE transport":        regexp.MustCompile(`NewSSEServer|NewSSEClient|transport\.NewSSE|"/sse"`),
		"a hard-coded gateway hostname": regexp.MustCompile(`mcp-enterprise\.|tg\.mctl\.ai`),
	}
	for _, dir := range []string{".", "../../cmd/mcpprobe"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}
		for _, e := range entries {
			// Test files are excluded: a guard that scans for a pattern
			// necessarily contains that pattern, and this scan is about the
			// shipped implementation.
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			path := filepath.Join(dir, e.Name())
			body, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			for what, re := range forbidden {
				if re.Match(body) {
					t.Errorf("%s introduces %s", path, what)
				}
			}
		}
	}
}

// TestDefaultClientDoesNotFollowRedirects keeps a probe pointed where the
// operator aimed it. A followed redirect would measure a different endpoint
// than the one named in the report.
func TestDefaultClientDoesNotFollowRedirects(t *testing.T) {
	o := Options{URL: "https://example.test/mcp", Mode: ModeModern}
	if err := o.normalize(); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if o.HTTPClient.CheckRedirect == nil {
		t.Fatal("default client follows redirects")
	}
	if err := o.HTTPClient.CheckRedirect(nil, nil); err != http.ErrUseLastResponse {
		t.Errorf("CheckRedirect = %v, want ErrUseLastResponse", err)
	}
}
