package bridgeclient_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/bridgeclient"
	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/bridgeclient/bridgefake"
	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/leakcheck"
)

var canary = leakcheck.Canaries[0]

func fileCred(t *testing.T, v string) bridgeclient.FileCredential {
	t.Helper()
	p := filepath.Join(t.TempDir(), "cred")
	if err := os.WriteFile(p, []byte(v), 0o600); err != nil {
		t.Fatal(err)
	}
	return bridgeclient.FileCredential{Path: p}
}

func setup(t *testing.T) (*bridgefake.Fake, *bridgeclient.Client) {
	t.Helper()
	f := bridgefake.New()
	t.Cleanup(f.Close)
	f.AddProvider(canary, "provider:glovo", "tnr_0123456789abcdef0123")
	o, err := bridgeclient.ParseOrigin(f.URL())
	if err != nil {
		t.Fatal(err)
	}
	return f, bridgeclient.New(o, fileCred(t, canary), nil)
}

func TestRoutes(t *testing.T) {
	f, c := setup(t)
	ctx := context.Background()
	id := f.Enqueue(bridgefake.Command("place_order_fake"))
	resp, err := c.Claim(ctx, 4)
	if err != nil || len(resp.Commands) != 1 {
		t.Fatalf("claim: %v %d", err, len(resp.Commands))
	}
	var doc map[string]any
	_ = json.Unmarshal(resp.Commands[0], &doc)
	tok := doc["lease_token"].(string)
	p, err := c.WritePermit(ctx, id, tok)
	if err != nil || p.CommandID != id || p.FenceRef == "" {
		t.Fatalf("permit: %+v %v", p, err)
	}
	body := fmt.Sprintf(`{"schema_version":"bridge.mctl.ai/v1alpha1","command_id":%q,"execution_id":"we_0123456789abcdef0123","lease_token":%q,"attempt":1,"worker_identity":"provider:glovo","outcome":"succeeded","provider_effect":"applied","completed_at":"2026-11-08T10:01:00Z"}`, id, tok)
	ack, err := c.SubmitResult(ctx, id, []byte(body))
	if err != nil || ack.Status != "completed" || ack.Replayed {
		t.Fatalf("result: %+v %v", ack, err)
	}
	ack, err = c.SubmitResult(ctx, id, []byte(body))
	if err != nil || !ack.Replayed {
		t.Fatalf("replay: %+v %v", ack, err)
	}
}

func TestAPIErrorShapes(t *testing.T) {
	f, c := setup(t)
	f.FailNext("claim", bridgefake.Fault{Status: 429, Body: "plain text", RetryAfter: "5"})
	_, err := c.Claim(context.Background(), 1)
	var ae *bridgeclient.APIError
	if !errors.As(err, &ae) || ae.Status != 429 || ae.Code != "" || ae.RetryAfter.Seconds() != 5 {
		t.Fatalf("429: %#v", err)
	}
	f.FailNext("claim", bridgefake.Fault{Status: 409, Body: `{"error":"e","code":"lease_stale"}`})
	_, err = c.Claim(context.Background(), 1)
	if !errors.As(err, &ae) || ae.Code != "lease_stale" {
		t.Fatalf("code: %#v", err)
	}
	f.FailNext("claim", bridgefake.Fault{Status: 401, Body: `{"error":"unauthorized"}`})
	_, err = c.Claim(context.Background(), 1)
	if !errors.As(err, &ae) || ae.Status != 401 || ae.Code != "" {
		t.Fatalf("401: %#v", err)
	}
	if strings.Contains(err.Error(), "unauthorized") {
		t.Fatal("the body must not be kept")
	}
}

// T24: every malformed claim body is an error, never an empty batch.
func TestMalformedClaimBodies(t *testing.T) {
	f, c := setup(t)
	big := `{"schema_version":"bridge.mctl.ai/v1alpha1","commands":[],"pad":"` + strings.Repeat("a", 64<<10) + `"}`
	for name, body := range map[string]string{
		"missing":  `{"schema_version":"bridge.mctl.ai/v1alpha1"}`,
		"null":     `{"schema_version":"bridge.mctl.ai/v1alpha1","commands":null}`,
		"object":   `{"schema_version":"bridge.mctl.ai/v1alpha1","commands":{}}`,
		"extra":    `{"schema_version":"bridge.mctl.ai/v1alpha1","commands":[],"x":1}`,
		"trailing": `{"schema_version":"bridge.mctl.ai/v1alpha1","commands":[]}garbage`,
		"unknown":  `{"schema_version":"bridge.mctl.ai/claim/v1alpha3","commands":[]}`,
		"cap":      big,
		"empty":    ``,
	} {
		f.SetClaimBody([]byte(body))
		resp, err := c.Claim(context.Background(), 1)
		if err == nil || !errors.Is(err, bridgeclient.ErrMalformed) || resp.Commands != nil {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	f.SetClaimBody([]byte(`{"schema_version":"bridge.mctl.ai/claim/v1alpha2","commands":[]}`))
	if resp, err := c.Claim(context.Background(), 1); err != nil || resp.SchemaVersion != "bridge.mctl.ai/claim/v1alpha2" {
		t.Fatalf("claim/v1alpha2: %v", err)
	}
}

// T17: egress is pinned to the configured origin.
func TestEgressPinned(t *testing.T) {
	var hitsB atomic.Int32
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hitsB.Add(1) }))
	defer b.Close()
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, b.URL+"/api/v1/bridge/commands/claim", http.StatusFound)
	}))
	defer a.Close()
	var proxyHits atomic.Int32
	px := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { proxyHits.Add(1) }))
	defer px.Close()
	t.Setenv("HTTP_PROXY", px.URL)
	t.Setenv("HTTPS_PROXY", px.URL)
	t.Setenv("NO_PROXY", "")

	origin, _ := bridgeclient.ParseOrigin(a.URL)
	hc := bridgeclient.NewHTTPClient(origin)
	req, _ := http.NewRequest(http.MethodPost, b.URL+"/api/v1/bridge/commands/claim", nil)
	if _, err := hc.Do(req); err == nil || !errors.Is(err, bridgeclient.ErrOrigin) {
		t.Fatalf("other origin must be refused before dialing: %v", err)
	}
	req, _ = http.NewRequest(http.MethodPost, a.URL+"/somewhere/else", nil)
	if _, err := hc.Do(req); !errors.Is(err, bridgeclient.ErrOrigin) {
		t.Fatalf("path outside the bridge routes: %v", err)
	}
	c := bridgeclient.New(origin, fileCred(t, canary), nil)
	if _, err := c.Claim(context.Background(), 1); err == nil {
		t.Fatal("a redirect must not be followed")
	}
	if hitsB.Load() != 0 || proxyHits.Load() != 0 {
		t.Fatalf("B hits = %d, proxy hits = %d, want 0", hitsB.Load(), proxyHits.Load())
	}
	for _, bad := range []string{"https://x.example/path", "https://x.example/?q=1", "https://u:p@x.example", "http://x.example", "ftp://127.0.0.1", "x.example", ""} {
		if _, err := bridgeclient.ParseOrigin(bad); err == nil {
			t.Errorf("origin %q must be refused", bad)
		}
	}
	for _, ok := range []string{"https://api.mctl.ai", "https://api.mctl.ai:8443/", "http://127.0.0.1:9", "http://localhost:80", "http://[::1]:9"} {
		if _, err := bridgeclient.ParseOrigin(ok); err != nil {
			t.Errorf("origin %q: %v", ok, err)
		}
	}
}

func TestCredentialRereadAndRedacted(t *testing.T) {
	f, _ := setup(t)
	o, _ := bridgeclient.ParseOrigin(f.URL())
	cred := fileCred(t, "wrong-credential")
	c := bridgeclient.New(o, cred, nil)
	_, err := c.Claim(context.Background(), 1)
	var ae *bridgeclient.APIError
	if !errors.As(err, &ae) || ae.Status != 401 {
		t.Fatalf("wrong credential: %v", err)
	}
	if err := os.WriteFile(cred.Path, []byte("  "+canary+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Claim(context.Background(), 1); err != nil {
		t.Fatalf("rotation without restart: %v", err)
	}
	s, _ := cred.Get()
	j, _ := json.Marshal(s)
	for _, out := range []string{s.String(), fmt.Sprintf("%v %+v %#v %s", s, s, s, s), string(j)} {
		if strings.Contains(out, canary) {
			t.Fatalf("credential formatted: %s", out)
		}
	}
	if err := os.WriteFile(cred.Path, []byte(strings.Repeat("a", 5000)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := cred.Get(); err == nil {
		t.Fatal("oversized credential must fail")
	}
}
