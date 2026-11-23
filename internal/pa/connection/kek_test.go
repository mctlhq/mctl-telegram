package connection_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/config"
	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
)

// TestKEK_LocalTiersMatchConfig keeps LocalKEKTiers equal to preview plus
// config.LocalTiers.
func TestKEK_LocalTiersMatchConfig(t *testing.T) {
	want := append([]string{"preview"}, config.LocalTiers...)
	if !slices.Equal(connection.LocalKEKTiers, want) {
		t.Fatalf("LocalKEKTiers = %v, want %v", connection.LocalKEKTiers, want)
	}
}

// TestKEK_ProductionRefusesLocal is the T3 startup check: Vault transit is
// mandatory in production. A local (KV) KEK is accepted only when ENV names
// preview or a local/test tier; an unset ENV is production. An empty or
// unknown mode is refused, never defaulted.
func TestKEK_ProductionRefusesLocal(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(testKEKKey)
	for _, tc := range []struct {
		name string
		env  map[string]string
		ok   bool
	}{
		{"no mode", map[string]string{"ENV": "preview", "PA_KEK_LOCAL_KEY": key}, false},
		{"unknown mode", map[string]string{"PA_KEK_MODE": "kv", "ENV": "preview", "PA_KEK_LOCAL_KEY": key}, false},
		{"local with ENV unset", map[string]string{"PA_KEK_MODE": "local", "PA_KEK_LOCAL_KEY": key}, false},
		{"local in production", map[string]string{"PA_KEK_MODE": "local", "ENV": "production", "PA_KEK_LOCAL_KEY": key}, false},
		{"local in a lookalike tier", map[string]string{"PA_KEK_MODE": "local", "ENV": "preview-prod", "PA_KEK_LOCAL_KEY": key}, false},
		{"local on preview, short key", map[string]string{"PA_KEK_MODE": "local", "ENV": "preview", "PA_KEK_LOCAL_KEY": "c2hvcnQ="}, false},
		{"local on preview", map[string]string{"PA_KEK_MODE": "local", "ENV": "Preview", "PA_KEK_LOCAL_KEY": key}, true},
		{"local on ci", map[string]string{"PA_KEK_MODE": "local", "ENV": "ci", "PA_KEK_LOCAL_KEY": key}, true},
		{"transit over http", map[string]string{"PA_KEK_MODE": "transit", "PA_KEK_TRANSIT_ADDR": "http://vault.example", "PA_KEK_TRANSIT_MOUNT": "transit", "PA_KEK_TRANSIT_KEY": "pa"}, false},
		{"transit from env alone (no token source, no client)", map[string]string{"PA_KEK_MODE": "transit", "PA_KEK_TRANSIT_ADDR": "https://vault.example", "PA_KEK_TRANSIT_MOUNT": "transit", "PA_KEK_TRANSIT_KEY": "pa"}, false},
		{"transit without key name", map[string]string{"PA_KEK_MODE": "transit", "PA_KEK_TRANSIT_ADDR": "https://vault.example", "PA_KEK_TRANSIT_MOUNT": "transit"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := connection.LoadKEKConfig(func(k string) string { return tc.env[k] })
			if err != nil {
				t.Fatal(err)
			}
			kek, err := connection.NewKEK(cfg)
			if tc.ok != (err == nil) {
				t.Fatalf("NewKEK err = %v, want ok=%v", err, tc.ok)
			}
			if err != nil && (!errors.Is(err, connection.ErrKEKConfig) || kek != nil) {
				t.Fatalf("refusal is not ErrKEKConfig with no KEK: %v", err)
			}
		})
	}
	// Direct construction is refused the same way.
	if _, err := connection.NewLocalKEK(testKEKKey, ""); !errors.Is(err, connection.ErrKEKConfig) {
		t.Fatalf("NewLocalKEK with ENV unset: %v", err)
	}
}

// fakeTransit is a Vault transit engine stand-in: encrypt/decrypt with a
// reversible tag, plus a switch to fail.
type fakeTransit struct {
	calls atomic.Int32
	fail  atomic.Bool
}

func (f *fakeTransit) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.calls.Add(1)
	if r.Header.Get("X-Vault-Token") != "fake-vault-token" || f.fail.Load() {
		http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
		return
	}
	var body map[string]string
	_ = json.NewDecoder(r.Body).Decode(&body)
	switch r.URL.Path {
	case "/v1/transit/encrypt/pa-connections":
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"ciphertext": "vault:v1:" + body["plaintext"]}})
	case "/v1/transit/decrypt/pa-connections":
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"plaintext": strings.TrimPrefix(body["ciphertext"], "vault:v1:")}})
	default:
		http.NotFound(w, r)
	}
}

// TestKEK_TransitRoundTrip checks the transit KEK against a fake Vault: a
// wrap/unwrap round trip, and an unwrap failure is ErrUnreadable.
func TestKEK_TransitRoundTrip(t *testing.T) {
	ft := &fakeTransit{}
	srv := httptest.NewTLSServer(ft)
	t.Cleanup(srv.Close)
	kek, err := connection.NewTransitKEK(connection.TransitConfig{
		Address: srv.URL, Mount: "transit", KeyName: "pa-connections",
		Token:      func(context.Context) (string, error) { return "fake-vault-token", nil },
		HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if kek.ID() != "transit:transit/pa-connections" {
		t.Fatalf("id %q", kek.ID())
	}
	ctx := context.Background()
	dek := bytes.Repeat([]byte{7}, 32)
	wrapped, err := kek.Wrap(ctx, dek)
	if err != nil {
		t.Fatal(err)
	}
	got, err := kek.Unwrap(ctx, wrapped)
	if err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("round trip: %v", err)
	}
	ft.fail.Store(true)
	if _, err := kek.Unwrap(ctx, wrapped); !errors.Is(err, connection.ErrUnreadable) {
		t.Fatalf("unwrap on a Vault error: %v, want ErrUnreadable", err)
	}
}
