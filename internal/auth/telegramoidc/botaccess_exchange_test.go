package telegramoidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// fakeOP serves a minimal OpenID Provider whose /token response carries
// tokenExtra on top of access_token, token_type and a signed id_token.
func fakeOP(t *testing.T, tokenExtra map[string]any) (issuer string, nonce string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pubJSON, err := (&jose.JSONWebKey{Key: &priv.PublicKey, KeyID: "rsa-1", Algorithm: "RS256", Use: "sig"}).MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	const clientID = "8568443430"
	nonce = "test-nonce"
	var srv *httptest.Server
	var idToken string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": srv.URL, "authorization_endpoint": srv.URL + "/auth",
			"token_endpoint": srv.URL + "/token", "jwks_uri": srv.URL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[` + string(pubJSON) + `]}`))
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		body := map[string]any{"access_token": "x", "token_type": "Bearer", "id_token": idToken}
		for k, v := range tokenExtra {
			body[k] = v
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: priv, KeyID: "rsa-1"}},
		(&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	claims, _ := json.Marshal(map[string]any{
		"iss": srv.URL, "aud": clientID, "sub": "1234567890123456789", "id": "500100101",
		"nonce": nonce, "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
	})
	jws, err := signer.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	if idToken, err = jws.CompactSerialize(); err != nil {
		t.Fatal(err)
	}
	return srv.URL, nonce
}

func newBotAccessClient(t *testing.T, issuer string, requestBotAccess bool) *Client {
	t.Helper()
	c, err := New(context.Background(), Config{
		IssuerURL: issuer, ClientID: "8568443430", ClientSecret: "secret",
		RedirectURL: "https://tg.mctl.ai/oauth/telegram/callback", RequestBotAccess: requestBotAccess,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

// T1: the authorization URL carries telegram:bot_access only when requested.
func TestAuthCodeURL_BotAccessScope(t *testing.T) {
	issuer, _ := fakeOP(t, nil)
	for _, tc := range []struct {
		on   bool
		want string
	}{{true, "openid profile telegram:bot_access"}, {false, "openid profile"}} {
		raw := newBotAccessClient(t, issuer, tc.on).AuthCodeURL("st", "n", "ch")
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if got := u.Query().Get("scope"); got != tc.want {
			t.Errorf("RequestBotAccess=%v: scope = %q, want %q", tc.on, got, tc.want)
		}
	}
}

// T3: Exchange reports the grant signal from the token response scope only,
// and passes the raw scope through for logs.
func TestExchange_BotAccessSignal(t *testing.T) {
	for _, tc := range []struct {
		name      string
		extra     map[string]any
		requested bool
		want      BotAccess
		wantScope string
	}{
		{"granted", map[string]any{"scope": "openid profile telegram:bot_access"}, true, BotAccessGranted, "openid profile telegram:bot_access"},
		{"scope without bot access", map[string]any{"scope": "openid profile"}, true, BotAccessUnknown, "openid profile"},
		{"no scope field", nil, true, BotAccessUnknown, ""},
		{"not requested", map[string]any{"scope": "openid profile telegram:bot_access"}, false, BotAccessUnknown, "openid profile telegram:bot_access"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			issuer, nonce := fakeOP(t, tc.extra)
			id, err := newBotAccessClient(t, issuer, tc.requested).Exchange(context.Background(), "code", "verifier", nonce)
			if err != nil {
				t.Fatalf("Exchange: %v", err)
			}
			if id.BotAccess != tc.want {
				t.Errorf("BotAccess = %q, want %q", id.BotAccess, tc.want)
			}
			if id.ReportedScope != tc.wantScope {
				t.Errorf("ReportedScope = %q, want %q", id.ReportedScope, tc.wantScope)
			}
		})
	}
}
