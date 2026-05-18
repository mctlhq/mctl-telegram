package oauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

// chiAdapter satisfies the local Router interface using a real chi.Mux. This
// is the production wiring path used by cmd/server/main.go via Server.Register.
// We keep the adapter inside the test file because the package's own Router
// interface deliberately avoids importing chi.
type chiAdapter struct{ mux *chi.Mux }

func (a *chiAdapter) Get(p string, h http.HandlerFunc)  { a.mux.Get(p, h) }
func (a *chiAdapter) Post(p string, h http.HandlerFunc) { a.mux.Post(p, h) }

// TestServer_RegistersOnChi confirms that mounting the OAuth handlers on a
// real chi.Mux does not panic and that each declared route actually serves.
// Without this test, a typo in a Register pattern would only fail in
// production (the mockRouter accepts anything).
func TestServer_RegistersOnChi(t *testing.T) {
	srv := newTestServer(t)
	mux := chi.NewRouter()
	srv.Register(&chiAdapter{mux: mux})

	// /.well-known/oauth-authorization-server: 200 JSON.
	req := httptest.NewRequest("GET", "/.well-known/oauth-authorization-server", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("metadata status = %d", rec.Code)
	}
	var body map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["issuer"] != testIssuer {
		t.Errorf("issuer = %v", body["issuer"])
	}

	// /oauth/authorize: 400 without PKCE params (smoke).
	req = httptest.NewRequest("GET", "/oauth/authorize", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("authorize without params = %d", rec.Code)
	}

	// /oauth/register: 400 on bad body (smoke).
	req = httptest.NewRequest("POST", "/oauth/register", http.NoBody)
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("register without body = %d", rec.Code)
	}

	// /oauth/token: 400 on bad grant_type (smoke).
	req = httptest.NewRequest("POST", "/oauth/token", http.NoBody)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("token without body = %d", rec.Code)
	}

	// /oauth/telegram/callback: registered as GET (Telegram's OIDC redirect is
	// a GET); 400 without a state param. A 405 here would mean the route was
	// mistakenly mounted as POST.
	req = httptest.NewRequest("GET", "/oauth/telegram/callback", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("callback without state = %d (want 400)", rec.Code)
	}
}
