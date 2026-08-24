package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// doRevokeRequest posts form values to /oauth/revoke and returns the recorder.
func doRevokeRequest(t *testing.T, mux *mockRouter, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", "/oauth/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	mux.serve("POST", "/oauth/revoke", rec, req)
	return rec
}

// TestRevoke_LiveToken confirms revoking a live refresh token returns 200
// with an empty body and makes the token unusable at /oauth/token
// afterwards (RFC 7009 SS2.2).
func TestRevoke_LiveToken(t *testing.T) {
	srv := newTestServer(t)
	mux := newMockRouter()
	srv.Register(mux)
	resp := authCodeTokens(t, srv, mux)
	refreshTok, _ := resp["refresh_token"].(string)

	revokeForm := url.Values{}
	revokeForm.Set("token", refreshTok)
	revokeForm.Set("client_id", "claude.ai")
	rec := doRevokeRequest(t, mux, revokeForm)
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if rec.Body.Len() != 0 {
		t.Errorf("revoke success body = %q, want empty", rec.Body.String())
	}

	refreshForm := url.Values{}
	refreshForm.Set("grant_type", "refresh_token")
	refreshForm.Set("refresh_token", refreshTok)
	refreshForm.Set("client_id", "claude.ai")
	if rec := doTokenRequest(t, mux, refreshForm); rec.Code == http.StatusOK {
		t.Fatal("revoked refresh token was still accepted at /oauth/token")
	}
}

// TestRevoke_KillsFamilySiblings confirms revoking one token in a rotation
// lineage revokes every other still-active token sharing the same
// FamilyID, not just the presented token.
func TestRevoke_KillsFamilySiblings(t *testing.T) {
	srv := newTestServer(t)
	mux := newMockRouter()
	srv.Register(mux)
	resp := authCodeTokens(t, srv, mux)
	original, _ := resp["refresh_token"].(string)

	refreshForm := url.Values{}
	refreshForm.Set("grant_type", "refresh_token")
	refreshForm.Set("refresh_token", original)
	refreshForm.Set("client_id", "claude.ai")
	rec := doTokenRequest(t, mux, refreshForm)
	if rec.Code != http.StatusOK {
		t.Fatalf("rotation failed: %d %s", rec.Code, rec.Body.String())
	}
	var rotated map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&rotated); err != nil {
		t.Fatalf("decode rotated resp: %v", err)
	}
	rotatedTok, _ := rotated["refresh_token"].(string)

	// original is now revoked (rotated); revoke it anyway — the family
	// revoke must reach the live sibling (rotatedTok) too.
	revokeForm := url.Values{}
	revokeForm.Set("token", original)
	revokeForm.Set("client_id", "claude.ai")
	if rec := doRevokeRequest(t, mux, revokeForm); rec.Code != http.StatusOK {
		t.Fatalf("revoke status = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	rt, err := srv.store.LookupRefreshToken(context.Background(), rotatedTok)
	if err != nil {
		t.Fatalf("lookup rotated token: %v", err)
	}
	if !rt.Revoked() {
		t.Error("sibling token in the same family was not revoked")
	}
	if rt.RevokedReason != "explicit_revoke" {
		t.Errorf("sibling revoked_reason = %q, want \"explicit_revoke\"", rt.RevokedReason)
	}
}

// TestRevoke_Idempotent confirms revoking the same token twice returns 200
// both times (RFC 7009 does not distinguish "already revoked" from "never
// existed").
func TestRevoke_Idempotent(t *testing.T) {
	srv := newTestServer(t)
	mux := newMockRouter()
	srv.Register(mux)
	resp := authCodeTokens(t, srv, mux)
	refreshTok, _ := resp["refresh_token"].(string)

	revokeForm := url.Values{}
	revokeForm.Set("token", refreshTok)
	revokeForm.Set("client_id", "claude.ai")
	if rec := doRevokeRequest(t, mux, revokeForm); rec.Code != http.StatusOK {
		t.Fatalf("first revoke status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if rec := doRevokeRequest(t, mux, revokeForm); rec.Code != http.StatusOK {
		t.Fatalf("second revoke status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
}

// TestRevoke_UnknownToken confirms a token value that matches nothing
// returns 200 with an empty body, not 400 or 404 (RFC 7009 SS2.2).
func TestRevoke_UnknownToken(t *testing.T) {
	srv := newTestServer(t)
	mux := newMockRouter()
	srv.Register(mux)

	form := url.Values{}
	form.Set("token", "totally-bogus-token")
	form.Set("client_id", "claude.ai")
	rec := doRevokeRequest(t, mux, form)
	if rec.Code != http.StatusOK {
		t.Fatalf("unknown token revoke status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if rec.Body.Len() != 0 {
		t.Errorf("unknown token revoke body = %q, want empty", rec.Body.String())
	}
}

// TestRevoke_WrongClientDoesNotRevoke is the chief security property: a
// caller presenting another client's token must get the same 200 response
// as an unknown token, and the token must remain live afterward. This is
// what stops /oauth/revoke being usable to probe or kill another client's
// tokens.
func TestRevoke_WrongClientDoesNotRevoke(t *testing.T) {
	srv := newTestServer(t)
	mux := newMockRouter()
	srv.Register(mux)
	resp := authCodeTokens(t, srv, mux)
	refreshTok, _ := resp["refresh_token"].(string)

	form := url.Values{}
	form.Set("token", refreshTok)
	form.Set("client_id", "someone-else")
	rec := doRevokeRequest(t, mux, form)
	if rec.Code != http.StatusOK {
		t.Fatalf("wrong-client revoke status = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	rt, err := srv.store.LookupRefreshToken(context.Background(), refreshTok)
	if err != nil {
		t.Fatalf("lookup token: %v", err)
	}
	if rt.Revoked() {
		t.Error("token was revoked despite a mismatched client_id")
	}
}

// TestRevoke_MalformedRequest confirms missing token, missing client_id,
// and an unparseable body all yield 400 invalid_request.
func TestRevoke_MalformedRequest(t *testing.T) {
	srv := newTestServer(t)
	mux := newMockRouter()
	srv.Register(mux)
	resp := authCodeTokens(t, srv, mux)
	refreshTok, _ := resp["refresh_token"].(string)

	t.Run("missing token", func(t *testing.T) {
		form := url.Values{}
		form.Set("client_id", "claude.ai")
		rec := doRevokeRequest(t, mux, form)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
		}
		assertInvalidRequest(t, rec)
	})

	t.Run("missing client_id", func(t *testing.T) {
		form := url.Values{}
		form.Set("token", refreshTok)
		rec := doRevokeRequest(t, mux, form)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
		}
		assertInvalidRequest(t, rec)
	})

	t.Run("unparseable body", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/oauth/revoke", strings.NewReader("token=%zz"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		mux.serve("POST", "/oauth/revoke", rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
		}
		assertInvalidRequest(t, rec)
	})
}

func assertInvalidRequest(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if body["error"] != "invalid_request" {
		t.Errorf("error = %q, want invalid_request", body["error"])
	}
}

// TestRevoke_TokenTypeHintIgnored confirms token_type_hint is accepted but
// does not change behavior: an access-token hint on a value that is not a
// known refresh token still falls into the "unknown token, 200 OK" branch.
func TestRevoke_TokenTypeHintIgnored(t *testing.T) {
	srv := newTestServer(t)
	mux := newMockRouter()
	srv.Register(mux)

	form := url.Values{}
	form.Set("token", "some-jwt-access-token")
	form.Set("client_id", "claude.ai")
	form.Set("token_type_hint", "access_token")
	rec := doRevokeRequest(t, mux, form)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
}

// TestRevoke_StoreErrorDoesNotReport200 confirms a genuine store failure
// during lookup is surfaced as 500 server_error rather than a false 200 —
// a false success here would let an operator believe a leaked token was
// cut off when the revoke actually failed.
func TestRevoke_StoreErrorDoesNotReport200(t *testing.T) {
	srv := newTestServer(t)
	mux := newMockRouter()
	srv.Register(mux)
	// Close the underlying DB to force a genuine (non-not-found) lookup
	// error on the next query.
	if err := srv.store.DB.Close(); err != nil {
		t.Fatalf("close db: %v", err)
	}

	form := url.Values{}
	form.Set("token", "irrelevant")
	form.Set("client_id", "claude.ai")
	rec := doRevokeRequest(t, mux, form)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", rec.Code, rec.Body.String())
	}
	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if body["error"] != "server_error" {
		t.Errorf("error = %q, want server_error", body["error"])
	}
}

// TestAuthorizationServerMetadata_AdvertisesRevocationEndpoint confirms the
// discovery document advertises the new /oauth/revoke endpoint so RFC
// 7009-aware clients can discover it.
func TestAuthorizationServerMetadata_AdvertisesRevocationEndpoint(t *testing.T) {
	srv := newTestServer(t)
	mux := newMockRouter()
	srv.Register(mux)
	req := httptest.NewRequest("GET", "/.well-known/oauth-authorization-server", nil)
	rec := httptest.NewRecorder()
	mux.serve("GET", "/.well-known/oauth-authorization-server", rec, req)
	var body map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode metadata: %v", err)
	}
	want := testIssuer + "/oauth/revoke"
	if body["revocation_endpoint"] != want {
		t.Errorf("revocation_endpoint = %v, want %v", body["revocation_endpoint"], want)
	}
}
