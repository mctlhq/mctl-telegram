package oauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/auth/localjwt"
)

// doTokenRequest posts form values to /oauth/token and returns the recorder.
func doTokenRequest(t *testing.T, mux *mockRouter, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	mux.serve("POST", "/oauth/token", rec, req)
	return rec
}

// authCodeTokens drives authorize + widget callback + token and returns the
// decoded response from a successful authorization_code exchange.
func authCodeTokens(t *testing.T, srv *Server, mux *mockRouter) map[string]any {
	t.Helper()
	verifier, challenge := pkceVerifierAndChallenge()
	cs := obtainAuthorizationCode(t, srv, mux, challenge)
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", cs.code)
	form.Set("client_id", "claude.ai")
	form.Set("redirect_uri", "https://claude.ai/cb")
	form.Set("code_verifier", verifier)
	rec := doTokenRequest(t, mux, form)
	if rec.Code != http.StatusOK {
		t.Fatalf("auth_code token exchange failed: %d %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode token resp: %v", err)
	}
	return resp
}

// TestToken_AuthCodeIssuesRefreshToken confirms the authorization_code
// exchange now hands back a refresh_token alongside the access token.
func TestToken_AuthCodeIssuesRefreshToken(t *testing.T) {
	srv := newTestServer(t)
	mux := newMockRouter()
	srv.Register(mux)
	resp := authCodeTokens(t, srv, mux)
	if rt, _ := resp["refresh_token"].(string); rt == "" {
		t.Fatal("authorization_code response missing refresh_token")
	}
}

// TestToken_RefreshGrantRenewsAccessToken is the core fix: an MCP client whose
// access token has expired exchanges its refresh token for a new access token
// without re-running the Telegram widget flow.
func TestToken_RefreshGrantRenewsAccessToken(t *testing.T) {
	srv := newTestServer(t)
	mux := newMockRouter()
	srv.Register(mux)
	resp := authCodeTokens(t, srv, mux)
	refreshTok, _ := resp["refresh_token"].(string)

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshTok)
	form.Set("client_id", "claude.ai")
	rec := doTokenRequest(t, mux, form)
	if rec.Code != http.StatusOK {
		t.Fatalf("refresh grant failed: %d %s", rec.Code, rec.Body.String())
	}
	var refreshed map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&refreshed); err != nil {
		t.Fatalf("decode refresh resp: %v", err)
	}
	access, _ := refreshed["access_token"].(string)
	if access == "" {
		t.Fatal("refresh response missing access_token")
	}
	newRefresh, _ := refreshed["refresh_token"].(string)
	if newRefresh == "" {
		t.Fatal("refresh response missing rotated refresh_token")
	}
	if newRefresh == refreshTok {
		t.Fatal("refresh_token was not rotated")
	}
	if _, err := localjwt.Verify(access, testJWTSecret, testIssuer); err != nil {
		t.Fatalf("refreshed access_token failed verification: %v", err)
	}
}

// TestToken_RefreshGraceWindowReplay_Succeeds covers the actual production
// bug fix: a deterministic-derivation caller that retries a refresh with the
// same predecessor within the grace window (e.g. after a dropped response)
// must recover the already-committed successor and succeed, not fail with
// invalid_grant.
func TestToken_RefreshGraceWindowReplay_Succeeds(t *testing.T) {
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
		t.Fatalf("first refresh failed: %d %s", rec.Code, rec.Body.String())
	}
	var rotated map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&rotated); err != nil {
		t.Fatalf("decode rotated resp: %v", err)
	}
	rotatedTok, _ := rotated["refresh_token"].(string)

	// Immediate replay of the original token (well within the grace window,
	// no clock manipulation needed — real elapsed time here is
	// milliseconds) must succeed and hand back the SAME successor a
	// deterministic-derivation caller would have recomputed.
	rec2 := doTokenRequest(t, mux, refreshForm)
	if rec2.Code != http.StatusOK {
		t.Fatalf("grace-window replay was rejected: %d %s", rec2.Code, rec2.Body.String())
	}
	var replayed map[string]any
	if err := json.NewDecoder(rec2.Body).Decode(&replayed); err != nil {
		t.Fatalf("decode grace replay resp: %v", err)
	}
	if replayed["refresh_token"] != rotatedTok {
		t.Errorf("grace replay refresh_token = %v, want %v (the already-committed successor)",
			replayed["refresh_token"], rotatedTok)
	}

	// The recovered successor must still work for a further, genuine rotation.
	nextForm := url.Values{}
	nextForm.Set("grant_type", "refresh_token")
	nextForm.Set("refresh_token", rotatedTok)
	nextForm.Set("client_id", "claude.ai")
	if rec := doTokenRequest(t, mux, nextForm); rec.Code != http.StatusOK {
		t.Errorf("rotation on grace-replayed successor failed: %d %s", rec.Code, rec.Body.String())
	}
}

// TestToken_RefreshGraceWindow_WrongClientRejected ensures a grace-window
// replay presenting a different client_id than the original rotation is
// never trusted, and doesn't disturb the legitimate successor.
func TestToken_RefreshGraceWindow_WrongClientRejected(t *testing.T) {
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
		t.Fatalf("first refresh failed: %d %s", rec.Code, rec.Body.String())
	}
	var rotated map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&rotated); err != nil {
		t.Fatalf("decode rotated resp: %v", err)
	}
	rotatedTok, _ := rotated["refresh_token"].(string)

	wrongClientForm := url.Values{}
	wrongClientForm.Set("grant_type", "refresh_token")
	wrongClientForm.Set("refresh_token", original)
	wrongClientForm.Set("client_id", "someone-else")
	if rec := doTokenRequest(t, mux, wrongClientForm); rec.Code == http.StatusOK {
		t.Fatal("grace-window replay with mismatched client_id was accepted")
	}

	// The legitimate successor must remain usable after the rejected attempt.
	legitForm := url.Values{}
	legitForm.Set("grant_type", "refresh_token")
	legitForm.Set("refresh_token", rotatedTok)
	legitForm.Set("client_id", "claude.ai")
	if rec := doTokenRequest(t, mux, legitForm); rec.Code != http.StatusOK {
		t.Errorf("legitimate successor should still work after rejected cross-client replay: %d %s", rec.Code, rec.Body.String())
	}
}

// TestToken_RefreshReuseAfterGraceWindow_RevokesFamily confirms that once the
// grace window elapses, a replayed predecessor is treated as genuine reuse
// and the whole family dies — so even the freshly rotated token stops
// working.
func TestToken_RefreshReuseAfterGraceWindow_RevokesFamily(t *testing.T) {
	srv := newTestServer(t)
	mux := newMockRouter()
	srv.Register(mux)
	resp := authCodeTokens(t, srv, mux)
	original, _ := resp["refresh_token"].(string)

	refreshForm := url.Values{}
	refreshForm.Set("grant_type", "refresh_token")
	refreshForm.Set("refresh_token", original)
	refreshForm.Set("client_id", "claude.ai")

	// First refresh rotates the token.
	rec := doTokenRequest(t, mux, refreshForm)
	if rec.Code != http.StatusOK {
		t.Fatalf("first refresh failed: %d %s", rec.Code, rec.Body.String())
	}
	var rotated map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&rotated); err != nil {
		t.Fatalf("decode rotated resp: %v", err)
	}
	rotatedTok, _ := rotated["refresh_token"].(string)

	// Advance the server's clock past the grace window. RevokedAt is
	// stamped with real time.Now() in the store layer, independent of
	// srv.clock — pushing srv.clock into the future is what moves the
	// comparison past the window without a real sleep (same pattern as
	// TestToken_RefreshRejectsExpiredToken above).
	srv.clock = func() time.Time { return time.Now().Add(time.Hour) }

	// Reusing the original (now-rotated) token past the grace window must
	// be rejected.
	if rec := doTokenRequest(t, mux, refreshForm); rec.Code == http.StatusOK {
		t.Fatal("reusing a rotated refresh token past the grace window was accepted")
	}

	// Reuse detection must revoke the whole family, so the freshly rotated
	// token is dead too.
	reuseForm := url.Values{}
	reuseForm.Set("grant_type", "refresh_token")
	reuseForm.Set("refresh_token", rotatedTok)
	reuseForm.Set("client_id", "claude.ai")
	if rec := doTokenRequest(t, mux, reuseForm); rec.Code == http.StatusOK {
		t.Fatal("token family was not revoked after reuse detection")
	}
}

// TestToken_RefreshRotationRace_ConcurrentRecovery models the real race this
// fix targets: two requests racing to refresh the same predecessor token
// (e.g. two MCP sessions sharing credentials). Both must succeed with the
// identical rotated session instead of one winning and one hard-failing.
func TestToken_RefreshRotationRace_ConcurrentRecovery(t *testing.T) {
	srv := newTestServer(t)
	mux := newMockRouter()
	srv.Register(mux)
	resp := authCodeTokens(t, srv, mux)
	original, _ := resp["refresh_token"].(string)

	const n = 5
	var wg sync.WaitGroup
	codes := make([]int, n)
	refreshTokens := make([]string, n)
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			form := url.Values{}
			form.Set("grant_type", "refresh_token")
			form.Set("refresh_token", original)
			form.Set("client_id", "claude.ai")
			rec := doTokenRequest(t, mux, form)
			codes[i] = rec.Code
			if rec.Code == http.StatusOK {
				var body map[string]any
				if err := json.NewDecoder(rec.Body).Decode(&body); err == nil {
					refreshTokens[i], _ = body["refresh_token"].(string)
				}
			}
		}(i)
	}
	wg.Wait()

	successes := 0
	var successToken string
	for i, code := range codes {
		if code == http.StatusOK {
			successes++
			if successToken == "" {
				successToken = refreshTokens[i]
			} else if refreshTokens[i] != successToken {
				t.Errorf("racer %d got a different successor token than the others", i)
			}
		}
	}
	if successes != n {
		t.Errorf("expected all %d concurrent racers to recover the same successor, got %d successes (codes: %v)", n, successes, codes)
	}
}

// TestToken_RefreshRejectsUnknownToken confirms a bogus refresh token is
// rejected rather than treated as valid.
func TestToken_RefreshRejectsUnknownToken(t *testing.T) {
	srv := newTestServer(t)
	mux := newMockRouter()
	srv.Register(mux)
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", "totally-bogus-token")
	form.Set("client_id", "claude.ai")
	if rec := doTokenRequest(t, mux, form); rec.Code == http.StatusOK {
		t.Fatal("unknown refresh token was accepted")
	}
}

// TestToken_RefreshRejectsClientMismatch confirms a refresh token bound to one
// client cannot be redeemed by another.
func TestToken_RefreshRejectsClientMismatch(t *testing.T) {
	srv := newTestServer(t)
	mux := newMockRouter()
	srv.Register(mux)
	resp := authCodeTokens(t, srv, mux)
	refreshTok, _ := resp["refresh_token"].(string)

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshTok)
	form.Set("client_id", "someone-else")
	if rec := doTokenRequest(t, mux, form); rec.Code == http.StatusOK {
		t.Fatal("refresh token redeemed under a mismatched client_id")
	}
}

// TestToken_RefreshRejectsExpiredToken confirms the handler rejects a refresh
// token whose absolute expiry has elapsed.
func TestToken_RefreshRejectsExpiredToken(t *testing.T) {
	srv := newTestServer(t)
	mux := newMockRouter()
	srv.Register(mux)
	// Issue a refresh token under the real clock (default TTL 720h).
	resp := authCodeTokens(t, srv, mux)
	refreshTok, _ := resp["refresh_token"].(string)
	// Advance the server clock past the refresh-token TTL.
	srv.clock = func() time.Time { return time.Now().Add(721 * time.Hour) }
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshTok)
	form.Set("client_id", "claude.ai")
	if rec := doTokenRequest(t, mux, form); rec.Code == http.StatusOK {
		t.Fatal("expired refresh token was accepted")
	}
}

// TestToken_RefreshIsAbsoluteNotSliding confirms a rotated token carries the
// original expiry forward — refreshing does not extend the absolute lifetime.
func TestToken_RefreshIsAbsoluteNotSliding(t *testing.T) {
	srv := newTestServer(t)
	mux := newMockRouter()
	srv.Register(mux)
	resp := authCodeTokens(t, srv, mux)
	refreshTok, _ := resp["refresh_token"].(string)

	// Rotate once, still under the real clock.
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshTok)
	form.Set("client_id", "claude.ai")
	rec := doTokenRequest(t, mux, form)
	if rec.Code != http.StatusOK {
		t.Fatalf("rotation failed: %d %s", rec.Code, rec.Body.String())
	}
	var rotated map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&rotated); err != nil {
		t.Fatalf("decode: %v", err)
	}
	rotatedTok, _ := rotated["refresh_token"].(string)

	// Past the original TTL the rotated token must also be dead — rotation
	// did not reset the clock.
	srv.clock = func() time.Time { return time.Now().Add(721 * time.Hour) }
	form2 := url.Values{}
	form2.Set("grant_type", "refresh_token")
	form2.Set("refresh_token", rotatedTok)
	form2.Set("client_id", "claude.ai")
	if rec := doTokenRequest(t, mux, form2); rec.Code == http.StatusOK {
		t.Fatal("rotated token outlived the original absolute TTL — expiry is sliding")
	}
}

// TestAuthorizationServerMetadata_AdvertisesRefreshGrant confirms the
// discovery document tells clients the refresh_token grant is available.
func TestAuthorizationServerMetadata_AdvertisesRefreshGrant(t *testing.T) {
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
	grants, _ := body["grant_types_supported"].([]any)
	found := false
	for _, g := range grants {
		if g == "refresh_token" {
			found = true
		}
	}
	if !found {
		t.Errorf("grant_types_supported missing refresh_token: %v", grants)
	}
}
