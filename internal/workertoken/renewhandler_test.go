package workertoken

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/auth/localjwt"
)

// mintFor signs a token directly, so tests can construct credentials the mint
// endpoint would never produce (wrong audience, stale origin, write scopes)
// and assert the renew handler rejects them.
func mintFor(t *testing.T, c localjwt.Claims, ttl time.Duration) string {
	t.Helper()
	iss, err := localjwt.NewIssuer([]byte(testWorkerHMACSecret), testWorkerIssuerURL)
	if err != nil {
		t.Fatalf("new issuer: %v", err)
	}
	tok, err := iss.Mint(c, ttl)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	return tok
}

func workerClaims() localjwt.Claims {
	return localjwt.Claims{
		Subject:          "tg:924671154",
		TelegramID:       924671154,
		Scopes:           []string{"telegram:dialogs:read", "telegram:messages:read"},
		Audience:         []string{workerAudience},
		OriginalIssuedAt: time.Now().Unix(),
	}
}

// renewRequest builds a request carrying tok as the bearer. The identity in
// context deliberately has NO admin:users scope: renewal must work without it,
// which is the whole point of the endpoint.
func renewRequest(tok, body string) *http.Request {
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(http.MethodPost, "/api/mcp/worker-token/renew", http.NoBody)
	} else {
		req = httptest.NewRequest(http.MethodPost, "/api/mcp/worker-token/renew", bytes.NewBufferString(body))
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	return req.WithContext(auth.With(req.Context(), &auth.Identity{
		UserID: 7, TelegramID: 924671154, Scopes: []string{"telegram:dialogs:read"},
	}))
}

func renewHandler() http.HandlerFunc {
	return NewRenewHandler([]byte(testWorkerHMACSecret), testWorkerIssuerURL, "")
}

func doRenew(t *testing.T, tok, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	renewHandler()(rec, renewRequest(tok, body))
	return rec
}

// R1: the happy path — a worker token is exchanged for a fresh one carrying
// the identical identity and scopes, without the caller holding admin:users.
func TestRenew_HappyPathPreservesIdentityAndScopes(t *testing.T) {
	tok := mintFor(t, workerClaims(), time.Hour)
	rec := doRenew(t, tok, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	var resp workerTokenResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.WorkerToken == tok {
		t.Fatal("renewed token is byte-identical to the presented one")
	}
	claims, err := localjwt.Verify(resp.WorkerToken, []byte(testWorkerHMACSecret), testWorkerIssuerURL)
	if err != nil {
		t.Fatalf("renewed token does not verify: %v", err)
	}
	if claims.TelegramID != 924671154 || claims.Subject != "tg:924671154" {
		t.Fatalf("identity changed: sub=%q tg_id=%d", claims.Subject, claims.TelegramID)
	}
	if strings.Join(claims.Scopes, ",") != "telegram:dialogs:read,telegram:messages:read" {
		t.Fatalf("scopes changed: %v", claims.Scopes)
	}
	if !hasAudience(claims.Audience, workerAudience) {
		t.Fatalf("renewed token lost the worker audience, so it could not be renewed again: %v", claims.Audience)
	}
	// A renewed token must be usable for at least most of the default TTL,
	// otherwise renewal has not actually bought any time.
	if got := time.Until(time.Unix(claims.ExpiresAt, 0)); got < defaultWorkerTokenTTL-time.Minute {
		t.Fatalf("renewed TTL = %v, want ~%v", got, defaultWorkerTokenTTL)
	}
}

// bridgeClaims is workerClaims's local-bridge counterpart: aud=["mcp-worker-bridge"]
// carrying the full send/pin-capable scope set.
func bridgeClaims() localjwt.Claims {
	return localjwt.Claims{
		Subject:          "tg:924671154",
		TelegramID:       924671154,
		Scopes:           []string{"telegram:messages:send", "telegram:messages:pin"},
		Audience:         []string{workerBridgeAudience},
		OriginalIssuedAt: time.Now().Unix(),
	}
}

// TestRenew_LocalBridgeTokenRenewsWithSendScope: a token minted with
// aud=["mcp-worker-bridge"] and send/pin scopes renews successfully and the
// renewed token preserves those scopes — this is the test that would fail
// against the pre-fix code (the old defense-in-depth check would reject it).
func TestRenew_LocalBridgeTokenRenewsWithSendScope(t *testing.T) {
	tok := mintFor(t, bridgeClaims(), time.Hour)
	rec := doRenew(t, tok, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	var resp workerTokenResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	claims, err := localjwt.Verify(resp.WorkerToken, []byte(testWorkerHMACSecret), testWorkerIssuerURL)
	if err != nil {
		t.Fatalf("renewed token does not verify: %v", err)
	}
	if strings.Join(claims.Scopes, ",") != "telegram:messages:send,telegram:messages:pin" {
		t.Fatalf("scopes changed: %v", claims.Scopes)
	}
	if !hasAudience(claims.Audience, workerBridgeAudience) {
		t.Fatalf("renewed token lost the bridge audience, so it could not be renewed again: %v", claims.Audience)
	}
}

// TestRenew_LocalBridgeTokenRejectsScopeOutsideBridgeAllowlist: a token
// carrying aud=["mcp-worker-bridge"] plus a scope outside
// allowedLocalBridgeScopes is refused renewal, mirroring
// TestRenew_RejectsScopeOutsideAllowlist for the new allowlist.
func TestRenew_LocalBridgeTokenRejectsScopeOutsideBridgeAllowlist(t *testing.T) {
	c := bridgeClaims()
	c.Scopes = []string{"telegram:messages:send", "admin:users"}
	rec := doRenew(t, mintFor(t, c, time.Hour), "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403, body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "local-bridge allowlist") {
		t.Fatalf("unhelpful error body: %s", rec.Body.String())
	}
}

// TestRenew_ReadOnlyTokenStillRejectsSendScope: regression — a token with
// aud=["mcp-worker-ro"] carrying "telegram:messages:send" is still refused
// renewal, proving the audience-to-allowlist mapping did not cross-wire.
func TestRenew_ReadOnlyTokenStillRejectsSendScope(t *testing.T) {
	c := workerClaims()
	c.Scopes = []string{"telegram:dialogs:read", "telegram:messages:send"}
	rec := doRenew(t, mintFor(t, c, time.Hour), "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403, body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "read-only allowlist") {
		t.Fatalf("unhelpful error body: %s", rec.Body.String())
	}
}

// R2: the endpoint must refuse any token that is not a worker token. Without
// this an ordinary interactive session could be traded for a headless
// credential, since the generic audience policy is disabled by default.
func TestRenew_RejectsNonWorkerAudience(t *testing.T) {
	for _, tc := range []struct {
		name string
		aud  []string
	}{
		{"no audience", nil},
		{"agent audience", []string{"agent"}},
		{"bridge audience", []string{"bridge"}},
		{"local-bridge-shaped but wrong string", []string{"mcp-worker-bridge-typo"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := workerClaims()
			c.Audience = tc.aud
			rec := doRenew(t, mintFor(t, c, time.Hour), "")
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403, body=%s", rec.Code, rec.Body.String())
			}
		})
	}
}

// R3: renewal must not perpetuate a scope outside the read-only allowlist,
// even though the mint path cannot currently produce one.
func TestRenew_RejectsScopeOutsideAllowlist(t *testing.T) {
	c := workerClaims()
	c.Scopes = []string{"telegram:dialogs:read", "telegram:messages:send"}
	rec := doRenew(t, mintFor(t, c, time.Hour), "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403, body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "read-only allowlist") {
		t.Fatalf("unhelpful error body: %s", rec.Body.String())
	}
}

// R4: the caller cannot smuggle in a different identity or wider scopes. The
// request struct has no such fields and decodeStrict rejects unknown ones, so
// an attempt must fail loudly rather than be silently dropped.
func TestRenew_RejectsIdentityOrScopeInBody(t *testing.T) {
	tok := mintFor(t, workerClaims(), time.Hour)
	for _, body := range []string{
		`{"telegram_id":210408407}`,
		`{"scopes":["telegram:messages:send"]}`,
	} {
		rec := doRenew(t, tok, body)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("body %s: status = %d, want 400 (field must not be silently ignored), body=%s",
				body, rec.Code, rec.Body.String())
		}
	}
}

// R5: the absolute ceiling. Renewal extends a credential; it must not extend
// it forever, or the bound #412 introduced would be defeated by this endpoint.
func TestRenew_RefusesOnceChainExhausted(t *testing.T) {
	c := workerClaims()
	c.OriginalIssuedAt = time.Now().Add(-maxRenewalChain - time.Hour).Unix()
	rec := doRenew(t, mintFor(t, c, time.Hour), "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403, body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "renewal window exhausted") {
		t.Fatalf("error body should explain that an admin must re-mint: %s", rec.Body.String())
	}
}

// R6: near the ceiling the TTL is clamped, not refused — the last renewal
// before the deadline must still return a usable token so the worker keeps
// running right up to the cutoff.
func TestRenew_ClampsTTLToRemainingChain(t *testing.T) {
	c := workerClaims()
	remaining := 36 * time.Hour
	c.OriginalIssuedAt = time.Now().Add(-maxRenewalChain + remaining).Unix()
	rec := doRenew(t, mintFor(t, c, time.Hour), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	var resp workerTokenResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	claims, err := localjwt.Verify(resp.WorkerToken, []byte(testWorkerHMACSecret), testWorkerIssuerURL)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	got := time.Until(time.Unix(claims.ExpiresAt, 0))
	if got > remaining+time.Minute {
		t.Fatalf("TTL %v exceeds the remaining chain %v — the ceiling is not enforced", got, remaining)
	}
	if got < remaining-time.Minute {
		t.Fatalf("TTL %v is well under the remaining chain %v — the last renewal was cut short", got, remaining)
	}
}

// R7: the origin anchor must survive renewal. If each renewal reset it, the
// ceiling in R5 would never be reached and the chain would be unbounded.
func TestRenew_PreservesOriginAnchorAcrossRenewals(t *testing.T) {
	c := workerClaims()
	origin := time.Now().Add(-200 * 24 * time.Hour).Unix()
	c.OriginalIssuedAt = origin
	rec := doRenew(t, mintFor(t, c, time.Hour), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	var resp workerTokenResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	claims, err := localjwt.Verify(resp.WorkerToken, []byte(testWorkerHMACSecret), testWorkerIssuerURL)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.OriginalIssuedAt != origin {
		t.Fatalf("orig_iat = %d, want %d (anchor reset would make the chain endless)", claims.OriginalIssuedAt, origin)
	}
}

// R8: a token minted before orig_iat existed — such as the one the production
// canary runs on today — must still be renewable, anchoring to its own iat.
func TestRenew_LegacyTokenAnchorsToIssuedAt(t *testing.T) {
	c := workerClaims()
	c.OriginalIssuedAt = 0
	iat := time.Now().Add(-30 * 24 * time.Hour).Unix()
	c.IssuedAt = iat
	rec := doRenew(t, mintFor(t, c, time.Hour), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("legacy token must renew, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp workerTokenResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	claims, err := localjwt.Verify(resp.WorkerToken, []byte(testWorkerHMACSecret), testWorkerIssuerURL)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.OriginalIssuedAt != iat {
		t.Fatalf("orig_iat = %d, want the legacy token's iat %d", claims.OriginalIssuedAt, iat)
	}
}

// R9: a legacy token whose own iat is already older than the ceiling must be
// refused rather than silently granted a fresh window.
func TestRenew_LegacyTokenPastCeilingIsRefused(t *testing.T) {
	c := workerClaims()
	c.OriginalIssuedAt = 0
	c.IssuedAt = time.Now().Add(-maxRenewalChain - 24*time.Hour).Unix()
	rec := doRenew(t, mintFor(t, c, time.Hour), "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403, body=%s", rec.Code, rec.Body.String())
	}
}

// R10: no bearer header, or a bearer that does not verify, is unauthorized.
func TestRenew_RejectsMissingOrBadBearer(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/mcp/worker-token/renew", http.NoBody)
		req = req.WithContext(auth.With(req.Context(), &auth.Identity{UserID: 7}))
		rec := httptest.NewRecorder()
		renewHandler()(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	})
	t.Run("wrong signing key", func(t *testing.T) {
		other, _ := localjwt.NewIssuer([]byte("another-hmac-secret-32-bytes!!!!"), testWorkerIssuerURL)
		tok, _ := other.Mint(workerClaims(), time.Hour)
		rec := doRenew(t, tok, "")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401, body=%s", rec.Code, rec.Body.String())
		}
	})
	t.Run("unauthenticated context", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/mcp/worker-token/renew", http.NoBody)
		req.Header.Set("Authorization", "Bearer "+mintFor(t, workerClaims(), time.Hour))
		rec := httptest.NewRecorder()
		renewHandler()(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	})
}

// R11: a caller-supplied ttl_hours may shorten the token but never lift it
// above the mint path's own ceiling.
func TestRenew_TTLHoursCappedAtMax(t *testing.T) {
	tok := mintFor(t, workerClaims(), time.Hour)
	rec := doRenew(t, tok, `{"ttl_hours":100000}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	var resp workerTokenResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	claims, err := localjwt.Verify(resp.WorkerToken, []byte(testWorkerHMACSecret), testWorkerIssuerURL)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got := time.Until(time.Unix(claims.ExpiresAt, 0)); got > maxWorkerTokenTTL+time.Minute {
		t.Fatalf("TTL = %v exceeds ceiling %v", got, maxWorkerTokenTTL)
	}
}

// R12: when the deployment configures an MCP audience, the renewed token must
// carry it alongside the worker marker — otherwise tightening
// OAUTH_JWT_AUDIENCE would lock out the very worker that keeps renewing.
func TestRenew_CarriesConfiguredMCPAudience(t *testing.T) {
	h := NewRenewHandler([]byte(testWorkerHMACSecret), testWorkerIssuerURL, "https://tg.test/mcp")
	rec := httptest.NewRecorder()
	h(rec, renewRequest(mintFor(t, workerClaims(), time.Hour), ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	var resp workerTokenResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	claims, err := localjwt.Verify(resp.WorkerToken, []byte(testWorkerHMACSecret), testWorkerIssuerURL)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !hasAudience(claims.Audience, workerAudience) || !hasAudience(claims.Audience, "https://tg.test/mcp") {
		t.Fatalf("audience = %v, want both the worker marker and the configured MCP audience", claims.Audience)
	}
}

// TestRenew_LogsPurposeAndExpiry is the renewal counterpart of
// TestNewHandler_LogsPurposeAndExpiry: a renewed credential must be as
// greppable as a freshly minted one, otherwise the audit trail goes blind
// after the first renewal.
func TestRenew_LogsPurposeAndExpiry(t *testing.T) {
	buf := captureLogs(t)
	tok := mintFor(t, bridgeClaims(), time.Hour)
	rec := doRenew(t, tok, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	logged := buf.String()
	if !strings.Contains(logged, `"purpose":"local-bridge"`) {
		t.Errorf("renew log missing purpose=local-bridge: %s", logged)
	}
	if !strings.Contains(logged, `"audience_marker":"`+workerBridgeAudience+`"`) {
		t.Errorf("renew log missing audience_marker: %s", logged)
	}
	if !strings.Contains(logged, `"expires_at":`) {
		t.Errorf("renew log missing expires_at: %s", logged)
	}
}
