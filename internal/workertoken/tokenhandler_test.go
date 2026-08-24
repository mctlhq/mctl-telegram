package workertoken

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/auth"
)

const testWorkerHMACSecret = "test-hmac-secret-bytes-32!!!!!!!"
const testWorkerIssuerURL = "https://tg.test"

func adminRequest(body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/api/mcp/worker-token", bytes.NewBufferString(body))
	req = req.WithContext(auth.With(req.Context(), &auth.Identity{
		UserID: 1, TelegramID: 42, Scopes: []string{"admin:users"},
	}))
	return req
}

func decodeJWTPayload(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("malformed token: %q", token)
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	return string(payloadJSON)
}

// T1: default request (no scopes, no ttl_hours) mints a token with exactly
// allowedReadOnlyScopes and TTL defaultWorkerTokenTTL.
func TestNewHandler_DefaultScopesAndTTL(t *testing.T) {
	h := NewHandler([]byte(testWorkerHMACSecret), testWorkerIssuerURL, "")
	req := adminRequest(`{"telegram_id":924671154}`)
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	var resp workerTokenResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	payload := decodeJWTPayload(t, resp.WorkerToken)
	if !strings.Contains(payload, `"tg_id":924671154`) {
		t.Fatalf("payload missing target tg_id: %s", payload)
	}
	if !strings.Contains(payload, `"aud":"mcp-worker-ro"`) {
		t.Fatalf("payload missing aud=mcp-worker-ro: %s", payload)
	}
	if !strings.Contains(payload, `"telegram:dialogs:read"`) || !strings.Contains(payload, `"telegram:messages:read"`) {
		t.Fatalf("payload missing default read-only scopes: %s", payload)
	}
	if strings.Contains(payload, `"telegram:messages:send"`) {
		t.Fatalf("payload must not carry a write scope: %s", payload)
	}

	expiresAt, err := time.Parse(time.RFC3339, resp.ExpiresAt)
	if err != nil {
		t.Fatalf("parse expires_at: %v", err)
	}
	wantExpiry := time.Now().Add(defaultWorkerTokenTTL)
	if diff := wantExpiry.Sub(expiresAt); diff < -time.Minute || diff > time.Minute {
		t.Fatalf("expires_at %v not within a minute of expected default TTL expiry %v", expiresAt, wantExpiry)
	}
}

// T2: a request with a write scope or admin:users in scopes is rejected
// with 400 and produces no token.
func TestNewHandler_RejectsWriteScope(t *testing.T) {
	for _, scope := range []string{"telegram:messages:send", "telegram:messages:pin", "admin:users", "bogus:scope"} {
		t.Run(scope, func(t *testing.T) {
			h := NewHandler([]byte(testWorkerHMACSecret), testWorkerIssuerURL, "")
			req := adminRequest(`{"telegram_id":42,"scopes":["` + scope + `"]}`)
			rec := httptest.NewRecorder()
			h(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
			}
			var body map[string]string
			if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
				t.Fatalf("decode error body: %v", err)
			}
			if body["error"] == "" {
				t.Fatal("expected an error message and no minted token")
			}
		})
	}
}

// T3: non-admin authenticated identity gets 403; unauthenticated request
// gets 401.
func TestNewHandler_RejectsNonAdmin(t *testing.T) {
	h := NewHandler([]byte(testWorkerHMACSecret), testWorkerIssuerURL, "")
	req := httptest.NewRequest(http.MethodPost, "/api/mcp/worker-token", bytes.NewBufferString(`{"telegram_id":42}`))
	req = req.WithContext(auth.With(req.Context(), &auth.Identity{UserID: 1, TelegramID: 42}))
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403, body=%s", rec.Code, rec.Body.String())
	}
}

func TestNewHandler_RejectsAnonymous(t *testing.T) {
	h := NewHandler([]byte(testWorkerHMACSecret), testWorkerIssuerURL, "")
	req := httptest.NewRequest(http.MethodPost, "/api/mcp/worker-token", bytes.NewBufferString(`{"telegram_id":42}`))
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestNewHandler_RejectsMissingTelegramID(t *testing.T) {
	h := NewHandler([]byte(testWorkerHMACSecret), testWorkerIssuerURL, "")
	req := adminRequest(`{}`)
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// T4: ttl_hours above the ceiling is clamped to maxWorkerTokenTTL; ttl_hours
// within range is honored exactly.
func TestNewHandler_TTLClamp(t *testing.T) {
	h := NewHandler([]byte(testWorkerHMACSecret), testWorkerIssuerURL, "")
	req := adminRequest(`{"telegram_id":42,"ttl_hours":100000}`)
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	var resp workerTokenResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	expiresAt, err := time.Parse(time.RFC3339, resp.ExpiresAt)
	if err != nil {
		t.Fatalf("parse expires_at: %v", err)
	}
	wantExpiry := time.Now().Add(maxWorkerTokenTTL)
	if diff := wantExpiry.Sub(expiresAt); diff < -time.Minute || diff > time.Minute {
		t.Fatalf("ttl_hours=100000 expires_at %v not clamped to ceiling %v", expiresAt, wantExpiry)
	}
}

func TestNewHandler_TTLWithinRangeHonored(t *testing.T) {
	h := NewHandler([]byte(testWorkerHMACSecret), testWorkerIssuerURL, "")
	req := adminRequest(`{"telegram_id":42,"ttl_hours":48}`)
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	var resp workerTokenResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	expiresAt, err := time.Parse(time.RFC3339, resp.ExpiresAt)
	if err != nil {
		t.Fatalf("parse expires_at: %v", err)
	}
	wantExpiry := time.Now().Add(48 * time.Hour)
	if diff := wantExpiry.Sub(expiresAt); diff < -time.Minute || diff > time.Minute {
		t.Fatalf("ttl_hours=48 expires_at %v not honored, want ~%v", expiresAt, wantExpiry)
	}
}

// Explicit scopes within the allowlist (a strict subset) are honored as
// requested rather than silently expanded to the full default set.
func TestNewHandler_ExplicitSubsetScopeHonored(t *testing.T) {
	h := NewHandler([]byte(testWorkerHMACSecret), testWorkerIssuerURL, "")
	req := adminRequest(`{"telegram_id":42,"scopes":["telegram:dialogs:read"]}`)
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	var resp workerTokenResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	payload := decodeJWTPayload(t, resp.WorkerToken)
	if !strings.Contains(payload, `"telegram:dialogs:read"`) {
		t.Fatalf("payload missing requested scope: %s", payload)
	}
	if strings.Contains(payload, `"telegram:messages:read"`) {
		t.Fatalf("payload must not silently include the non-requested default scope: %s", payload)
	}
}

// T8: when the wiring passes a configured /mcp audience (OAUTH_JWT_AUDIENCE),
// the minted token's aud list carries it alongside "mcp-worker-ro" — otherwise
// localjwt.CheckAudience on the shared /mcp provider would reject every
// worker token the moment an operator sets that config.
func TestNewHandler_IncludesConfiguredMCPAudience(t *testing.T) {
	h := NewHandler([]byte(testWorkerHMACSecret), testWorkerIssuerURL, "https://mcp.example.com")
	req := adminRequest(`{"telegram_id":924671154}`)
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	var resp workerTokenResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	payload := decodeJWTPayload(t, resp.WorkerToken)
	if !strings.Contains(payload, `"mcp-worker-ro"`) || !strings.Contains(payload, `"https://mcp.example.com"`) {
		t.Fatalf("payload aud must carry both the marker and the configured audience: %s", payload)
	}
}

// T9: trailing data after a valid JSON body is rejected, matching
// decodeStrict's documented contract.
func TestNewHandler_RejectsTrailingBodyData(t *testing.T) {
	h := NewHandler([]byte(testWorkerHMACSecret), testWorkerIssuerURL, "")
	req := adminRequest(`{"telegram_id":924671154}{"telegram_id":1}`)
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for trailing body data, body=%s", rec.Code, rec.Body.String())
	}
}
