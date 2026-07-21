package agentapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/auth"
)

const testAgentHMACSecret = "test-hmac-secret-bytes-32!!!!!!!"
const testAgentIssuerURL = "https://tg.test"

func TestNewAgentTokenHandler_RejectsNonAdmin(t *testing.T) {
	h := NewAgentTokenHandler([]byte(testAgentHMACSecret), testAgentIssuerURL, map[int64]bool{999: true})
	req := httptest.NewRequest(http.MethodPost, "/api/agent/token",
		bytes.NewBufferString(`{"telegram_id":42}`))
	req = req.WithContext(auth.With(req.Context(), &auth.Identity{UserID: 1, TelegramID: 42}))
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403, body=%s", rec.Code, rec.Body.String())
	}
}

func TestNewAgentTokenHandler_RejectsAnonymous(t *testing.T) {
	h := NewAgentTokenHandler([]byte(testAgentHMACSecret), testAgentIssuerURL, map[int64]bool{42: true})
	req := httptest.NewRequest(http.MethodPost, "/api/agent/token", bytes.NewBufferString(`{"telegram_id":42}`))
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestNewAgentTokenHandler_MintsForTargetUser(t *testing.T) {
	h := NewAgentTokenHandler([]byte(testAgentHMACSecret), testAgentIssuerURL, map[int64]bool{42: true})
	req := httptest.NewRequest(http.MethodPost, "/api/agent/token",
		bytes.NewBufferString(`{"telegram_id":777,"ttl_hours":48}`))
	// The MINTING admin (42) is not the same as the TARGET account (777) the
	// token authenticates as — this is the load-bearing behavior distinguishing
	// this endpoint from the bridge's self-mint pattern.
	req = req.WithContext(auth.With(req.Context(), &auth.Identity{UserID: 1, TelegramID: 42}))
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	var resp agentTokenResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	parts := strings.Split(resp.AgentToken, ".")
	if len(parts) != 3 {
		t.Fatalf("malformed token: %q", resp.AgentToken)
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	payload := string(payloadJSON)
	if !strings.Contains(payload, `"tg_id":777`) {
		t.Fatalf("payload missing target tg_id=777: %s", payload)
	}
	if !strings.Contains(payload, `"aud":"agent"`) {
		t.Fatalf("payload missing aud=agent: %s", payload)
	}
	if !strings.Contains(payload, `"iss":"`+testAgentIssuerURL+`"`) {
		t.Fatalf("payload missing expected issuer: %s", payload)
	}
}

func TestNewAgentTokenHandler_RejectsMissingTelegramID(t *testing.T) {
	h := NewAgentTokenHandler([]byte(testAgentHMACSecret), testAgentIssuerURL, map[int64]bool{42: true})
	req := httptest.NewRequest(http.MethodPost, "/api/agent/token", bytes.NewBufferString(`{}`))
	req = req.WithContext(auth.With(req.Context(), &auth.Identity{UserID: 1, TelegramID: 42}))
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}
