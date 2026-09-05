package bridge

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/auth"
)

type failProvider struct {
	err error
}

func (p failProvider) Authenticate(_ *http.Request) (*auth.Identity, error) {
	return nil, p.err
}

func TestBridgeHandler_AuthFailureIsGeneric(t *testing.T) {
	hub := NewHub()
	internal := errors.New("token is malformed: unexpected signing method RS256")
	h := NewBridgeHandler(hub, failProvider{err: internal}, nil, context.Background())
	req := httptest.NewRequest(http.MethodGet, "/bridge", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "RS256") || strings.Contains(body, "malformed") || strings.Contains(body, internal.Error()) {
		t.Fatalf("401 body leaked verifier internals: %q", body)
	}
	if !strings.Contains(body, "invalid credentials") {
		t.Fatalf("401 body = %q, want generic invalid credentials", body)
	}
}
