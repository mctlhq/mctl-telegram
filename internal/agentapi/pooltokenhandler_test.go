package agentapi

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/auth/localjwt"
)

func mintPool(t *testing.T, id *auth.Identity, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", "/api/agent/pool-token", strings.NewReader(body))
	if id != nil {
		req = req.WithContext(auth.With(req.Context(), id))
	}
	rec := httptest.NewRecorder()
	NewPoolTokenHandler(poolTestSecret, poolTestIssuer)(rec, req)
	return rec
}

func TestPoolToken_Mint(t *testing.T) {
	admin := &auth.Identity{UserID: 1, Scopes: []string{"admin:users"}}
	if rec := mintPool(t, nil, `{"pool_name":"main"}`); rec.Code != http.StatusUnauthorized {
		t.Errorf("no identity: %d", rec.Code)
	}
	if rec := mintPool(t, &auth.Identity{UserID: 2}, `{"pool_name":"main"}`); rec.Code != http.StatusForbidden {
		t.Errorf("non-admin: %d", rec.Code)
	}
	for _, body := range []string{`{}`, `{"pool_name":"Bad_Name"}`, `{"pool_name":"main","extra":1}`, `{"pool_name":"-x"}`} {
		if rec := mintPool(t, admin, body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", body, rec.Code)
		}
	}

	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(prev)

	for body, wantTTL := range map[string]time.Duration{
		`{"pool_name":"main"}`:                        30 * 24 * time.Hour,
		`{"pool_name":"main","ttl_hours":24}`:         24 * time.Hour,
		`{"pool_name":"main","ttl_hours":999999}`:     90 * 24 * time.Hour,
		`{"pool_name":"main","ttl_hours":9223372036}`: 90 * 24 * time.Hour,
		`{"pool_name":"main","ttl_hours":-5}`:         30 * 24 * time.Hour,
	} {
		rec := mintPool(t, admin, body)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", body, rec.Code, rec.Body.String())
		}
		var resp poolTokenResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		c, err := localjwt.Verify(resp.PoolToken, poolTestSecret, poolTestIssuer)
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		if got := time.Duration(c.ExpiresAt-c.IssuedAt) * time.Second; got != wantTTL {
			t.Errorf("%s: ttl %v, want %v", body, got, wantTTL)
		}
		if c.Subject != "pool:main" || c.TelegramID != 0 || c.JobID != 0 || c.Jti == "" || c.Jti != resp.Jti ||
			c.OriginalIssuedAt != c.IssuedAt || len(c.Audience) != 1 || c.Audience[0] != "agent-pool" {
			t.Errorf("claims wrong: %+v", c)
		}
		if strings.Contains(logs.String(), resp.PoolToken) {
			t.Error("log line contains the token")
		}
	}
	if !strings.Contains(logs.String(), "pool token minted") {
		t.Error("missing log line")
	}
}
