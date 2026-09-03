package workertoken

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/auth/localjwt"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

// T3: mint -> renew carries the identical jti across both tokens, and the
// jti is non-empty (128-bit random, base64url).
func TestMintThenRenew_PreservesJti(t *testing.T) {
	h := NewHandler([]byte(testWorkerHMACSecret), testWorkerIssuerURL, "")
	rec := httptest.NewRecorder()
	h(rec, adminRequest(`{"telegram_id":924671154}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("mint status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	var minted workerTokenResponse
	if err := json.NewDecoder(rec.Body).Decode(&minted); err != nil {
		t.Fatalf("decode mint response: %v", err)
	}
	mintedClaims, err := localjwt.Verify(minted.WorkerToken, []byte(testWorkerHMACSecret), testWorkerIssuerURL)
	if err != nil {
		t.Fatalf("verify minted token: %v", err)
	}
	if mintedClaims.Jti == "" {
		t.Fatal("minted token carries no jti")
	}

	rrec := doRenew(t, minted.WorkerToken, "")
	if rrec.Code != http.StatusOK {
		t.Fatalf("renew status = %d, want 200, body=%s", rrec.Code, rrec.Body.String())
	}
	var renewed workerTokenResponse
	if err := json.NewDecoder(rrec.Body).Decode(&renewed); err != nil {
		t.Fatalf("decode renew response: %v", err)
	}
	renewedClaims, err := localjwt.Verify(renewed.WorkerToken, []byte(testWorkerHMACSecret), testWorkerIssuerURL)
	if err != nil {
		t.Fatalf("verify renewed token: %v", err)
	}
	if renewedClaims.Jti != mintedClaims.Jti {
		t.Fatalf("jti changed across renewal: minted=%q renewed=%q", mintedClaims.Jti, renewedClaims.Jti)
	}
}

// A token minted before Jti existed (claims.Jti == "") gains a fresh one at
// its first renewal, so it becomes denylist-eligible from then on.
func TestRenew_LegacyTokenWithoutJtiGetsOneMinted(t *testing.T) {
	c := workerClaims()
	c.Jti = ""
	tok := mintFor(t, c, time.Hour)
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
		t.Fatalf("verify: %v", err)
	}
	if claims.Jti == "" {
		t.Fatal("renewed token should have gained a fresh jti")
	}
}

// newRevocationTestStore opens and migrates an in-memory sqlite DB so the
// worker_token_revocations table (and everything else db.Migrate creates)
// exists.
func newRevocationTestStore(t *testing.T, name string) *db.Store {
	t.Helper()
	ctx := context.Background()
	conn, err := db.Open(ctx, "file:"+name+"?mode=memory&cache=shared", 0, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := db.Migrate(ctx, conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return &db.Store{DB: conn}
}

// T4: mint a worker token, revoke it by jti, then present it to
// /api/mcp/worker-token/renew through the ACTUAL auth middleware chain
// (auth.Middleware wrapping a localjwt.Provider wired with the revocation
// cache) — not just the renew handler's own logic — and assert 401. The
// renew handler itself never re-checks revocation; rejection has to come
// from the middleware in front of it, which is exactly what #472 requires
// ("a revoked token stays revoked across renewal").
func TestRenewThroughAuthMiddleware_RejectsRevokedToken(t *testing.T) {
	store := newRevocationTestStore(t, "workertoken_t4")
	ctx := context.Background()

	mintHandler := NewHandler([]byte(testWorkerHMACSecret), testWorkerIssuerURL, "")
	mrec := httptest.NewRecorder()
	mintHandler(mrec, adminRequest(`{"telegram_id":924671154}`))
	if mrec.Code != http.StatusOK {
		t.Fatalf("mint status = %d, want 200, body=%s", mrec.Code, mrec.Body.String())
	}
	var minted workerTokenResponse
	if err := json.NewDecoder(mrec.Body).Decode(&minted); err != nil {
		t.Fatalf("decode mint response: %v", err)
	}
	claims, err := localjwt.Verify(minted.WorkerToken, []byte(testWorkerHMACSecret), testWorkerIssuerURL)
	if err != nil {
		t.Fatalf("verify minted token: %v", err)
	}
	if claims.Jti == "" {
		t.Fatal("minted token carries no jti")
	}

	if err := store.RevokeWorkerToken(ctx, claims.Jti, claims.TelegramID, "leaked", 1); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	cache := localjwt.NewRevocationCache(store, time.Minute)
	provider, err := localjwt.NewProvider(store, localjwt.ProviderConfig{
		Secret:          []byte(testWorkerHMACSecret),
		ExpectedIssuer:  testWorkerIssuerURL,
		RevocationCache: cache,
	})
	if err != nil {
		t.Fatalf("new provider: %v", err)
	}

	renewHandler := NewRenewHandler([]byte(testWorkerHMACSecret), testWorkerIssuerURL, "")
	chain := auth.Middleware(provider, true, nil, auth.ResourceMetadata{})(renewHandler)

	req := httptest.NewRequest(http.MethodPost, "/api/mcp/worker-token/renew", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+minted.WorkerToken)
	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (revoked token must not renew), body=%s", rec.Code, rec.Body.String())
	}
}
