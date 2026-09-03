package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/auth/localjwt"
	"github.com/mctlhq/mctl-telegram/internal/workertoken"
)

const (
	mintTestSecret = "test-hmac-secret-bytes-32!!!!!!!"
	mintTestIssuer = "https://tg.test"
)

func newMintServer(t *testing.T) *Server {
	t.Helper()
	minter, err := workertoken.NewMinter([]byte(mintTestSecret), mintTestIssuer, "")
	if err != nil {
		t.Fatalf("new minter: %v", err)
	}
	return &Server{Store: newToolsTestStore(t), WorkerTokenMinter: minter}
}

func callMint(t *testing.T, srv *Server, scopes []string, args map[string]any) *mcplib.CallToolResult {
	t.Helper()
	ctx := auth.With(context.Background(), &auth.Identity{UserID: 1, Scopes: scopes})
	_, handler := srv.toolMintWorkerToken()
	result, err := handler(ctx, mcplib.CallToolRequest{Params: mcplib.CallToolParams{
		Name: "mint_worker_token", Arguments: args,
	}})
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	return result
}

func decodeMint(t *testing.T, result *mcplib.CallToolResult) mintWorkerTokenResult {
	t.Helper()
	if result.IsError {
		t.Fatalf("expected success, got error result: %+v", result.Content)
	}
	var out mintWorkerTokenResult
	b, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatalf("marshal structured content: %v", err)
	}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	return out
}

func TestToolMintWorkerToken_RequiresAdminScope(t *testing.T) {
	srv := newMintServer(t)
	result := callMint(t, srv, []string{"telegram:messages:send"}, map[string]any{"telegram_id": float64(42)})
	if !result.IsError {
		t.Fatal("expected scope rejection for identity without admin:users")
	}
}

// A deployment that cannot enforce revocation must not gain a mint path
// through MCP that its HTTP surface deliberately withholds. cmd/server wires
// the minter only inside the workerTokenMintable gate, so "no minter" is that
// gate, and the tool has to refuse rather than panic or silently succeed.
func TestToolMintWorkerToken_RefusesWithoutMinter(t *testing.T) {
	srv := &Server{Store: newToolsTestStore(t)}
	result := callMint(t, srv, []string{"admin:users"}, map[string]any{"telegram_id": float64(42)})
	if !result.IsError {
		t.Fatal("expected refusal when no minter is wired")
	}
	msg := ""
	for _, c := range result.Content {
		if tc, ok := c.(mcplib.TextContent); ok {
			msg += tc.Text
		}
	}
	if !strings.Contains(msg, "revocation") {
		t.Errorf("refusal should say why (revocation cannot be enforced), got: %s", msg)
	}
}

func TestToolMintWorkerToken_RejectsNonPositiveTelegramID(t *testing.T) {
	srv := newMintServer(t)
	for _, arg := range []map[string]any{{}, {"telegram_id": float64(0)}, {"telegram_id": float64(-1)}} {
		if result := callMint(t, srv, []string{"admin:users"}, arg); !result.IsError {
			t.Errorf("expected rejection for args %+v", arg)
		}
	}
}

// Write capability is never a default. An unqualified mint is read-only, and
// asking for send without naming the local-bridge purpose is refused rather
// than quietly downgraded or quietly granted.
func TestToolMintWorkerToken_SendRequiresExplicitPurpose(t *testing.T) {
	srv := newMintServer(t)

	def := decodeMint(t, callMint(t, srv, []string{"admin:users"}, map[string]any{"telegram_id": float64(42)}))
	if def.Purpose != "read-only" {
		t.Errorf("default purpose = %q, want read-only", def.Purpose)
	}
	for _, s := range def.Scopes {
		if strings.Contains(s, ":send") || strings.Contains(s, ":pin") {
			t.Errorf("an unqualified mint granted a write scope: %v", def.Scopes)
		}
	}

	refused := callMint(t, srv, []string{"admin:users"}, map[string]any{
		"telegram_id": float64(42), "scopes": "telegram:messages:send",
	})
	if !refused.IsError {
		t.Error("asking for send without purpose=local-bridge must be refused, not granted")
	}

	bridged := decodeMint(t, callMint(t, srv, []string{"admin:users"}, map[string]any{
		"telegram_id": float64(42), "purpose": "local-bridge",
	}))
	if !containsString(bridged.Scopes, "telegram:messages:send") {
		t.Errorf("local-bridge purpose should carry send, got %v", bridged.Scopes)
	}
}

func TestToolMintWorkerToken_RejectsUnknownPurpose(t *testing.T) {
	srv := newMintServer(t)
	result := callMint(t, srv, []string{"admin:users"}, map[string]any{
		"telegram_id": float64(42), "purpose": "nonsense",
	})
	if !result.IsError {
		t.Fatal("an unrecognised purpose must be rejected, never silently read-only")
	}
}

// expires_at and jti are the deliverable, not decoration: a worker token lives
// for months and warns nobody as it ends, and the jti is what revokes it
// later. Both must be present and usable, not merely non-empty.
func TestToolMintWorkerToken_ReturnsUsableExpiryAndJti(t *testing.T) {
	srv := newMintServer(t)
	got := decodeMint(t, callMint(t, srv, []string{"admin:users"}, map[string]any{
		"telegram_id": float64(42), "purpose": "local-bridge",
	}))
	exp, err := time.Parse(time.RFC3339, got.ExpiresAt)
	if err != nil {
		t.Fatalf("expires_at is not RFC3339: %q (%v)", got.ExpiresAt, err)
	}
	if d := time.Until(exp); d < 29*24*time.Hour || d > 31*24*time.Hour {
		t.Errorf("default TTL = %v, want ~30 days", d)
	}
	claims, err := localjwt.Verify(got.WorkerToken, []byte(mintTestSecret), mintTestIssuer)
	if err != nil {
		t.Fatalf("minted token does not verify: %v", err)
	}
	if claims.Jti == "" || claims.Jti != got.Jti {
		t.Errorf("result jti %q does not match the token's %q — an operator who records the result cannot revoke this credential", got.Jti, claims.Jti)
	}
}

// ttl_hours must reach the policy: honoured below the ceiling, clamped TO the
// ceiling above it. Asserting only "not more than 90 days" would pass on a
// tool that silently ignored ttl_hours altogether and always issued the
// 30-day default.
func TestToolMintWorkerToken_TTLIsHonouredThenClamped(t *testing.T) {
	srv := newMintServer(t)
	ttlOf := func(args map[string]any) time.Duration {
		t.Helper()
		got := decodeMint(t, callMint(t, srv, []string{"admin:users"}, args))
		exp, err := time.Parse(time.RFC3339, got.ExpiresAt)
		if err != nil {
			t.Fatalf("parse expires_at: %v", err)
		}
		return time.Until(exp)
	}

	// Below the ceiling: the requested value is used, not the default.
	if d := ttlOf(map[string]any{"telegram_id": float64(42), "ttl_hours": float64(48)}); d < 47*time.Hour || d > 49*time.Hour {
		t.Errorf("ttl_hours=48 produced %v — the requested TTL did not reach the mint policy", d)
	}
	// Above the ceiling: clamped to 90 days, not rejected and not honoured.
	if d := ttlOf(map[string]any{"telegram_id": float64(42), "ttl_hours": float64(24 * 365)}); d < 89*24*time.Hour || d > 91*24*time.Hour {
		t.Errorf("ttl_hours=8760 produced %v, want it clamped to ~90 days", d)
	}
}

// The parity test the issue asks for: both transports must issue the same
// credential, so a policy change on one side alone fails here. It drives the
// REAL HTTP handler and the REAL tool and compares the decoded claims —
// scopes, audience and the orig_iat anchoring — rather than comparing two
// copies of a constant, which would pass while the two paths drifted.
func TestMintWorkerToken_HTTPAndToolIssueTheSameCredential(t *testing.T) {
	for _, purpose := range []string{"", "local-bridge"} {
		t.Run("purpose="+purpose, func(t *testing.T) {
			srv := newMintServer(t)
			args := map[string]any{"telegram_id": float64(4242)}
			if purpose != "" {
				args["purpose"] = purpose
			}
			viaTool := decodeMint(t, callMint(t, srv, []string{"admin:users"}, args))

			body := `{"telegram_id":4242}`
			if purpose != "" {
				body = `{"telegram_id":4242,"purpose":"` + purpose + `"}`
			}
			h := workertoken.NewHandler([]byte(mintTestSecret), mintTestIssuer, "")
			r := httptest.NewRequest("POST", "/api/mcp/worker-token", strings.NewReader(body))
			r = r.WithContext(auth.With(r.Context(), &auth.Identity{UserID: 1, Scopes: []string{"admin:users"}}))
			rec := httptest.NewRecorder()
			h(rec, r)
			if rec.Code != http.StatusOK {
				t.Fatalf("http mint status %d: %s", rec.Code, rec.Body.String())
			}
			var httpResp struct {
				WorkerToken string `json:"worker_token"`
				ExpiresAt   string `json:"expires_at"`
				Jti         string `json:"jti"`
			}
			if err := json.NewDecoder(rec.Body).Decode(&httpResp); err != nil {
				t.Fatalf("decode http response: %v", err)
			}

			toolClaims, err := localjwt.Verify(viaTool.WorkerToken, []byte(mintTestSecret), mintTestIssuer)
			if err != nil {
				t.Fatalf("verify tool token: %v", err)
			}
			httpClaims, err := localjwt.Verify(httpResp.WorkerToken, []byte(mintTestSecret), mintTestIssuer)
			if err != nil {
				t.Fatalf("verify http token: %v", err)
			}

			// The jti is the only handle that revokes this one token, and
			// it cannot be read back out of the token by the operator
			// holding it. A transport that omits it leaves "revoke every
			// token for this account" as the only remaining move, so both
			// have to hand it over.
			if httpResp.Jti == "" || httpResp.Jti != httpClaims.Jti {
				t.Errorf("http jti = %q, want the issued token's jti %q", httpResp.Jti, httpClaims.Jti)
			}
			if viaTool.Jti == "" || viaTool.Jti != toolClaims.Jti {
				t.Errorf("tool jti = %q, want the issued token's jti %q", viaTool.Jti, toolClaims.Jti)
			}

			if !sameStrings(toolClaims.Scopes, httpClaims.Scopes) {
				t.Errorf("scopes drifted: tool=%v http=%v", toolClaims.Scopes, httpClaims.Scopes)
			}
			if !sameStrings(toolClaims.Audience, httpClaims.Audience) {
				t.Errorf("audience drifted: tool=%v http=%v", toolClaims.Audience, httpClaims.Audience)
			}
			if toolClaims.Subject != httpClaims.Subject {
				t.Errorf("subject drifted: tool=%q http=%q", toolClaims.Subject, httpClaims.Subject)
			}
			// Both anchor the renewal chain; the values are seconds apart at
			// most, so compare that both are set and close rather than equal.
			if toolClaims.OriginalIssuedAt == 0 || httpClaims.OriginalIssuedAt == 0 {
				t.Errorf("orig_iat missing: tool=%d http=%d", toolClaims.OriginalIssuedAt, httpClaims.OriginalIssuedAt)
			}
			if d := toolClaims.ExpiresAt - httpClaims.ExpiresAt; d > 5 || d < -5 {
				t.Errorf("TTL drifted by %ds between transports", d)
			}
			if toolClaims.Jti == "" || toolClaims.Jti == httpClaims.Jti {
				t.Errorf("each mint must get its own jti; got tool=%q http=%q", toolClaims.Jti, httpClaims.Jti)
			}
		})
	}
}

func containsString(hay []string, needle string) bool {
	for _, s := range hay {
		if s == needle {
			return true
		}
	}
	return false
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// errMinter fails every mint the way an internal fault would: not wrapping
// ErrInvalidMintRequest, so it takes the "ours, not the caller's" branch.
type errMinter struct{ err error }

func (m errMinter) Mint(workertoken.MintRequest) (*workertoken.Minted, error) { return nil, m.err }

// An internal mint failure has two audiences with opposite needs. The caller
// gets a sanitised sentence, because the internals of a signing failure are
// not theirs to act on. The auditor asking why a mint failed gets the cause,
// because "failed to issue worker token" answers nothing. Asserting only the
// first half is what let the audit row quietly degrade to the sanitised text.
func TestToolMintWorkerToken_InternalFailureSanitisesCallerButAuditsCause(t *testing.T) {
	const cause = "sign worker token: hsm unreachable"
	srv := &Server{Store: newToolsTestStore(t), WorkerTokenMinter: errMinter{err: errors.New(cause)}}
	result := callMint(t, srv, []string{"admin:users"}, map[string]any{"telegram_id": float64(42)})
	if !result.IsError {
		t.Fatal("expected an error result on internal mint failure")
	}
	msg := ""
	for _, c := range result.Content {
		if tc, ok := c.(mcplib.TextContent); ok {
			msg += tc.Text
		}
	}
	if !strings.Contains(msg, "failed to issue worker token") {
		t.Fatalf("caller message = %q, want the generic sentence", msg)
	}
	if strings.Contains(msg, "hsm unreachable") {
		t.Fatalf("caller message leaks internals: %q", msg)
	}

	var status, auditMsg string
	err := srv.Store.DB.QueryRowContext(context.Background(),
		`SELECT status, error FROM audit_logs WHERE tool_name = $1 ORDER BY id DESC LIMIT 1`,
		"mint_worker_token").Scan(&status, &auditMsg)
	if err != nil {
		t.Fatalf("read audit row: %v", err)
	}
	if status != "error" {
		t.Fatalf("audit status = %q, want error", status)
	}
	if !strings.Contains(auditMsg, "hsm unreachable") {
		t.Fatalf("audit row = %q, want the underlying cause", auditMsg)
	}
}
