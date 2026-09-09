package mcpprobe_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/db"
	mcpapp "github.com/mctlhq/mctl-telegram/internal/mcp"
	"github.com/mctlhq/mctl-telegram/internal/mcpprobe"
)

// newInProcessStore opens an in-memory SQLite store and runs migrations,
// exactly like internal/mcp's own test helpers (see
// internal/mcp/tools_test.go newToolsTestStore).
func newInProcessStore(t *testing.T) *db.Store {
	t.Helper()
	ctx := context.Background()
	conn, err := db.Open(ctx, "file::memory:?cache=shared", 0, 0)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := db.Migrate(ctx, conn); err != nil {
		t.Fatalf("db.Migrate: %v", err)
	}
	return &db.Store{DB: conn}
}

// T7: in-process integration test. This mounts the REAL internal/mcp.Server
// HTTP handler -- the same HTTPHandler() production wires at /mcp (see
// cmd/server/main.go) -- not a hand-rolled fake, and produces an
// in-process-current-main result. It intentionally does not layer the real
// OAuth/JWT auth.Middleware on top: that stack is exercised by internal/
// oauth's own test suite, and stacking it here would only test auth twice
// while adding nothing to what this package's tests are about (modern/
// legacy MCP protocol behavior). The identity injected below plays exactly
// the role auth.Middleware plays for a validated token: populating
// auth.Identity in the request context that HTTPHandler's
// WithHTTPContextFunc forwards unchanged into every tool handler.
//
// This result must never be reported as live tg.mctl.ai evidence -- it is
// evidence about the code in this checkout, nothing more.
func TestInProcessCurrentMain_ModernAndLegacy(t *testing.T) {
	const fixtureTelegramID = 700000585 // synthetic; not a real Telegram id

	store := newInProcessStore(t)
	ctx := context.Background()

	uid, err := store.EnsureUserByTelegramID(ctx, fixtureTelegramID, "seed", "Seed User")
	if err != nil {
		t.Fatalf("EnsureUserByTelegramID: %v", err)
	}
	if _, err := store.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, session_encrypted, send_enabled, mode) VALUES($1, $2, $3, 'hosted')`,
		uid, []byte("fixture-not-a-real-session"), true,
	); err != nil {
		t.Fatalf("seed hosted account: %v", err)
	}

	mcpSrv := mcpapp.New(store, nil, true) // AllowSend=true; Pool is nil -- untouched by get_my_send_status

	identity := &auth.Identity{UserID: uid, Scopes: []string{"telegram:messages:send"}}
	injectIdentity := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(auth.With(r.Context(), identity)))
		})
	}

	httpServer := httptest.NewServer(injectIdentity(mcpSrv.HTTPHandler()))
	t.Cleanup(httpServer.Close)

	modernResult, err := mcpprobe.ProbeModern(ctx, mcpprobe.ModernConfig{BaseURL: httpServer.URL})
	if err != nil {
		t.Fatalf("ProbeModern: %v", err)
	}
	if !modernResult.ToolCall.Attempted || modernResult.ToolCall.IsError {
		t.Fatalf("modern get_my_send_status against the real handler did not succeed: %+v", modernResult.ToolCall)
	}

	legacyResult, err := mcpprobe.ProbeLegacy(ctx, mcpprobe.LegacyConfig{BaseURL: httpServer.URL})
	if err != nil {
		t.Fatalf("ProbeLegacy: %v", err)
	}
	if !legacyResult.Initialize.SessionIDMinted {
		t.Error("legacy initialize against the real handler did not mint a session id")
	}
	if !legacyResult.ToolCall.Attempted || legacyResult.ToolCall.IsError {
		t.Fatalf("legacy get_my_send_status against the real handler did not succeed: %+v", legacyResult.ToolCall)
	}

	report := mcpprobe.NewReport(mcpprobe.ReportMeta{
		EvidenceSource: mcpprobe.EvidenceInProcessCurrentMain,
		Label:          "internal/mcp.Server.HTTPHandler(), in-process (T7)",
	}, modernResult, legacyResult, nil)

	if report.EvidenceSource != mcpprobe.EvidenceInProcessCurrentMain {
		t.Errorf("EvidenceSource = %q, want %q", report.EvidenceSource, mcpprobe.EvidenceInProcessCurrentMain)
	}
	if report.Pending != "" {
		t.Errorf("Pending = %q, want empty: this report reflects a real run, not a deferred operator row", report.Pending)
	}
}
