package mcpprobe_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/auth/localjwt"
	"github.com/mctlhq/mctl-telegram/internal/db"
	mcpapp "github.com/mctlhq/mctl-telegram/internal/mcp"
	"github.com/mctlhq/mctl-telegram/internal/mcpprobe"

	"net/http/httptest"

	_ "modernc.org/sqlite"
)

const (
	inProcessIssuer = "https://tg.test"
	inProcessTGID   = 500100101
)

var inProcessSecret = []byte("mcpprobe-inprocess-secret-32b!!!")

// newInProcessTarget mounts the real MCP handler behind the real
// authentication middleware and returns its URL plus a valid bearer.
//
// It deliberately builds a smaller fixture than the Local Bridge end-to-end
// harness: this test is about what the MCP handler wiring does with a
// protocol request, so pulling in the OAuth server and the bridge hub would
// add moving parts without adding evidence.
func newInProcessTarget(t *testing.T) (string, string) {
	t.Helper()
	ctx := context.Background()

	conn, err := db.Open(ctx, "file:"+filepath.Join(t.TempDir(), "probe.db"), 0, 0)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := db.Migrate(ctx, conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	store := db.NewStore(conn, nil)

	provider, err := localjwt.NewProvider(store, localjwt.ProviderConfig{
		Secret:           inProcessSecret,
		ExpectedIssuer:   inProcessIssuer,
		ExpectedAudience: "mcp",
		AudienceRequired: true,
	})
	if err != nil {
		t.Fatalf("provider: %v", err)
	}
	issuer, err := localjwt.NewIssuer(inProcessSecret, inProcessIssuer)
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	token, err := issuer.Mint(localjwt.Claims{
		Subject:    "tg:500100101",
		TelegramID: inProcessTGID,
		Scopes:     []string{"telegram:messages:read"},
		Audience:   []string{"mcp"},
	}, time.Hour)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	// allowSend=false keeps this fixture incapable of delivering a message
	// even if a future change let a mutating tool through the guard.
	mcpSrv := mcpapp.New(store, nil, false)
	r := chi.NewRouter()
	r.Mount("/mcp", auth.Middleware(provider, true, nil, auth.ResourceMetadata{
		BaseURL: inProcessIssuer, MCPPath: "/mcp",
	})(mcpSrv.HTTPHandler()))

	ts := httptest.NewServer(r)
	t.Cleanup(ts.Close)
	return ts.URL + "/mcp", token
}

// TestInProcess_ModernPathAgainstRealHandler is T7. It produces the one
// evidence row continuous integration is entitled to produce, and it is
// labelled as such: this is what the code on this branch supports, not what
// any deployed endpoint does.
func TestInProcess_ModernPathAgainstRealHandler(t *testing.T) {
	url, token := newInProcessTarget(t)

	report, err := mcpprobe.Run(context.Background(), mcpprobe.Options{
		URL: url, Mode: mcpprobe.ModeModern, Token: token,
		Source: mcpprobe.SourceInProcess, SkipOAuth: true,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if report.Source != mcpprobe.SourceInProcess {
		t.Fatalf("source = %s; an in-process result must never claim to be a deployed one", report.Source)
	}
	if report.Summary != mcpprobe.OutcomePass {
		t.Fatalf("summary = %s\nsteps: %+v\nnegatives: %+v", report.Summary, report.Steps, report.Negatives)
	}
	if report.Server.Name != "mctl-telegram" {
		t.Errorf("server name = %q, want mctl-telegram", report.Server.Name)
	}
	if len(report.Server.SupportedVersions) == 0 {
		t.Error("server advertised no supported versions")
	}
	// The headline finding of the modern row: no session identifier exists
	// on this path, so nothing in front of the server needs affinity for it.
	if report.Session.HeaderPresent {
		t.Errorf("modern path minted a session identifier (length %d)", report.Session.IDLength)
	}

	var sawReadOnly, sawMutating bool
	for _, tool := range report.Tools {
		switch tool.Name {
		case mcpprobe.DefaultTool:
			sawReadOnly = tool.ReadOnly != nil && *tool.ReadOnly
		case "send_message":
			sawMutating = tool.ReadOnly == nil || !*tool.ReadOnly
		}
	}
	if !sawReadOnly {
		t.Errorf("%s was not reported read-only by the real handler", mcpprobe.DefaultTool)
	}
	if !sawMutating {
		t.Error("send_message was reported read-only by the real handler")
	}
}

// TestInProcess_LegacyPathAgainstRealHandler records what the legacy row
// looks like on this branch: an identifier is minted at initialize, and it
// is not required afterwards. Both halves matter, and asserting them here
// means a change to either one has to be deliberate.
func TestInProcess_LegacyPathAgainstRealHandler(t *testing.T) {
	url, token := newInProcessTarget(t)

	report, err := mcpprobe.Run(context.Background(), mcpprobe.Options{
		URL: url, Mode: mcpprobe.ModeLegacy, LegacyVersion: mcp.ProtocolVersion20250618,
		Token: token, Source: mcpprobe.SourceInProcess, SkipOAuth: true,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if report.Summary != mcpprobe.OutcomePass {
		t.Fatalf("summary = %s\nsteps: %+v", report.Summary, report.Steps)
	}
	if !report.Session.HeaderPresent {
		t.Error("legacy initialize minted no session identifier")
	}
	if report.Session.Required == nil {
		t.Fatal("legacy run did not measure whether the session identifier is required")
	}
	// Measured, not assumed: the legacy path refuses a request that carries
	// no identifier at all.
	if !*report.Session.Required {
		t.Error("the legacy path stopped requiring a session identifier; that is a " +
			"rollout-affecting change, not a test detail — see mctlhq/mctl-telegram#568")
	}
	if report.Session.ForeignAccepted == nil {
		t.Fatal("legacy run did not measure whether a foreign identifier is accepted")
	}
	// And it accepts any well-formed identifier, including one it never
	// issued. That combination is the useful finding: a router must carry
	// the header through, but need not pin a request to the process that
	// issued it.
	if !*report.Session.ForeignAccepted {
		t.Error("the legacy path became genuinely session-bound; a router in front of it " +
			"would now need replica affinity — see mctlhq/mctl-telegram#568")
	}
}

// TestInProcess_ModernAndLegacyStaySeparate keeps the two rows from being
// read as one measurement. They disagree about sessions, and that
// disagreement is a finding rather than an inconsistency to smooth over.
func TestInProcess_ModernAndLegacyStaySeparate(t *testing.T) {
	url, token := newInProcessTarget(t)
	ctx := context.Background()

	modern, err := mcpprobe.Run(ctx, mcpprobe.Options{
		URL: url, Mode: mcpprobe.ModeModern, Token: token,
		Source: mcpprobe.SourceInProcess, SkipOAuth: true,
	})
	if err != nil {
		t.Fatalf("modern run: %v", err)
	}
	legacy, err := mcpprobe.Run(ctx, mcpprobe.Options{
		URL: url, Mode: mcpprobe.ModeLegacy, LegacyVersion: mcp.ProtocolVersion20250618,
		Token: token, Source: mcpprobe.SourceInProcess, SkipOAuth: true,
	})
	if err != nil {
		t.Fatalf("legacy run: %v", err)
	}
	if modern.Session.HeaderPresent == legacy.Session.HeaderPresent {
		t.Errorf("both rows report session presence %v; the two paths differ here and the report must show it",
			modern.Session.HeaderPresent)
	}
	if len(modern.Negatives) == 0 || len(legacy.Negatives) != 0 {
		t.Errorf("negatives: modern %d, legacy %d — the modern binding is only testable on the modern row",
			len(modern.Negatives), len(legacy.Negatives))
	}
}
