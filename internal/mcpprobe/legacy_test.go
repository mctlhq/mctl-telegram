package mcpprobe_test

import (
	"context"
	"net/http"
	"testing"

	mcpserver "github.com/mark3labs/mcp-go/server"

	"github.com/mctlhq/mctl-telegram/internal/mcpprobe"
)

// T4: legacy stateful fake mints Mcp-Session-Id; the probe records and uses
// it only in legacy mode (it never appears in a ModernResult, since
// ProbeModern and ProbeLegacy are separate functions returning separate
// types -- see modern_test.go).
func TestProbeLegacy_InitializeMintsSessionAndToolCallSucceeds(t *testing.T) {
	srv := newFixtureServer(t)

	result, err := mcpprobe.ProbeLegacy(context.Background(), mcpprobe.LegacyConfig{BaseURL: srv.URL})
	if err != nil {
		t.Fatalf("ProbeLegacy: %v", err)
	}

	if result.ProtocolVersion != mcpprobe.DefaultLegacyProtocolVersion {
		t.Errorf("ProtocolVersion = %q, want %q", result.ProtocolVersion, mcpprobe.DefaultLegacyProtocolVersion)
	}

	if result.Initialize == nil {
		t.Fatal("Initialize observation missing")
	}
	if result.Initialize.HTTPStatus != http.StatusOK {
		t.Fatalf("initialize HTTP status = %d, want 200", result.Initialize.HTTPStatus)
	}
	if !result.Initialize.SessionIDMinted {
		t.Error("legacy initialize did not mint a session id")
	}
	if result.Initialize.SessionIDLength == 0 {
		t.Error("SessionIDMinted=true but SessionIDLength=0")
	}
	if result.Initialize.NegotiatedProtocolVersion != mcpprobe.DefaultLegacyProtocolVersion {
		t.Errorf("negotiated protocol version = %q, want %q", result.Initialize.NegotiatedProtocolVersion, mcpprobe.DefaultLegacyProtocolVersion)
	}

	if result.ToolsList == nil || !result.ToolsList.Attempted {
		t.Fatal("legacy tools/list was not attempted")
	}
	if result.ToolsList.ToolCount != 2 {
		t.Errorf("tools/list tool count = %d, want 2", result.ToolsList.ToolCount)
	}

	if result.ToolCall == nil || !result.ToolCall.Attempted {
		t.Fatalf("legacy tools/call was not attempted: %+v", result.ToolCall)
	}
	if result.ToolCall.IsError {
		t.Error("legacy read-only tools/call reported isError=true")
	}
}

// A server configured to actually validate sessions locally
// (mcpserver.WithStateful(true), matching InsecureStatefulSessionIdManager)
// must refuse the same call once the session id is dropped -- the evidence
// for "session id required", distinct from "minted".
func TestProbeLegacy_SessionRequiredWhenServerValidatesLocally(t *testing.T) {
	srv := newFixtureServer(t, mcpserver.WithStateful(true))

	result, err := mcpprobe.ProbeLegacy(context.Background(), mcpprobe.LegacyConfig{BaseURL: srv.URL})
	if err != nil {
		t.Fatalf("ProbeLegacy: %v", err)
	}

	if !result.Initialize.SessionIDMinted {
		t.Fatal("precondition: stateful server did not mint a session id")
	}
	if !result.ToolsList.SessionIDRequired {
		t.Error("stateful server: expected tools/list without session id to be refused")
	}
}
