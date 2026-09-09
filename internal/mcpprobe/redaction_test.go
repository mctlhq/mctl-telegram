package mcpprobe_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"

	"github.com/mctlhq/mctl-telegram/internal/mcpprobe"
)

// Fixture secrets. These are synthetic values that never leave this test
// process's fake server -- not real credentials -- used only to prove that
// even when the raw wire response is dripping with the exact categories
// requirements.md acceptance criterion C forbids, the Report this package
// returns cannot carry them. Per CLAUDE.md's synthetic-fixture rule, the
// tool-result "chat title"/"peer id" values below use the Alice/Bob personas
// rather than any real Telegram identifier.
const (
	fixtureBearerToken = "shhh-fixture-bearer-token-do-not-log-9f8e7d"
	fixtureChatTitle   = "Alice & Bob"
	fixturePeerID      = "peer_alice_998877"
	fixturePhoneNumber = "+15551234567"
	fixtureMessageBody = "the secret launch code is 4821"
)

// newLeakyFixtureServer returns a modern+legacy capable server whose
// get_my_send_status tool result deliberately embeds every category of data
// a Report must never carry, and whose handler also asserts the incoming
// Authorization header equals fixtureBearerToken -- proving the probe really
// did send the secret over the wire, not merely that it withheld one it
// never had.
func newLeakyFixtureServer(t *testing.T) *httptest.Server {
	t.Helper()

	srv := mcpserver.NewMCPServer("mcpprobe-leaky-fixture", "1.0.0", mcpserver.WithToolCapabilities(true))
	srv.AddTool(
		mcplib.NewTool("get_my_send_status", mcplib.WithReadOnlyHintAnnotation(true)),
		func(_ context.Context, _ mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
			leaky, _ := json.Marshal(map[string]any{
				"can_send":     true,
				"chat_title":   fixtureChatTitle,
				"peer_id":      fixturePeerID,
				"phone_number": fixturePhoneNumber,
				"message_body": fixtureMessageBody,
				"bearer_echo":  fixtureBearerToken,
			})
			return mcplib.NewToolResultText(string(leaky)), nil
		},
	)

	mux := http.NewServeMux()
	mcpHandler := mcpserver.NewStreamableHTTPServer(srv)
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+fixtureBearerToken {
			t.Errorf("server did not receive the configured bearer token: got %q", got)
		}
		mcpHandler.ServeHTTP(w, r)
	}))

	httpServer := httptest.NewServer(mux)
	t.Cleanup(httpServer.Close)
	return httpServer
}

// T6: redaction test proves serialized output omits fixture bearer tokens,
// message bodies, chat titles, peer ids, and full session ids, in both
// modern and legacy mode, even though the live fixture server actually
// returned all of them over the wire.
func TestReport_RedactsFixtureSecrets(t *testing.T) {
	forbidden := []string{
		fixtureBearerToken,
		fixtureChatTitle,
		fixturePeerID,
		fixturePhoneNumber,
		fixtureMessageBody,
	}

	assertRedacted := func(t *testing.T, label string, report *mcpprobe.Report) {
		t.Helper()
		out, err := json.Marshal(report)
		if err != nil {
			t.Fatalf("marshal report: %v", err)
		}
		serialized := string(out)
		for _, secret := range forbidden {
			if strings.Contains(serialized, secret) {
				t.Errorf("%s: serialized report contains forbidden fixture value %q\nreport: %s", label, secret, serialized)
			}
		}
	}

	t.Run("modern", func(t *testing.T) {
		srv := newLeakyFixtureServer(t)
		modernResult, err := mcpprobe.ProbeModern(context.Background(), mcpprobe.ModernConfig{
			BaseURL:     srv.URL,
			BearerToken: fixtureBearerToken,
		})
		if err != nil {
			t.Fatalf("ProbeModern: %v", err)
		}
		if !modernResult.ToolCall.Attempted || modernResult.ToolCall.IsError {
			t.Fatalf("precondition: tools/call did not succeed: %+v", modernResult.ToolCall)
		}
		report := mcpprobe.NewReport(mcpprobe.ReportMeta{
			EvidenceSource: mcpprobe.EvidenceInProcessCurrentMain,
			Label:          "redaction test",
		}, modernResult, nil, nil)
		assertRedacted(t, "modern", report)
	})

	t.Run("legacy", func(t *testing.T) {
		srv := newLeakyFixtureServer(t)
		legacyResult, err := mcpprobe.ProbeLegacy(context.Background(), mcpprobe.LegacyConfig{
			BaseURL:     srv.URL,
			BearerToken: fixtureBearerToken,
		})
		if err != nil {
			t.Fatalf("ProbeLegacy: %v", err)
		}
		if !legacyResult.ToolCall.Attempted || legacyResult.ToolCall.IsError {
			t.Fatalf("precondition: legacy tools/call did not succeed: %+v", legacyResult.ToolCall)
		}
		if legacyResult.Initialize.SessionIDLength == 0 {
			t.Fatal("precondition: legacy initialize did not mint a session id to try to leak")
		}
		report := mcpprobe.NewReport(mcpprobe.ReportMeta{
			EvidenceSource: mcpprobe.EvidenceInProcessCurrentMain,
			Label:          "redaction test",
		}, nil, legacyResult, nil)
		assertRedacted(t, "legacy", report)
	})
}
