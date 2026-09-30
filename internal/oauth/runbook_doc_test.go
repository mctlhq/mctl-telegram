package oauth

import (
	"os"
	"strings"
	"testing"
)

// TestRunbookDocumentsCallbackReasons is T15: every reason* const declared in
// server.go must appear in docs/runbook.md's rejection-reasons table, so a
// new const added on this side of the deliberate internal/web/internal/oauth
// duplication cannot silently drift from the documentation. Also asserts the
// startup headline "auth provider init failed" (cmd/server/main.go) is
// documented. Modelled on troubleshooting_doc_test.go.
func TestRunbookDocumentsCallbackReasons(t *testing.T) {
	reasons := []string{
		reasonMissingState,
		reasonMissingCode,
		reasonOIDCError,
		reasonUnknownState,
		reasonExpiredState,
		reasonExchangeFailed,
		reasonPrefetchRefused,
	}

	data, err := os.ReadFile("../../docs/runbook.md")
	if err != nil {
		t.Fatalf("failed to read docs/runbook.md: %v", err)
	}
	content := string(data)

	if !strings.Contains(content, `id="connectrejectionreasons"`) {
		t.Error(`docs/runbook.md missing anchor: id="connectrejectionreasons"`)
	}

	for _, reason := range reasons {
		if !strings.Contains(content, reason) {
			t.Errorf("docs/runbook.md does not mention reason %q", reason)
		}
	}

	const startupHeadline = "auth provider init failed"
	if !strings.Contains(content, startupHeadline) {
		t.Errorf("docs/runbook.md does not mention the startup headline %q", startupHeadline)
	}
}
