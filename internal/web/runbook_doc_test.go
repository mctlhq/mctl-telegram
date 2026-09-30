package web

import (
	"os"
	"strings"
	"testing"
)

// TestRunbookDocumentsConnectReasons is T14: every reason* const declared in
// connect.go must appear in docs/runbook.md's rejection-reasons table, so a
// new const added on this side of the deliberate internal/web/internal/oauth
// duplication (see connect.go's block comment) cannot silently drift from the
// documentation. Modelled on
// internal/oauth/troubleshooting_doc_test.go.
func TestRunbookDocumentsConnectReasons(t *testing.T) {
	reasons := []string{
		reasonMissingState,
		reasonMissingCode,
		reasonUnknownState,
		reasonExpiredState,
		reasonExchangeFailed,
		reasonOIDCError,
		reasonPrefetchRefused,
		reasonRecoveredRedirect,
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
}
