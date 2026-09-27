package mcp

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

// undocumentedCatalogCodes lists mtprotoErrCatalog/mtprotoTransientCatalog
// keys that docs/troubleshooting.md deliberately does not document (they are
// not among the eight families issue #669 asked for). Adding a new catalog
// entry without either documenting it (via a "<!-- catalog: CODE -->" marker
// whose message+action appear verbatim on the page) or listing it here fails
// this test — see requirements.md acceptance criteria for
// issue-669-docs-troubleshooting-page-for-the-error.
var undocumentedCatalogCodes = map[string]bool{
	"USERNAME_INVALID":       true,
	"USERNAME_NOT_OCCUPIED":  true,
	"CHAT_FORBIDDEN":         true,
	"CHAT_WRITE_FORBIDDEN":   true,
	"USER_BANNED_IN_CHANNEL": true,
	"MESSAGE_ID_INVALID":     true,
	"MSG_ID_INVALID":         true,
	"INPUT_USER_DEACTIVATED": true,
	"PHONE_NUMBER_INVALID":   true,
	"CHANNEL_PRIVATE":        true,
	"USER_NOT_PARTICIPANT":   true,
	"PEER_FLOOD":             true,
}

const troubleshootingDocPath = "../../docs/troubleshooting.md"

func readTroubleshootingDoc(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(troubleshootingDocPath)
	if err != nil {
		t.Fatalf("failed to read %s: %v", troubleshootingDocPath, err)
	}
	return string(data)
}

// catalogMarkerRe matches "<!-- catalog: CODE -->" markers in the doc.
var catalogMarkerRe = regexp.MustCompile(`<!--\s*catalog:\s*([A-Z0-9_]+)\s*-->`)

func TestTroubleshootingDocCatalogMarkersAreReal(t *testing.T) {
	content := readTroubleshootingDoc(t)
	matches := catalogMarkerRe.FindAllStringSubmatch(content, -1)
	if len(matches) == 0 {
		t.Fatal("expected at least one \"<!-- catalog: CODE -->\" marker in docs/troubleshooting.md")
	}
	for _, m := range matches {
		code := m[1]
		_, inErr := mtprotoErrCatalog[code]
		_, inTransient := mtprotoTransientCatalog[code]
		if !inErr && !inTransient {
			t.Errorf("docs/troubleshooting.md marks %q as a catalog code, but it is not a key in mtprotoErrCatalog or mtprotoTransientCatalog", code)
		}
	}
}

func TestTroubleshootingDocCoversOrAllowlistsEveryCatalogEntry(t *testing.T) {
	content := readTroubleshootingDoc(t)
	markedCodes := map[string]bool{}
	for _, m := range catalogMarkerRe.FindAllStringSubmatch(content, -1) {
		markedCodes[m[1]] = true
	}

	checkEntry := func(code, message, action string) {
		if undocumentedCatalogCodes[code] {
			if markedCodes[code] {
				t.Errorf("catalog code %q is both allowlisted as undocumented and marked with a <!-- catalog: %s --> comment; pick one", code, code)
			}
			return
		}
		if !markedCodes[code] {
			t.Errorf("catalog code %q is neither documented (a \"<!-- catalog: %s -->\" marker) nor listed in undocumentedCatalogCodes", code, code)
			return
		}
		if !containsVerbatim(content, message) {
			t.Errorf("catalog code %q message not found verbatim in docs/troubleshooting.md: %q", code, message)
		}
		if action != "" && !containsVerbatim(content, action) {
			t.Errorf("catalog code %q action not found verbatim in docs/troubleshooting.md: %q", code, action)
		}
	}

	for code, entry := range mtprotoErrCatalog {
		checkEntry(code, entry.message, entry.action)
	}
	for code, entry := range mtprotoTransientCatalog {
		checkEntry(code, entry.message, entry.action)
	}
}

func TestTroubleshootingDocRendersConfirmationTTL(t *testing.T) {
	content := readTroubleshootingDoc(t)
	want := fmt.Sprintf("%d minutes", int(ConfirmationTTL.Minutes()))
	if !containsVerbatim(content, want) {
		t.Errorf("docs/troubleshooting.md does not render ConfirmationTTL (%s) verbatim; expected to find %q", ConfirmationTTL, want)
	}
}

func TestTroubleshootingDocRendersSessionRevokedText(t *testing.T) {
	content := readTroubleshootingDoc(t)
	want := sessionErrText(db.ErrSessionRevoked)
	if want == "" {
		t.Fatal("sessionErrText(db.ErrSessionRevoked) returned an empty string")
	}
	if !containsVerbatim(content, want) {
		t.Errorf("docs/troubleshooting.md does not quote sessionErrText(db.ErrSessionRevoked) verbatim; expected to find %q", want)
	}
}

func TestTroubleshootingDocRendersConfirmationErrorStrings(t *testing.T) {
	content := readTroubleshootingDoc(t)
	// Verbatim strings returned by get_media in internal/mcp/media_tools.go.
	strs := []string{
		"confirmation_id not found, expired, or already used",
		"confirmation_id was issued for a different (peer, message_id) — re-run prepare_get_media",
		"confirmation_id belongs to another identity",
		"download already in progress for this confirmation_id — retry shortly",
	}
	for _, s := range strs {
		if !containsVerbatim(content, s) {
			t.Errorf("docs/troubleshooting.md does not contain the media_tools.go confirmation error string verbatim: %q", s)
		}
	}
}

func containsVerbatim(haystack, needle string) bool {
	return needle != "" && strings.Contains(haystack, needle)
}
