package oauth

import (
	"os"
	"strings"
	"testing"
)

// TestTroubleshootingDocQuotesRedirectURISchemeError asserts that the exact
// error text validateRedirectURIShape returns for a custom-scheme
// redirect_uri (e.g. a "cursor://" client) is quoted verbatim in
// docs/troubleshooting.md, so the page cannot drift from the actual
// validation behavior it documents.
func TestTroubleshootingDocQuotesRedirectURISchemeError(t *testing.T) {
	_, err := validateRedirectURIShape("cursor://anonymous/callback")
	if err == nil {
		t.Fatal("expected validateRedirectURIShape(\"cursor://anonymous/callback\") to return an error")
	}

	data, rerr := os.ReadFile("../../docs/troubleshooting.md")
	if rerr != nil {
		t.Fatalf("failed to read docs/troubleshooting.md: %v", rerr)
	}
	content := string(data)

	want := err.Error()
	if !strings.Contains(content, want) {
		t.Errorf("docs/troubleshooting.md does not quote validateRedirectURIShape's error verbatim; expected to find %q", want)
	}
}
