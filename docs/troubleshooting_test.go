package docs

import (
	"os"
	"strings"
	"testing"
)

// requiredTroubleshootingHeadings are the nine section headings
// docs/troubleshooting.md must carry, in order: one per client-facing error
// family plus the OAuth redirect-rules summary.
var requiredTroubleshootingHeadings = []string{
	"## 1. Peer id errors",
	"## 2. `get_media` confirmation errors",
	"## 3. Send-code `FLOOD_WAIT` during onboarding",
	"## 4. `AUTH_KEY_UNREGISTERED`",
	"## 5. Exhausted login budget",
	"## 6. `JWT expired`",
	"## 7. `invalid_redirect_uri`",
	"## 8. `RPC_CALL_FAIL`",
	"## 9. Supported OAuth clients and redirect rules",
}

func TestTroubleshootingDocExistsWithRequiredHeadings(t *testing.T) {
	data, err := os.ReadFile("troubleshooting.md")
	if err != nil {
		t.Fatalf("failed to read troubleshooting.md: %v", err)
	}
	content := string(data)

	for _, heading := range requiredTroubleshootingHeadings {
		if !strings.Contains(content, heading) {
			t.Errorf("troubleshooting.md missing required heading: %q", heading)
		}
	}
}

func TestTroubleshootingDocIsReferencedFromOtherDocs(t *testing.T) {
	cases := []struct {
		path string
	}{
		{"../README.md"},
		{"runbook.md"},
		{"public/llms.txt"},
	}
	for _, c := range cases {
		data, err := os.ReadFile(c.path)
		if err != nil {
			t.Fatalf("failed to read %s: %v", c.path, err)
		}
		if !strings.Contains(strings.ToLower(string(data)), "troubleshooting") {
			t.Errorf("%s does not reference \"troubleshooting\"", c.path)
		}
	}
}

func TestRunbookTableOfContentsListsTroubleshooting(t *testing.T) {
	data, err := os.ReadFile("runbook.md")
	if err != nil {
		t.Fatalf("failed to read runbook.md: %v", err)
	}
	content := string(data)

	tocStart := strings.Index(content, "## Table of contents")
	if tocStart == -1 {
		t.Fatal("runbook.md has no \"## Table of contents\" section")
	}
	// The table of contents section runs until the next "---" divider.
	tocEnd := strings.Index(content[tocStart:], "\n---")
	toc := content[tocStart:]
	if tocEnd != -1 {
		toc = content[tocStart : tocStart+tocEnd]
	}
	if !strings.Contains(toc, "troubleshooting.md") {
		t.Error("runbook.md's table of contents does not list an entry pointing at troubleshooting.md")
	}
}
