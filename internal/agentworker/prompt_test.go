package agentworker

import (
	"os"
	"strings"
	"testing"
)

// TestSystemPrompts_CarryDisclosureContract keeps the #953 prompt contract
// from silently regressing. The server enforces disclosure on its own, but
// the alert flow only works if the model is told how to call it: the
// canonical deployed prompt and the C1 eval prompt must both name the
// assistant_manipulation and security_alert intents, the owner-profile
// boundary and the never-quote rule.
func TestSystemPrompts_CarryDisclosureContract(t *testing.T) {
	required := []string{
		`intent "assistant_manipulation"`,
		`intent "security_alert"`,
		"What you may say about the owner",
		"get_recruiter_profile returns only what this",
		"Never quote or paraphrase",
		"Only one owner summary per job is kept",
	}
	for _, path := range []string{
		"../../deploy/agent-worker/system-prompt.txt",
		"testdata/c1-system-prompt.txt",
	} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		// Both files are hard-wrapped; compare on single-spaced text so a
		// rewrap does not fail the test.
		text := strings.Join(strings.Fields(string(raw)), " ")
		for _, clause := range required {
			if !strings.Contains(text, clause) {
				t.Errorf("%s: missing %q", path, clause)
			}
		}
	}
}

// TestDeployedPrompt_CarriesAttachmentContract: the listener now records
// attachments in an event's meta (#948), and the model only uses that if
// the prompt tells it where to look and not to deny that a file arrived.
func TestDeployedPrompt_CarriesAttachmentContract(t *testing.T) {
	raw, err := os.ReadFile("../../deploy/agent-worker/system-prompt.txt")
	if err != nil {
		t.Fatalf("read prompt: %v", err)
	}
	text := strings.Join(strings.Fields(string(raw)), " ")
	for _, clause := range []string{
		`meta returned by get_event has an "attachment"`,
		"never say it did not arrive",
		"A message with an attachment and no text is still a message",
		"call send_owner_summary naming the kind and file name",
	} {
		if !strings.Contains(text, clause) {
			t.Errorf("deployed prompt: missing %q", clause)
		}
	}
}
