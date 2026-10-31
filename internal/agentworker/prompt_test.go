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

// TestDeployedPrompt_CarriesLeadIDContract: save_job_lead creates a lead
// unless it is given a lead_id (#951). Without this guidance the model
// would either duplicate a lead on every turn or pack several roles into
// one.
func TestDeployedPrompt_CarriesLeadIDContract(t *testing.T) {
	raw, err := os.ReadFile("../../deploy/agent-worker/system-prompt.txt")
	if err != nil {
		t.Fatalf("read prompt: %v", err)
	}
	text := strings.Join(strings.Fields(string(raw)), " ")
	for _, clause := range []string{
		"get_conversation_context returns them in leads",
		"pass its lead_id",
		"omit lead_id, which creates a new lead",
		"a message pitching two roles is two calls",
	} {
		if !strings.Contains(text, clause) {
			t.Errorf("deployed prompt: missing %q", clause)
		}
	}
	if strings.Contains(text, "later calls upsert") {
		t.Error("deployed prompt still says later calls upsert")
	}
}

// TestDeployedPrompt_CarriesOwnerChannelContract: nothing the owner writes
// in Saved Messages reaches the agent, and nothing tracks a promise made in
// a reply (#952). Without these clauses the model asks the owner to "tell
// me what to say" and promises follow-ups "shortly" on the owner's behalf.
func TestDeployedPrompt_CarriesOwnerChannelContract(t *testing.T) {
	raw, err := os.ReadFile("../../deploy/agent-worker/system-prompt.txt")
	if err != nil {
		t.Fatalf("read prompt: %v", err)
	}
	text := strings.Join(strings.Fields(string(raw)), " ")
	for _, clause := range []string{
		"No promises on the owner's behalf",
		`Never promise a time ("shortly"`,
		"never promise that anything will be sent later",
		"The owner cannot reply to you.",
		"never ask the owner to send you answers, to tell you what to say",
		"write to the sender in the chat themselves, which stops you in that chat",
	} {
		if !strings.Contains(text, clause) {
			t.Errorf("deployed prompt: missing %q", clause)
		}
	}
	if strings.Contains(text, " he cannot") {
		t.Error("deployed prompt assumes the owner's pronouns")
	}
}

// TestDeployedPrompt_CarriesPronounContract: owner summaries assumed the
// sender's gender ("answer him in the chat", #988), copied from the prompt's
// own example. The prompt must name people or use "they" and must not model
// a gendered pronoun itself.
func TestDeployedPrompt_CarriesPronounContract(t *testing.T) {
	raw, err := os.ReadFile("../../deploy/agent-worker/system-prompt.txt")
	if err != nil {
		t.Fatalf("read prompt: %v", err)
	}
	text := strings.Join(strings.Fields(string(raw)), " ")
	for _, clause := range []string{
		`Refer to the sender and anyone else by name or as "they"`,
		"never write he, him, she or her about a person unless they stated their pronouns",
	} {
		if !strings.Contains(text, clause) {
			t.Errorf("deployed prompt: missing %q", clause)
		}
	}
	for _, phrase := range []string{"answer him", "answer her", "ask him", "ask her", "tell him", "tell her"} {
		if strings.Contains(text, phrase) {
			t.Errorf("deployed prompt models a gendered pronoun: %q", phrase)
		}
	}
}

// TestSystemPrompts_CarryOwnerVoiceContract: drafts voiced preferences the
// profile does not hold as the owner's own ("Video would be my preference",
// #998). Policy has no value to match there, so the prompt is the only
// guard, in the deployed prompt and the C1 eval prompt alike.
func TestSystemPrompts_CarryOwnerVoiceContract(t *testing.T) {
	for _, path := range []string{
		"../../deploy/agent-worker/system-prompt.txt",
		"testdata/c1-system-prompt.txt",
	} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		text := strings.Join(strings.Fields(string(raw)), " ")
		for _, clause := range []string{
			`Speak about the owner in the third person, by name or as "the owner", never as "I".`,
			"Never state a preference, choice or availability as the owner's",
			`("my preference", "I prefer", "works for me", "I'll confirm")`,
			"unless get_recruiter_profile holds it",
		} {
			if !strings.Contains(text, clause) {
				t.Errorf("%s: missing %q", path, clause)
			}
		}
	}
}
