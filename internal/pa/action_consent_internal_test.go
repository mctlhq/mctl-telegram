package pa

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/pa/convo"
	"github.com/mctlhq/mctl-telegram/internal/pa/jobs"
	"github.com/mctlhq/mctl-telegram/internal/pa/output/safetext"
)

// TestActionConsentPromptIsConsentText: each action-consent prompt sends
// exactly the text whose hash its button binds, in one message, in every
// chat language.
func TestActionConsentPromptIsConsentText(t *testing.T) {
	for tpl, want := range map[safetext.Template]string{
		safetext.TextActionConsentPrompt: convo.ActionConsentText, safetext.TextActionConsentPromptRU: convo.ActionConsentTextRU,
	} {
		for _, l := range []safetext.Lang{safetext.LangEN, safetext.LangRU} {
			got := safetext.ServerText(tpl).In(l)
			if got.String() != want || got.Parts() != 1 {
				t.Fatalf("action consent prompt in language %d differs from its convo text (parts %d)", l, got.Parts())
			}
		}
	}
	if outboxTemplates[jobs.OutboxActionConsentPrompt] != safetext.TextActionConsentPrompt ||
		outboxTemplates[jobs.OutboxActionConsentPromptRU] != safetext.TextActionConsentPromptRU {
		t.Fatal("an action-consent prompt kind sends another text")
	}
	// The two consents cannot be confused at the button: neither action
	// prefix starts the other, and each binds its own version and hash.
	if strings.HasPrefix(actionConsentAcceptPrefix, consentAcceptPrefix) || strings.HasPrefix(consentAcceptPrefix, actionConsentAcceptPrefix) {
		t.Fatal("one consent button prefix starts the other")
	}
	if isActionConsentAction(consentAcceptAction(false)) || isActionConsentAction(consentAcceptAction(true)) ||
		!isActionConsentAction(actionConsentAcceptAction(false)) || !isActionConsentAction(actionConsentAcceptAction(true)) {
		t.Fatal("the consent buttons are told apart wrongly")
	}
	for ru, sha := range map[bool]string{false: convo.ActionConsentTextSHA256For(false), true: convo.ActionConsentTextSHA256For(true)} {
		if got, want := actionConsentAcceptAction(ru), "actions_accept:"+convo.ActionConsentVersion+":"+sha; got != want {
			t.Fatalf("action %q, want %q", got, want)
		}
	}
}

// TestActionConsentOutboxKinds: a prompt carries the one consent button in
// its own language and cannot be sent without it; the accepted reply and
// the two once-per-connection notices carry none and have their fixed
// texts.
func TestActionConsentOutboxKinds(t *testing.T) {
	for kind, label := range map[jobs.OutboxKind]safetext.Template{
		jobs.OutboxActionConsentPrompt: safetext.LabelConsentAccept, jobs.OutboxActionConsentPromptRU: safetext.LabelConsentAcceptRU,
	} {
		if !kind.CarriesButton() || kind.ConnectionLevel() {
			t.Fatalf("%s is not a conversation-level prompt", kind)
		}
		if kb, ok := outboxKeyboard(jobs.OutboxItem{Kind: kind, Button: "id"}); !ok || len(kb) != 1 || len(kb[0]) != 1 || kb[0][0].Data != "id" || kb[0][0].Label != label {
			t.Fatalf("%s keyboard = %+v, %v", kind, kb, ok)
		}
		if _, ok := outboxKeyboard(jobs.OutboxItem{Kind: kind}); ok {
			t.Fatalf("%s without its button is sendable", kind)
		}
	}
	for kind, text := range map[jobs.OutboxKind]safetext.Template{
		jobs.OutboxActionConsentAccepted: safetext.TextActionConsentAccepted,
		jobs.OutboxActionConsentNeeded:   safetext.TextActionConsentNeeded,
		jobs.OutboxWriteScopeNeeded:      safetext.TextWriteScopeNeeded,
	} {
		if kind.CarriesButton() || outboxTemplates[kind] != text {
			t.Fatalf("%s: button %v, text %q", kind, kind.CarriesButton(), outboxTemplates[kind].String())
		}
		if kb, ok := outboxKeyboard(jobs.OutboxItem{Kind: kind}); !ok || kb != nil {
			t.Fatalf("%s keyboard = %+v, %v", kind, kb, ok)
		}
		if _, ok := outboxKeyboard(jobs.OutboxItem{Kind: kind, Button: "x"}); ok {
			t.Fatalf("%s with a button is sendable", kind)
		}
	}
	// The notices are per connection, so a principal gets each once per
	// connection; the replies are per update.
	for _, kind := range []jobs.OutboxKind{jobs.OutboxActionConsentNeeded, jobs.OutboxWriteScopeNeeded} {
		if !kind.ConnectionLevel() {
			t.Fatalf("%s is not connection-level", kind)
		}
	}
	if jobs.OutboxActionConsentAccepted.ConnectionLevel() {
		t.Fatal("the accepted reply is connection-level")
	}
	for why, want := range map[WithheldReason]jobs.OutboxKind{
		WithheldConsent: jobs.OutboxActionConsentNeeded, WithheldScope: jobs.OutboxWriteScopeNeeded,
	} {
		if got, ok := WithheldNotice(why); !ok || got != want {
			t.Fatalf("notice for %s = %s, %v", why, got, ok)
		}
	}
	for _, why := range []WithheldReason{WithheldNone, WithheldWritesOff, "other"} {
		if got, ok := WithheldNotice(why); ok || got != "" {
			t.Fatalf("notice for %q = %s", why, got)
		}
	}
	if _, err := NewActionGate(nil, func() (bool, error) { return true, nil }, nil); err == nil {
		t.Fatal("an action gate without a store")
	}
}

// TestActionConsent_E2E runs the consent to actions through the
// production reply path: with writes on, /consent after the data-flow
// consent sends the actions text with its button, in the client's
// language; the press records the text that was shown and is answered.
// With the switch not wired, off or unreadable, /consent sends the
// data-flow text as it always did.
func TestActionConsent_E2E(t *testing.T) {
	for _, tc := range []actionConsentCase{
		{"en", convo.ActionConsentText, safetext.LabelConsentAccept, convo.ActionConsentTextSHA256For(false)},
		{"ru", convo.ActionConsentTextRU, safetext.LabelConsentAcceptRU, convo.ActionConsentTextSHA256For(true)},
	} {
		// A store per language: update ids are deduplicated per store.
		t.Run(tc.lang, func(t *testing.T) {
			eachStore(t, func(t *testing.T, s *db.Store) { actionConsentE2E(t, s, tc) })
		})
	}
}

type actionConsentCase struct {
	lang, text string
	label      safetext.Template
	sha        string
}

func actionConsentE2E(t *testing.T, s *db.Store, tc actionConsentCase) {
	t.Helper()
	user := aliceID
	if tc.lang == "ru" {
		user = bobID
	}
	h := newOutboxRepliesHarness(t, s, nil)
	on, failing := false, false
	say := func(text string) sentMessage {
		t.Helper()
		from := map[string]any{"id": user, "is_bot": false, "first_name": "Alice", "language_code": tc.lang}
		if code := h.message(user, map[string]any{"text": text, "from": from}); code != http.StatusOK {
			t.Fatalf("%s: %d", text, code)
		}
		msgs := h.messagesTo(user)
		if len(msgs) == 0 {
			t.Fatalf("%s (%s): nothing sent", text, tc.lang)
		}
		return msgs[len(msgs)-1]
	}
	// The data-flow consent first, with the switch not wired.
	first := say("/consent")
	if len(first.kb) != 1 || first.text == tc.text {
		t.Fatalf("first prompt %+v", first)
	}
	if code := h.press(user, first.kb[0][0].Data); code != http.StatusOK {
		t.Fatalf("press: %d", code)
	}
	if m := say("/consent"); m.text != first.text {
		t.Fatalf("switch not wired: /consent sent %q", m.text)
	}
	h.conv.writes = func() (bool, error) {
		if failing {
			return true, errors.New("injected flag error")
		}
		return on, nil
	}
	if m := say("/consent"); m.text != first.text {
		t.Fatalf("writes off: /consent sent %q", m.text)
	}
	on, failing = true, true
	if m := say("/consent"); m.text != first.text {
		t.Fatalf("switch unreadable: /consent sent %q", m.text)
	}
	failing = false

	prompt := say("/consent")
	if prompt.text != tc.text || len(prompt.kb) != 1 || len(prompt.kb[0]) != 1 || prompt.kb[0][0].Label != tc.label || prompt.kb[0][0].Data == "" {
		t.Fatalf("action prompt %q with %+v", prompt.text, prompt.kb)
	}
	if code := h.press(user, prompt.kb[0][0].Data); code != http.StatusOK {
		t.Fatalf("press: %d", code)
	}
	msgs := h.messagesTo(user)
	// The harness presses without a client language, so the answer is in English.
	if got, want := msgs[len(msgs)-1].text, safetext.ServerText(safetext.TextActionConsentAccepted).String(); got != want {
		t.Fatalf("after the press: %q, want %q", got, want)
	}
	var version, sha, state string
	if err := s.DB.QueryRow(`SELECT version, text_sha256, state FROM pa_action_consents WHERE principal = $1`, user).Scan(&version, &sha, &state); err != nil {
		t.Fatal(err)
	}
	if version != convo.ActionConsentVersion || sha != tc.sha || state != string(convo.ConsentAccepted) {
		t.Fatalf("stored %s %s %s", version, sha, state)
	}
	// An ordinary message is admitted as before and shows no prompt.
	before := len(h.messagesTo(user))
	if code := h.message(user, map[string]any{"text": "hello"}); code != http.StatusOK {
		t.Fatal("message refused")
	}
	for _, m := range h.messagesTo(user)[before:] {
		if m.text == tc.text {
			t.Fatal("an ordinary message was answered with the consent to actions")
		}
	}
}
