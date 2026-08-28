package executor

import "testing"

// The agent is shown its own past replies as conversation history, so once a
// few carry the disclosure the model starts writing it into the draft itself.
// Appending unconditionally then sent the line twice to the recipient —
// observed live on 2026-08-27, message 94 of the preview soak.
func TestAppendDisclosure_NotDuplicatedWhenDraftAlreadyEndsWithIt(t *testing.T) {
	const d = "— ИИ-ассистент"
	for _, tc := range []struct {
		name    string
		payload string
		want    string
	}{
		{
			name:    "model reproduced the disclosure",
			payload: "Подскажите пару слотов.\n— ИИ-ассистент",
			want:    "Подскажите пару слотов.\n— ИИ-ассистент",
		},
		{
			name:    "reproduced with trailing whitespace",
			payload: "Подскажите пару слотов.\n— ИИ-ассистент\n  ",
			want:    "Подскажите пару слотов.\n— ИИ-ассистент\n  ",
		},
		{
			name:    "plain draft still gets it",
			payload: "Подскажите пару слотов.",
			want:    "Подскажите пару слотов.\n— ИИ-ассистент",
		},
		{
			// Mentioning it mid-text is not a disclosure at the end, which is
			// where a reader looks for one.
			name:    "mentioned mid-text still gets it appended",
			payload: "Внизу будет — ИИ-ассистент, не пугайтесь. Подскажите слоты.",
			want:    "Внизу будет — ИИ-ассистент, не пугайтесь. Подскажите слоты.\n— ИИ-ассистент",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := appendDisclosure(tc.payload, d); got != tc.want {
				t.Fatalf("appendDisclosure() =\n%q\nwant\n%q", got, tc.want)
			}
		})
	}
}

func TestAppendDisclosure_EmptyDisclosureLeavesPayloadAlone(t *testing.T) {
	if got := appendDisclosure("текст", ""); got != "текст" {
		t.Fatalf("got %q", got)
	}
}

// Codex P1 on #430: a disclosure can be an ordinary phrase, and a draft that
// happens to end with those words — negated, even — must still get the real
// line. Matching the bare text would have stripped the positive disclosure the
// executor exists to guarantee.
func TestAppendDisclosure_RequiresItsOwnLine(t *testing.T) {
	const d = "I'm an AI assistant."
	payload := "It is false that I'm an AI assistant."
	want := payload + "\n" + d
	if got := appendDisclosure(payload, d); got != want {
		t.Fatalf("a sentence merely ending in the disclosure words must still be disclosed:\ngot  %q\nwant %q", got, want)
	}
	// The same words on their own line are a real disclosure and must not double.
	onOwnLine := "Sure, happy to talk.\n" + d
	if got := appendDisclosure(onOwnLine, d); got != onOwnLine {
		t.Fatalf("got %q, want unchanged", got)
	}
}

// Codex P2 on #430: localized model output can end in a non-breaking space,
// which an ASCII cutset leaves in place — the suffix check would then miss and
// duplicate the line, which is the very symptom this fix targets.
func TestAppendDisclosure_TrimsUnicodeWhitespace(t *testing.T) {
	const d = "— ИИ-ассистент"
	for _, tail := range []string{"\u00a0", "\u2009", "\u3000", " \u00a0\n"} {
		payload := "Подскажите пару слотов.\n" + d + tail
		if got := appendDisclosure(payload, d); got != payload {
			t.Fatalf("tail %q: disclosure duplicated:\ngot %q", tail, got)
		}
	}
}

// Claude P3 on #430: TrimSpace of a blank disclosure is "", and
// HasSuffix(x, "") is true for every payload — without the guard a
// whitespace-only disclosure would silently suppress the append everywhere.
func TestAppendDisclosure_BlankDisclosureLeavesPayloadAlone(t *testing.T) {
	for _, d := range []string{"", " ", "\t\n", "\u00a0"} {
		if got := appendDisclosure("текст", d); got != "текст" {
			t.Fatalf("disclosure %q: got %q, want the payload untouched", d, got)
		}
	}
}

// A message that is nothing but the disclosure must not be doubled either.
func TestAppendDisclosure_PayloadIsOnlyTheDisclosure(t *testing.T) {
	const d = "— ИИ-ассистент"
	if got := appendDisclosure(d, d); got != d {
		t.Fatalf("got %q, want unchanged", got)
	}
}
