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
