// Copyright 2025 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package safetext

import (
	"errors"
	"strings"
	"testing"
)

const cardArgs = `{"text":"<b>1 & 2</b> **x**","to":"Carol"}`

// TestCard_ShowsTheValuesExactly: markup in the arguments is shown, not
// stripped, in both languages, between the server templates.
func TestCard_ShowsTheValuesExactly(t *testing.T) {
	c, err := Card("send_message", cardArgs, false)
	if err != nil {
		t.Fatal(err)
	}
	if c.Parts() != 1 {
		t.Fatalf("parts = %d, want 1", c.Parts())
	}
	for _, l := range []Lang{LangEN, LangRU} {
		got := c.In(l).String()
		want := TextCardHead.In(l) + "\n\n" + TextCardAction.In(l) + "\nsend_message\n\n" + TextCardArgs.In(l) + "\n" + cardArgs +
			"\n\n" + TextCardFoot.In(l)
		if got != want {
			t.Errorf("lang %d:\n got %q\nwant %q", l, got, want)
		}
	}
	if c.In(LangEN).String() == c.In(LangRU).String() {
		t.Error("the Russian card is the English one")
	}
}

// TestCard_ExternalFlag: the warning is on a card of a conversation with
// external content, and only there.
func TestCard_ExternalFlag(t *testing.T) {
	for _, external := range []bool{false, true} {
		c, err := Card("send_message", cardArgs, external)
		if err != nil {
			t.Fatal(err)
		}
		for _, l := range []Lang{LangEN, LangRU} {
			if got := strings.Contains(c.In(l).String(), TextCardExternal.In(l)); got != external {
				t.Errorf("external=%v lang %d: warning present = %v", external, l, got)
			}
		}
	}
}

// TestCard_LinksAreDefanged: a link in a value does not stay a link, and
// nothing else of the value changes.
func TestCard_LinksAreDefanged(t *testing.T) {
	const args = `{"text":"see https://evil.example/x?d=1 and bob@evil.example"}`
	c, err := Card("send_message", args, false)
	if err != nil {
		t.Fatal(err)
	}
	got := c.String()
	for _, live := range []string{"https://evil.example", "evil.example/x", "bob@evil.example"} {
		if strings.Contains(got, live) {
			t.Errorf("card holds the live token %q: %q", live, got)
		}
	}
	if len(findCandidates(got)) != 0 {
		t.Errorf("card still holds link candidates: %q", got)
	}
	// The marks are the only change, so the card still names one value.
	back := strings.NewReplacer("[.]", ".", "[:]", ":", "[@]", "@").Replace(got)
	if !strings.Contains(back, args) {
		t.Errorf("undoing the marks does not give the arguments back: %q", back)
	}
}

// TestCard_ServerTextIsNotDefanged: the templates hold no link token of
// their own, so the pass over the whole card leaves them as written.
func TestCard_ServerTextIsNotDefanged(t *testing.T) {
	for _, tp := range CardTemplates() {
		for _, l := range []Lang{LangEN, LangRU} {
			if s := tp.In(l); neutralise(s, UserText{}) != s || s == "" {
				t.Errorf("template %q changes under neutralise or is empty", s)
			}
		}
	}
}

// TestCard_RefusesWhatItCannotShow: a value the card would have to change
// to show gives no card.
func TestCard_RefusesWhatItCannotShow(t *testing.T) {
	bad := map[string]string{
		"empty":            "",
		"newline":          "{\"a\":\n1}",
		"zero width space": "{\"to\":\"Ca\u200brol\"}",
		"bidi override":    "{\"to\":\"\u202eloraC\"}",
		"no-break space":   "{\"to\":\"Carol\u00a0x\"}",
		"tab":              "{\"to\":\"Carol\tx\"}",
		"control":          "{\"to\":\"Carol\x07\"}",
		"defang mark":      `{"to":"carol[.]example"}`,
		"defang at":        `{"to":"carol[@]example"}`,
		"defang colon":     `{"to":"https[:]//x"}`,
	}
	for name, args := range bad {
		if _, err := Card("send_message", args, false); !errors.Is(err, ErrCardUnshowable) {
			t.Errorf("%s: err = %v, want ErrCardUnshowable", name, err)
		}
		if _, err := Card(args, cardArgs, false); !errors.Is(err, ErrCardUnshowable) {
			t.Errorf("%s as the tool: err = %v, want ErrCardUnshowable", name, err)
		}
	}
}

// TestCard_OneMessageOrNone: a card that does not fit one message is
// refused, never cut.
func TestCard_OneMessageOrNone(t *testing.T) {
	frame, err := Card("send_message", "{}", true)
	if err != nil {
		t.Fatal(err)
	}
	room := MaxPartUTF16 - max(UTF16Len(frame.In(LangEN).String()), UTF16Len(frame.In(LangRU).String()))
	fits := `{"t":"` + strings.Repeat("a", room-6) + `"}`
	c, err := Card("send_message", fits, true)
	if err != nil || c.Parts() != 1 {
		t.Fatalf("largest card: %v, parts %d", err, c.Parts())
	}
	if _, err := Card("send_message", fits[:len(fits)-2]+`a"}`, true); !errors.Is(err, ErrTooLong) {
		t.Fatalf("one over: err = %v, want ErrTooLong", err)
	}
}
