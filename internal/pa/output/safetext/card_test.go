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
	"slices"
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
	for _, tp := range slices.Concat(CardTemplates(), DisclosureCardTemplates(), DeviceWriteCardTemplates()) {
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

func testDisclosure() Disclosure {
	return Disclosure{Home: "Alice home", Room: "Kitchen", Name: "Kitchen speaker", ID: "spk-kitchen-0001",
		Phrase: "Dinner is ready", Spoken: true}
}

const disclosureArgs = `{"device":"spk-kitchen-0001","phrase":"Dinner is ready"}`

// TestDisclosureCard_Layout is S2-D4 at the builder: the speaker, the
// whole text on its own line, and the room warning for spoken text only.
func TestDisclosureCard_Layout(t *testing.T) {
	c, err := DisclosureCard("alice_say_phrase (alice)", disclosureArgs, testDisclosure(), false)
	if err != nil {
		t.Fatal(err)
	}
	want := TextCardHead.String() + "\n\n" + TextCardAction.String() + "\nalice_say_phrase (alice)\n\n" +
		TextCardSpeaker.String() + "\nHome: Alice home\nRoom: Kitchen\nName: Kitchen speaker\nDevice id: spk-kitchen-0001\n\n" +
		TextCardPhrase.String() + "\nDinner is ready\n\n" + TextCardRoomWarning.String() + "\n\n" +
		TextCardArgs.String() + "\n" + disclosureArgs + "\n\n" + TextCardFoot.String()
	if got := c.String(); got != want {
		t.Fatalf("card:\n got %q\nwant %q", got, want)
	}
	ru := c.In(LangRU).String()
	for _, tp := range []Template{TextCardSpeaker, TextCardHome, TextCardRoom, TextCardDeviceName, TextCardDeviceID, TextCardPhrase, TextCardRoomWarning} {
		if !strings.Contains(ru, tp.In(LangRU)) || tp.In(LangRU) == tp.In(LangEN) {
			t.Errorf("Russian card lacks %q", tp.In(LangRU))
		}
	}
	if !strings.Contains(ru, "\nDinner is ready\n") || !strings.Contains(ru, " spk-kitchen-0001\n") {
		t.Fatalf("Russian card lacks the text or the id:\n%s", ru)
	}

	d := testDisclosure()
	d.Spoken, d.Home = false, ""
	c, err = DisclosureCard("alice_send_command (alice)", disclosureArgs, d, true)
	if err != nil {
		t.Fatal(err)
	}
	got := c.String()
	if strings.Contains(got, TextCardRoomWarning.String()) || strings.Contains(got, TextCardPhrase.String()) ||
		!strings.Contains(got, TextCardCommand.String()+"\nDinner is ready\n") {
		t.Fatalf("command card:\n%s", got)
	}
	if !strings.Contains(got, "\nHome: "+TextCardHomeUnknown.String()+"\n") || !strings.Contains(got, TextCardExternal.String()) {
		t.Fatalf("card without a home, with external content:\n%s", got)
	}
}

// TestDisclosureCard_RefusesWhatItCannotShow: the text and the device id
// are on the card exactly, or there is no card; nothing is cut.
func TestDisclosureCard_RefusesWhatItCannotShow(t *testing.T) {
	set := func(f func(*Disclosure)) Disclosure {
		d := testDisclosure()
		f(&d)
		return d
	}
	for name, d := range map[string]Disclosure{
		"no text":              set(func(d *Disclosure) { d.Phrase = "" }),
		"two lines of text":    set(func(d *Disclosure) { d.Phrase = "one\ntwo" }),
		"text with a link":     set(func(d *Disclosure) { d.Phrase = "open example.com" }),
		"text with a mention":  set(func(d *Disclosure) { d.Phrase = "ask @example_bot" }),
		"text ending in space": set(func(d *Disclosure) { d.Phrase = "Dinner " }),
		"text with a bidi":     set(func(d *Disclosure) { d.Phrase = "a‮b" }),
		"no id":                set(func(d *Disclosure) { d.ID = "" }),
		"an id that is a link": set(func(d *Disclosure) { d.ID = "spk.example.com" }),
		"no room":              set(func(d *Disclosure) { d.Room = "" }),
		"no name":              set(func(d *Disclosure) { d.Name = "" }),
		"a two-line name":      set(func(d *Disclosure) { d.Name = "Kitchen\nHome: Bob home" }),
		"a two-line home":      set(func(d *Disclosure) { d.Home = "Alice home\nRoom: Bedroom" }),
		"a defang mark":        set(func(d *Disclosure) { d.Room = "a[.]b" }),
	} {
		if _, err := DisclosureCard("alice_say_phrase (alice)", disclosureArgs, d, false); !errors.Is(err, ErrCardUnshowable) {
			t.Errorf("%s: err = %v, want ErrCardUnshowable", name, err)
		}
	}
	long := set(func(d *Disclosure) { d.Phrase = strings.Repeat("a", MaxPartUTF16) })
	if _, err := DisclosureCard("alice_say_phrase (alice)", disclosureArgs, long, false); !errors.Is(err, ErrTooLong) {
		t.Errorf("a text over one message: err = %v, want ErrTooLong", err)
	}
	// A link-like speaker name is shown defanged, as on any card; the text
	// and the id are not touched by it.
	named := set(func(d *Disclosure) { d.Name = "speaker.example.com" })
	c, err := DisclosureCard("alice_say_phrase (alice)", disclosureArgs, named, false)
	if err != nil || !strings.Contains(c.String(), "Name: speaker[.]example[.]com\n") {
		t.Fatalf("link-like name: %v\n%s", err, c.String())
	}
	if !ContainsLink("see example.com") || ContainsLink("Dinner at 19:30. Table for 2!") {
		t.Fatal("ContainsLink")
	}
}

const deviceWriteArgs = `{"brightness":40,"device":"lamp-desk-0003","state":"on"}`

func testDeviceWrite() DeviceWrite {
	return DeviceWrite{
		Light: true, Home: "Alice home", Room: "Study", Name: "Desk lamp", ID: "lamp-desk-0003",
		Values: []CardValue{{Kind: ValuePower, Value: "on"}, {Kind: ValueBrightness, Value: "40"}},
	}
}

// TestDeviceWriteCard_Layout: the device, then every value on a line of
// its own after its label, in both languages.
func TestDeviceWriteCard_Layout(t *testing.T) {
	c, err := DeviceWriteCard("alice_set_light (alice)", deviceWriteArgs, testDeviceWrite(), false)
	if err != nil {
		t.Fatal(err)
	}
	want := TextCardHead.String() + "\n\n" + TextCardAction.String() + "\nalice_set_light (alice)\n\n" +
		TextCardLight.String() + "\nHome: Alice home\nRoom: Study\nName: Desk lamp\nDevice id: lamp-desk-0003\n\n" +
		TextCardValues.String() + "\n" + TextCardPower.String() + " on\n" + TextCardBrightness.String() + " 40\n\n" +
		TextCardArgs.String() + "\n" + deviceWriteArgs + "\n\n" + TextCardFoot.String()
	if got := c.String(); got != want {
		t.Fatalf("card:\n got %q\nwant %q", got, want)
	}
	ru := c.In(LangRU).String()
	for _, line := range []string{TextCardLight.In(LangRU), TextCardValues.In(LangRU), TextCardPower.In(LangRU) + " on", TextCardBrightness.In(LangRU) + " 40"} {
		if !slices.Contains(strings.Split(ru, "\n"), line) {
			t.Errorf("no line of the Russian card is %q", line)
		}
	}
	for _, tp := range DeviceWriteCardTemplates() {
		if tp.In(LangRU) == tp.In(LangEN) {
			t.Errorf("template %q has no Russian text", tp.In(LangEN))
		}
	}

	// A speaker, no home, external content.
	w := DeviceWrite{Room: "Kitchen", Name: "Kitchen speaker", ID: "spk-kitchen-0001", Values: []CardValue{{Kind: ValueVolume, Value: "5"}}}
	c, err = DeviceWriteCard("alice_set_volume (alice)", `{"device":"spk-kitchen-0001","level":5}`, w, true)
	if err != nil {
		t.Fatal(err)
	}
	got := c.String()
	if !strings.Contains(got, TextCardSpeaker.String()+"\nHome: "+TextCardHomeUnknown.String()+"\n") ||
		!strings.Contains(got, "\n"+TextCardVolume.String()+" 5\n") || !strings.Contains(got, TextCardExternal.String()) ||
		strings.Contains(got, TextCardLight.String()) {
		t.Fatalf("speaker card:\n%s", got)
	}
	// Every kind has a label of its own, listed with the card's templates.
	seen := map[string]bool{}
	for k := ValuePlayback; k <= ValueScene; k++ {
		label, ok := k.label()
		if !ok || seen[label.String()] || !slices.Contains(DeviceWriteCardTemplates(), label) {
			t.Errorf("kind %d: label %q", k, label)
		}
		seen[label.String()] = true
	}
}

// TestDeviceWriteCard_RefusesWhatItCannotShow: the device id and every
// value are on the card exactly, or there is no card.
func TestDeviceWriteCard_RefusesWhatItCannotShow(t *testing.T) {
	set := func(f func(*DeviceWrite)) DeviceWrite {
		w := testDeviceWrite()
		w.Values = slices.Clone(w.Values)
		f(&w)
		return w
	}
	for name, w := range map[string]DeviceWrite{
		"no value":               set(func(w *DeviceWrite) { w.Values = nil }),
		"an empty value":         set(func(w *DeviceWrite) { w.Values[1].Value = "" }),
		"a two-line value":       set(func(w *DeviceWrite) { w.Values[1].Value = "40\n" + TextCardBrightness.String() + " 100" }),
		"a value with a space":   set(func(w *DeviceWrite) { w.Values[1].Value = "40 " }),
		"a value that is a link": set(func(w *DeviceWrite) { w.Values[0].Value = "example.com" }),
		"a value of no kind":     set(func(w *DeviceWrite) { w.Values[0].Kind = 0 }),
		"a kind out of range":    set(func(w *DeviceWrite) { w.Values[0].Kind = ValueScene + 1 }),
		"no id":                  set(func(w *DeviceWrite) { w.ID = "" }),
		"an id that is a link":   set(func(w *DeviceWrite) { w.ID = "lamp.example.com" }),
		"no room":                set(func(w *DeviceWrite) { w.Room = "" }),
		"no name":                set(func(w *DeviceWrite) { w.Name = "" }),
		"a two-line name":        set(func(w *DeviceWrite) { w.Name = "Desk lamp\n" + TextCardBrightness.String() + " 1" }),
		"a two-line home":        set(func(w *DeviceWrite) { w.Home = "Alice home\nRoom: Hall" }),
	} {
		if _, err := DeviceWriteCard("alice_set_light (alice)", deviceWriteArgs, w, false); !errors.Is(err, ErrCardUnshowable) {
			t.Errorf("%s: err = %v, want ErrCardUnshowable", name, err)
		}
	}
}
