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
)

// ErrCardUnshowable is returned by Card for a tool name or arguments the
// card cannot show as they are: empty, spanning lines, or holding a
// character Render would remove or replace (a format or control
// character, or a space other than U+0020), or holding a defang mark
// ("[.]", "[:]", "[@]") of its own. A card that showed such a value would
// show something other than what is sent, so there is no card.
var ErrCardUnshowable = errors.New("pa output: card value cannot be shown exactly")

// CardTemplates lists every server text of an approval card, in the order
// Card places them. TextCardExternal is present only on a card whose
// conversation holds external content.
func CardTemplates() []Template {
	return []Template{TextCardHead, TextCardAction, TextCardArgs, TextCardExternal, TextCardFoot}
}

// DisclosureCardTemplates lists every server text a disclosure card can
// hold besides CardTemplates. TextCardHomeUnknown stands in for a home the
// service did not report, one of TextCardPhrase and TextCardCommand is
// present, and TextCardRoomWarning only on a text that is said aloud.
func DisclosureCardTemplates() []Template {
	return []Template{TextCardSpeaker, TextCardHome, TextCardHomeUnknown, TextCardRoom, TextCardDeviceName,
		TextCardDeviceID, TextCardPhrase, TextCardCommand, TextCardRoomWarning}
}

// Disclosure is what a disclosure card shows besides the tool and the
// arguments (threat model T6): the speaker the text goes to and the text.
type Disclosure struct {
	// Home, Room and Name are the speaker's, as the service listed them
	// when the card was made; ID is its device id, the one in the
	// arguments. An empty Home is shown as not reported, never left out.
	Home, Room, Name, ID string
	// Phrase is the whole text, exactly as it is sent.
	Phrase string
	// Spoken: the text is said aloud, so the card warns about the room.
	Spoken bool
}

// ContainsLink reports whether s holds a token a bot message would have
// to defang: a URL, a scheme-less domain, a t.me or tg:// link, a mention
// or an address (threat model T14). A card shows such a token changed, so
// a value that must be shown exactly is refused when this is true.
func ContainsLink(s string) bool {
	return neutralise(s, UserText{}) != s
}

// cardValue reports whether v can be shown on a card as it is.
func cardValue(v string) bool {
	if v == "" || strings.ContainsRune(v, '\n') || normalise(v) != v {
		return false
	}
	// A value that already holds a defang mark would read the same as
	// the value whose link was defanged here ("a[.]b" and "a.b"): two
	// different calls behind one card. Refused, so that what a card
	// shows names one value.
	for _, mark := range []string{"[.]", "[:]", "[@]"} {
		if strings.Contains(v, mark) {
			return false
		}
	}
	return true
}

// Card builds the text of an approval card (threat model T7, T14): the
// registry templates of CardTemplates around the tool name and the
// arguments of the call, in English and in Russian.
//
// tool and args are not server text. They are shown exactly as given, or
// not at all (ErrCardUnshowable): nothing is stripped, so the principal
// approves the bytes that are sent, with one visible exception. A link
// token in them is defanged like one in model text, with nothing allowed:
// the card is a message of the bot, and a value on it must not become a
// link Telegram follows or previews.
//
// external adds TextCardExternal: the conversation holds content that did
// not come from the principal (T5), so the values may come from it.
//
// The card is one message. A card that does not fit one is refused with
// ErrTooLong, never cut: its buttons belong to all of it.
func Card(tool, args string, external bool) (Text, error) {
	return card(tool, args, nil, external)
}

// DisclosureCard is Card for a disclosure (threat model T6, S2-D4): above
// the arguments it shows the speaker (home, room, name and device id) and
// the whole text on a line of its own, and, for a text that is said
// aloud, TextCardRoomWarning.
//
// Every value is shown exactly or the card is refused (ErrCardUnshowable),
// as in Card. The text and the device id are stricter: a card on which
// either would be defanged is refused too, so the line the principal
// reads is the text that is sent and the id it is sent to. The text is
// never cut: a card that does not fit one message is ErrTooLong.
func DisclosureCard(tool, args string, d Disclosure, external bool) (Text, error) {
	for _, v := range []string{d.Room, d.Name, d.ID, d.Phrase} {
		if !cardValue(v) {
			return Text{}, ErrCardUnshowable
		}
	}
	if d.Home != "" && !cardValue(d.Home) {
		return Text{}, ErrCardUnshowable
	}
	if strings.TrimSpace(d.Phrase) != d.Phrase || strings.TrimSpace(d.ID) != d.ID {
		return Text{}, ErrCardUnshowable
	}
	return card(tool, args, &d, external)
}

func card(tool, args string, d *Disclosure, external bool) (Text, error) {
	for _, v := range []string{tool, args} {
		if !cardValue(v) {
			return Text{}, ErrCardUnshowable
		}
	}
	build := func(l Lang) (string, error) {
		var b strings.Builder
		b.WriteString(TextCardHead.In(l))
		b.WriteString("\n\n")
		b.WriteString(TextCardAction.In(l))
		b.WriteString("\n")
		b.WriteString(tool)
		b.WriteString("\n\n")
		idLine := ""
		if d != nil {
			home := d.Home
			if home == "" {
				home = TextCardHomeUnknown.In(l)
			}
			idLine = TextCardDeviceID.In(l) + " " + d.ID
			b.WriteString(TextCardSpeaker.In(l))
			b.WriteString("\n" + TextCardHome.In(l) + " " + home)
			b.WriteString("\n" + TextCardRoom.In(l) + " " + d.Room)
			b.WriteString("\n" + TextCardDeviceName.In(l) + " " + d.Name)
			b.WriteString("\n" + idLine)
			b.WriteString("\n\n")
			if d.Spoken {
				b.WriteString(TextCardPhrase.In(l))
			} else {
				b.WriteString(TextCardCommand.In(l))
			}
			b.WriteString("\n")
			b.WriteString(d.Phrase)
			b.WriteString("\n\n")
			if d.Spoken {
				b.WriteString(TextCardRoomWarning.In(l))
				b.WriteString("\n\n")
			}
		}
		b.WriteString(TextCardArgs.In(l))
		b.WriteString("\n")
		b.WriteString(args)
		if external {
			b.WriteString("\n\n")
			b.WriteString(TextCardExternal.In(l))
		}
		b.WriteString("\n\n")
		b.WriteString(TextCardFoot.In(l))
		// Over the whole text, so that a value cannot join the server text
		// next to it into a token. The templates hold none of their own
		// (TestCard_ServerTextIsNotDefanged).
		s := neutralise(b.String(), UserText{})
		if d != nil {
			// The text and the device id are on the card exactly as they
			// are sent, each on a line of its own, or there is no card.
			lines := strings.Split(s, "\n")
			if !containsLine(lines, d.Phrase) || !containsLine(lines, idLine) {
				return "", ErrCardUnshowable
			}
		}
		if UTF16Len(s) > MaxPartUTF16 {
			return "", ErrTooLong
		}
		return s, nil
	}
	en, err := build(LangEN)
	if err != nil {
		return Text{}, err
	}
	ru, err := build(LangRU)
	if err != nil {
		return Text{}, err
	}
	return Text{parts: []string{en}, ru: []string{ru}}, nil
}

func containsLine(lines []string, want string) bool {
	for _, l := range lines {
		if l == want {
			return true
		}
	}
	return false
}
