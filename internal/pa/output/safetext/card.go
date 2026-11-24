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
	"strconv"
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
// hold besides CardTemplates. TextCardHomeUnknown stands in for a home or a
// room the service did not report, one of TextCardPhrase and
// TextCardCommand is present, and TextCardRoomWarning only on a text that
// is said aloud.
func DisclosureCardTemplates() []Template {
	return []Template{TextCardSpeaker, TextCardHome, TextCardHomeUnknown, TextCardRoom, TextCardDeviceName,
		TextCardDeviceID, TextCardPhrase, TextCardCommand, TextCardRoomWarning}
}

// MusicCardTemplates lists every server text a music card holds besides
// CardTemplates.
func MusicCardTemplates() []Template {
	return []Template{TextCardSpeaker, TextCardHome, TextCardHomeUnknown, TextCardRoom, TextCardDeviceName,
		TextCardDeviceID, TextCardMusicQuery, TextCardMusicCommand}
}

// Music is what the card of a music request shows besides the tool and
// the arguments (alice_play_music): the speaker, the query, and the
// command the speaker receives for it.
type Music struct {
	// Home, Room, Name and ID are the speaker's, as in Disclosure. An
	// empty Home or Room is shown as not reported.
	Home, Room, Name, ID string
	// Query is the query, exactly as it is sent.
	Query string
	// Command is the whole text the speaker is handed: the service's fixed
	// words followed by Query.
	Command string
}

// Disclosure is what a disclosure card shows besides the tool and the
// arguments (threat model T6): the speaker the text goes to and the text.
type Disclosure struct {
	// Home, Room and Name are the speaker's, as the service listed them
	// when the card was made; ID is its device id, the one in the
	// arguments. An empty Home or Room is shown as not reported, never
	// left out.
	Home, Room, Name, ID string
	// Phrase is the whole text, exactly as it is sent.
	Phrase string
	// Spoken: the text is said aloud, so the card warns about the room.
	Spoken bool
	// query is set by MusicCard only: the card then shows the query and,
	// as Phrase, the command built from it.
	query string
}

// ScenarioCardTemplates lists every server text a scenario card holds
// besides CardTemplates.
func ScenarioCardTemplates() []Template {
	return []Template{TextCardScenario, TextCardDeviceName, TextCardScenarioID, TextCardScenarioSteps}
}

// Scenario is what a scenario card shows besides the tool and the
// arguments (threat model T6, S2-D6): the scenario and what it does.
type Scenario struct {
	// ID and Name are the scenario's, as the service gave them when the
	// card was made; ID is the one in the arguments.
	ID, Name string
	// Steps are every step of the scenario, in order.
	Steps []string
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
	return card(tool, args, nil, nil, external)
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
	d.query = ""
	return disclosureCard(tool, args, d, external)
}

func disclosureCard(tool, args string, d Disclosure, external bool) (Text, error) {
	for _, v := range []string{d.Name, d.ID, d.Phrase} {
		if !cardValue(v) {
			return Text{}, ErrCardUnshowable
		}
	}
	for _, v := range []string{d.Home, d.Room} {
		if v != "" && !cardValue(v) {
			return Text{}, ErrCardUnshowable
		}
	}
	if strings.TrimSpace(d.Phrase) != d.Phrase || strings.TrimSpace(d.ID) != d.ID {
		return Text{}, ErrCardUnshowable
	}
	return card(tool, args, &d, nil, external)
}

// MusicCard is Card for a music request (alice_play_music): above the
// arguments it shows the speaker, the query on a line of its own, and the
// command the speaker receives on another. The command must end with the
// query, after words of the service's that end in a space: a card whose
// two lines disagree is not built.
//
// The query, the command and the device id are shown exactly or the card
// is refused (ErrCardUnshowable), as the text of a DisclosureCard is.
func MusicCard(tool, args string, m Music, external bool) (Text, error) {
	prefix, ok := strings.CutSuffix(m.Command, m.Query)
	if !ok || !cardValue(m.Query) || strings.TrimSpace(m.Query) != m.Query ||
		len(prefix) < 2 || !strings.HasSuffix(prefix, " ") || strings.TrimSpace(prefix) != prefix[:len(prefix)-1] {
		return Text{}, ErrCardUnshowable
	}
	return disclosureCard(tool, args, Disclosure{
		Home: m.Home, Room: m.Room, Name: m.Name, ID: m.ID, Phrase: m.Command, query: m.Query,
	}, external)
}

// ScenarioCard is Card for a call that runs a scenario (S2-D6): above the
// arguments it shows the scenario's name and id and every one of its
// steps, numbered, one to a line. A card without steps is never built:
// no steps, or a step, name or id that cannot be shown as it is, is
// ErrCardUnshowable, and a card that does not fit one message is
// ErrTooLong. Steps are never left out or cut to make it fit.
func ScenarioCard(tool, args string, sc Scenario, external bool) (Text, error) {
	if len(sc.Steps) == 0 || !cardValue(sc.ID) || !cardValue(sc.Name) || strings.TrimSpace(sc.ID) != sc.ID {
		return Text{}, ErrCardUnshowable
	}
	for _, step := range sc.Steps {
		if !cardValue(step) || strings.TrimSpace(step) == "" {
			return Text{}, ErrCardUnshowable
		}
	}
	for _, v := range []string{tool, args} {
		if !cardValue(v) {
			return Text{}, ErrCardUnshowable
		}
	}
	build := func(l Lang) (string, error) {
		var b strings.Builder
		b.WriteString(TextCardHead.In(l) + "\n\n" + TextCardAction.In(l) + "\n" + tool + "\n\n")
		idLine := TextCardScenarioID.In(l) + " " + sc.ID
		b.WriteString(TextCardScenario.In(l))
		b.WriteString("\n" + TextCardDeviceName.In(l) + " " + sc.Name)
		b.WriteString("\n" + idLine + "\n\n")
		b.WriteString(TextCardScenarioSteps.In(l))
		for i, step := range sc.Steps {
			b.WriteString("\n" + strconv.Itoa(i+1) + ". " + step)
		}
		b.WriteString("\n\n" + TextCardArgs.In(l) + "\n" + args)
		if external {
			b.WriteString("\n\n" + TextCardExternal.In(l))
		}
		b.WriteString("\n\n" + TextCardFoot.In(l))
		// As in card: one pass over the whole text.
		s := neutralise(b.String(), UserText{})
		// The id is on the card exactly, and every step has its line.
		lines := strings.Split(s, "\n")
		if !containsLine(lines, idLine) {
			return "", ErrCardUnshowable
		}
		for i := range sc.Steps {
			if !hasLinePrefix(lines, strconv.Itoa(i+1)+". ") {
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

func hasLinePrefix(lines []string, prefix string) bool {
	for _, l := range lines {
		if strings.HasPrefix(l, prefix) && len(l) > len(prefix) {
			return true
		}
	}
	return false
}

func card(tool, args string, d *Disclosure, w *DeviceWrite, external bool) (Text, error) {
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
			home, room := d.Home, d.Room
			if home == "" {
				home = TextCardHomeUnknown.In(l)
			}
			if room == "" {
				room = TextCardHomeUnknown.In(l)
			}
			idLine = TextCardDeviceID.In(l) + " " + d.ID
			b.WriteString(TextCardSpeaker.In(l))
			b.WriteString("\n" + TextCardHome.In(l) + " " + home)
			b.WriteString("\n" + TextCardRoom.In(l) + " " + room)
			b.WriteString("\n" + TextCardDeviceName.In(l) + " " + d.Name)
			b.WriteString("\n" + idLine)
			b.WriteString("\n\n")
			switch {
			case d.query != "":
				b.WriteString(TextCardMusicQuery.In(l) + "\n" + d.query + "\n\n")
				b.WriteString(TextCardMusicCommand.In(l))
			case d.Spoken:
				b.WriteString(TextCardPhrase.In(l))
			default:
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
		var valueLines []string
		if w != nil {
			home, room, head := w.Home, w.Room, TextCardSpeaker
			if home == "" {
				home = TextCardHomeUnknown.In(l)
			}
			if room == "" {
				room = TextCardHomeUnknown.In(l)
			}
			if w.Light {
				head = TextCardLight
			}
			idLine = TextCardDeviceID.In(l) + " " + w.ID
			b.WriteString(head.In(l))
			b.WriteString("\n" + TextCardHome.In(l) + " " + home)
			b.WriteString("\n" + TextCardRoom.In(l) + " " + room)
			b.WriteString("\n" + TextCardDeviceName.In(l) + " " + w.Name)
			b.WriteString("\n" + idLine)
			b.WriteString("\n\n")
			b.WriteString(TextCardValues.In(l))
			for _, v := range w.Values {
				label, _ := v.Kind.label()
				line := label.In(l) + " " + v.Value
				valueLines = append(valueLines, line)
				b.WriteString("\n" + line)
			}
			b.WriteString("\n\n")
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
			if d.query != "" && !containsLine(lines, d.query) {
				return "", ErrCardUnshowable
			}
		}
		if w != nil {
			// The device id and every value are on the card exactly as
			// they are sent, each on a line of its own, or there is no
			// card.
			lines := strings.Split(s, "\n")
			for _, want := range append(valueLines, idLine) {
				if !containsLine(lines, want) {
					return "", ErrCardUnshowable
				}
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

// DeviceWriteCardTemplates lists every server text a device write card can
// hold besides CardTemplates: the device block (TextCardLight for a light,
// TextCardSpeaker for a speaker) and the label of each value.
func DeviceWriteCardTemplates() []Template {
	return []Template{TextCardSpeaker, TextCardLight, TextCardHome, TextCardHomeUnknown, TextCardRoom, TextCardDeviceName,
		TextCardDeviceID, TextCardValues, TextCardPlayback, TextCardVolume, TextCardPower, TextCardBrightness,
		TextCardColorTemp, TextCardScene}
}

// ValueKind names what a value of a device write sets. Each kind has one
// label in the registry, which says the unit and the range.
type ValueKind int

// The kinds of value a device write card can show.
const (
	ValuePlayback ValueKind = iota + 1
	ValueVolume
	ValuePower
	ValueBrightness
	ValueColorTemp
	ValueScene
)

// label returns the registry text written before a value of kind k.
func (k ValueKind) label() (Template, bool) {
	switch k {
	case ValuePlayback:
		return TextCardPlayback, true
	case ValueVolume:
		return TextCardVolume, true
	case ValuePower:
		return TextCardPower, true
	case ValueBrightness:
		return TextCardBrightness, true
	case ValueColorTemp:
		return TextCardColorTemp, true
	case ValueScene:
		return TextCardScene, true
	}
	return TextCardValues, false
}

// CardValue is one value a device write sends: Value is its text exactly
// as the arguments hold it, Kind says what it sets.
type CardValue struct {
	Kind  ValueKind
	Value string
}

// DeviceWrite is what the card of a device write shows besides the tool
// and the arguments (threat model T6): the device and the values.
type DeviceWrite struct {
	// Light: the device is a light; otherwise it is a speaker.
	Light bool
	// Home, Room and Name are the device's, as the service listed them
	// when the card was made; ID is its device id, the one in the
	// arguments. An empty Home or Room is shown as not reported, never
	// left out.
	Home, Room, Name, ID string
	// Values are every value the call sets, in the order they are shown.
	Values []CardValue
}

// DeviceWriteCard is Card for a write to one device (threat model T6):
// above the arguments it shows the device (home, room, name and device id)
// and every value on a line of its own after its label.
//
// Every value is shown exactly or the card is refused (ErrCardUnshowable),
// as in Card; the device id and the values are stricter, as the text of a
// DisclosureCard is: a card on which one of them would be defanged is
// refused. A write without a value has no card.
func DeviceWriteCard(tool, args string, w DeviceWrite, external bool) (Text, error) {
	if len(w.Values) == 0 {
		return Text{}, ErrCardUnshowable
	}
	exact := []string{w.ID}
	for _, v := range w.Values {
		if _, ok := v.Kind.label(); !ok {
			return Text{}, ErrCardUnshowable
		}
		exact = append(exact, v.Value)
	}
	for _, v := range exact {
		if !cardValue(v) || strings.TrimSpace(v) != v {
			return Text{}, ErrCardUnshowable
		}
	}
	if !cardValue(w.Name) {
		return Text{}, ErrCardUnshowable
	}
	for _, v := range []string{w.Home, w.Room} {
		if v != "" && !cardValue(v) {
			return Text{}, ErrCardUnshowable
		}
	}
	return card(tool, args, nil, &w, external)
}
