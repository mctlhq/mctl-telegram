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
	for _, v := range []string{tool, args} {
		if v == "" || strings.ContainsRune(v, '\n') || normalise(v) != v {
			return Text{}, ErrCardUnshowable
		}
		// A value that already holds a defang mark would read the same as
		// the value whose link was defanged here ("a[.]b" and "a.b"): two
		// different calls behind one card. Refused, so that what a card
		// shows names one value.
		for _, mark := range []string{"[.]", "[:]", "[@]"} {
			if strings.Contains(v, mark) {
				return Text{}, ErrCardUnshowable
			}
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
