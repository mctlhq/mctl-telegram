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

import "strings"

// Lang is a language the bot's own texts exist in. English is the zero
// value and the fallback for every text without a translation.
type Lang uint8

const (
	LangEN Lang = iota
	LangRU
)

// LangOf maps a Telegram language_code (IETF tag) to a Lang. Anything but
// Russian is English.
func LangOf(code string) Lang {
	code = strings.ToLower(strings.TrimSpace(code))
	if code == "ru" || strings.HasPrefix(code, "ru-") {
		return LangRU
	}
	return LangEN
}

// In returns the template in l, or in English when it has no translation.
func (t Template) In(l Lang) string {
	if l == LangRU && t.ru != "" {
		return t.ru
	}
	return t.s
}

// In returns the text in l: the Russian parts of a ServerText or
// WithRussian text when l is Russian and they exist, else the text itself.
// A translation cut into a different number of parts than the English is
// not used, so a resumed send (output.Sender.SendFrom) counts the same
// parts whichever language a retry picks.
func (t Text) In(l Lang) Text {
	if l == LangRU && len(t.ru) > 0 && len(t.ru) == len(t.parts) {
		return Text{parts: t.ru}
	}
	return Text{parts: t.parts}
}

// WithRussian joins two safe texts into one that Sender sends as en or ru
// by the principal's language. Both are already Render or ServerText
// output, so the result is no less safe than either.
func WithRussian(en, ru Text) Text {
	return Text{parts: en.parts, ru: ru.parts}
}
