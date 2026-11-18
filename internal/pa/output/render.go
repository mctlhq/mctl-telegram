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

// Package output is the only way the Personal Assistant bot sends anything
// to Telegram. It implements threat model T14, output exfiltration through
// the bot's own messages (docs/agent-runtime/personal-assistant-threat-model.md):
//
//   - Text is a value only this package can build: Render for model-authored
//     text, ServerText for server-authored templates. Sender accepts nothing
//     else, so model text cannot reach a send without going through Render.
//   - Render strips markup and neutralises every URL, scheme-less domain,
//     IP address, tg: link and bot mention unless that exact token appeared
//     in the principal's own text in this conversation.
//   - Sender sends plain text only (no parse_mode, no entities), with link
//     previews disabled on every message, and inline keyboards made only of
//     server-authored callback buttons. A URL, login, web app or inline
//     query button cannot be expressed.
//
// A static test (TestS1O1_SenderIsTheOnlyBotAPICallSite) keeps every Bot API
// send method and raw Bot API URL under internal/pa inside sender.go.
//
// The package is library code: nothing in the runtime constructs a Sender
// yet, and PA_ENABLED (default off) gates everything that will.
package output

import (
	"regexp"
	"strings"
	"unicode"
)

// Text is message text that is safe to send: either the output of Render or
// a server template. The zero value is empty and Sender refuses it.
type Text struct {
	s string
}

// String returns the text exactly as it will be sent.
func (t Text) String() string { return t.s }

// Template is server-authored message text: a constant written in the
// source, never model output. Convert only constants to it. The static test
// rejects a conversion of a non-literal value outside this package, because
// that is how model text would bypass Render.
type Template string

// ServerText wraps a server-authored template. It skips Render, since the
// server wrote it, but it is still sent through Sender with previews
// disabled and no parse mode.
func ServerText(t Template) Text {
	return Text{s: string(t)}
}

// UserText is the set of tokens the principal typed themselves in this
// conversation. Only text with user provenance (T5) belongs here: never
// tool output, forwarded content or model output.
type UserText struct {
	tokens map[string]struct{}
}

// AllowFromUserText collects the link and mention tokens of the given
// user-provenance texts. Render keeps a token only when it is exactly one of
// these: a user host is not enough, because a query string can be appended.
func AllowFromUserText(texts ...string) UserText {
	u := UserText{tokens: map[string]struct{}{}}
	for _, t := range texts {
		t = dropInvisible(t)
		for _, sp := range findCandidates(t) {
			u.tokens[t[sp.start:sp.end]] = struct{}{}
		}
	}
	return u
}

func (u UserText) allows(tok string) bool {
	_, ok := u.tokens[tok]
	return ok
}

// Render turns model-authored text into Text. It never fails: whatever it
// cannot prove safe is neutralised, not passed through.
//
//  1. Invisible format characters (Unicode Cf, which includes zero-width and
//     bidi controls) and control characters other than tab and newline are
//     removed, so they cannot split a link past the detector or reorder what
//     the principal sees.
//  2. Markup is stripped: HTML tags and comments, Markdown links and images
//     (rewritten to "label (target)"), and the paired emphasis, strike,
//     spoiler and code markers. Sender never sets parse_mode, so this is for
//     readability; the security property is step 3, which runs last on the
//     final text.
//  3. Every link token not exactly present in allow is defanged so no
//     Telegram client links it: each dot becomes "[.]", each colon "[:]" and
//     each @ "[@]". "https://a.example/x" becomes "https[:]//a[.]example/x".
func Render(model string, allow UserText) Text {
	s := dropInvisible(model)
	s = stripMarkup(s)
	return Text{s: neutralise(s, allow)}
}

// dropInvisible removes Unicode format characters and control characters
// other than \n and \t.
func dropInvisible(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return r
		}
		if unicode.Is(unicode.Cf, r) || unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}

var (
	// htmlComment and htmlTag match real tag shapes only, so "a < b" and
	// "<https://x>" are left for the link pass.
	htmlComment = regexp.MustCompile(`(?s)<!--.*?-->`)
	htmlTag     = regexp.MustCompile(`</?[A-Za-z][A-Za-z0-9-]*(?:\s[^<>]*)?/?>`)
	// mdLink matches [label](target) and ![alt](target).
	mdLink = regexp.MustCompile(`!?\[([^\[\]\n]*)\]\(\s*([^()\s]*(?:\([^()\s]*\)[^()\s]*)*)(?:\s+"[^"\n]*")?\s*\)`)
	// mdMarkers are the paired Markdown / MarkdownV2 markers: bold, underline,
	// strike, spoiler and code fences or spans. Single * and _ are left, as
	// they are common in plain text (2*3, snake_case).
	mdMarkers = regexp.MustCompile("\\*\\*|__|~~|\\|\\||`+")
)

func stripMarkup(s string) string {
	s = htmlComment.ReplaceAllString(s, "")
	s = htmlTag.ReplaceAllString(s, "")
	s = mdLink.ReplaceAllStringFunc(s, func(m string) string {
		sub := mdLink.FindStringSubmatch(m)
		label, target := strings.TrimSpace(sub[1]), strings.TrimSpace(sub[2])
		switch {
		case target == "":
			return label
		case label == "" || label == target:
			return target
		default:
			return label + " (" + target + ")"
		}
	})
	return mdMarkers.ReplaceAllString(s, "")
}

// dotClass is every character a client or IDNA treats as a label separator:
// the ASCII full stop, the ideographic full stop and the full-width and
// half-width full stops.
const dotClass = `[.\x{3002}\x{FF0E}\x{FF61}]`

var (
	// linkRE finds link tokens. Alternatives, in order:
	//   - any scheme URL (https:, tg:, ftp: ... with //);
	//   - the schemes that need no //: tg:, mailto:, tel:, sms:, intent:,
	//     javascript:, data:, file:;
	//   - a dotted IPv4 address with an optional port and path;
	//   - a dotted domain, scheme-less, with Unicode (IDN) or punycode labels
	//     and a letter or xn-- TLD, with an optional port and path. t.me and
	//     telegram.me links are domains like any other.
	// The token runs to the next space, quote or angle bracket; trailing
	// punctuation is trimmed afterwards.
	linkRE = regexp.MustCompile(`(?i)` +
		`[a-z][a-z0-9+.\-]*://` + tokenTail + `+` +
		`|\b(?:tg|mailto|tel|sms|intent|javascript|data|file):` + tokenTail + `+` +
		`|\b\d{1,3}(?:` + dotClass + `\d{1,3}){3}(?::\d+)?(?:[/?#]` + tokenTail + `*)?` +
		`|(?:` + label + dotClass + `)+(?:xn--[a-z0-9\-]{1,59}|\p{L}[\p{L}\p{M}]{1,62})(?::\d+)?(?:[/?#]` + tokenTail + `*)?`)

	// label is one domain label: letters, digits and marks, inner hyphens.
	label = `[\p{L}\p{N}\p{M}](?:[\p{L}\p{N}\p{M}\-]{0,61}[\p{L}\p{N}\p{M}])?`

	// tokenTail is one character of a link body.
	tokenTail = "[^\\s\\p{Z}<>\"'`]"

	// mentionRE finds @username mentions. Only mentions of bots (Telegram
	// requires a bot username to end in "bot") are neutralised: a bot
	// mention is a step towards a ?start= payload to another bot.
	mentionRE = regexp.MustCompile(`@[A-Za-z0-9_]{3,32}`)
)

type span struct{ start, end int }

// trailingPunct is trimmed from the end of a link token, as every client
// does: "see a.example." links a.example, not "a.example.".
const trailingPunct = ".,;:!?)]}'\"。，．｡"

// findCandidates returns the link and bot-mention tokens of s, in order and
// non-overlapping. A mention inside a link token ("x@evil.example") belongs
// to the link.
func findCandidates(s string) []span {
	var out []span
	for _, m := range linkRE.FindAllStringIndex(s, -1) {
		end := m[0] + len(strings.TrimRight(s[m[0]:m[1]], trailingPunct))
		if end > m[0] {
			out = append(out, span{m[0], end})
		}
	}
	var mentions []span
	for _, m := range mentionRE.FindAllStringIndex(s, -1) {
		if !strings.HasSuffix(strings.ToLower(s[m[0]:m[1]]), "bot") {
			continue
		}
		overlaps := false
		for _, l := range out {
			if m[0] < l.end && l.start < m[1] {
				overlaps = true
				break
			}
		}
		if !overlaps {
			mentions = append(mentions, span{m[0], m[1]})
		}
	}
	if len(mentions) == 0 {
		return out
	}
	merged := make([]span, 0, len(out)+len(mentions))
	i, j := 0, 0
	for i < len(out) || j < len(mentions) {
		if j == len(mentions) || (i < len(out) && out[i].start < mentions[j].start) {
			merged = append(merged, out[i])
			i++
		} else {
			merged = append(merged, mentions[j])
			j++
		}
	}
	return merged
}

var defang = strings.NewReplacer(
	".", "[.]", "。", "[.]", "．", "[.]", "｡", "[.]",
	":", "[:]",
	"@", "[@]",
)

func neutralise(s string, allow UserText) string {
	var b strings.Builder
	last := 0
	for _, sp := range findCandidates(s) {
		tok := s[sp.start:sp.end]
		b.WriteString(s[last:sp.start])
		if allow.allows(tok) {
			b.WriteString(tok)
		} else {
			b.WriteString(defang.Replace(tok))
		}
		last = sp.end
	}
	b.WriteString(s[last:])
	return b.String()
}
