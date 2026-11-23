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

// Package safetext holds the only values the Personal Assistant bot may
// send: Text and Template. It implements the construction half of threat
// model T14, output exfiltration through the bot's own messages
// (docs/agent-runtime/personal-assistant-threat-model.md); package output
// sends them.
//
//   - Text is a value only this package can build: Render for model-authored
//     text, ServerText for server-authored templates from the registry in
//     templates.go. Both types have unexported fields, so the compiler
//     refuses a Text or Template built anywhere else, by literal,
//     conversion, alias or generic. output.Sender accepts nothing else, so
//     model text cannot reach a send without going through Render.
//   - Inside this package, TestTemplatesAreLiteralRegistry keeps every
//     Template a string literal in templates.go and every field access in
//     the few functions that build or read the values.
//   - Render strips markup and neutralises every token Telegram could turn
//     into a link (URL, scheme-less or IDN domain, IP address, e-mail, tg:
//     link, bot mention) unless that exact token appeared in the principal's
//     own text in this conversation.
//
// The package is a leaf: it imports nothing from internal/pa, and must not,
// so that it stays small enough to review as a whole.
package safetext

import (
	"errors"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Text is message text that is safe to send, already cut into Bot API sized
// parts: either the output of Render or a server template. The zero value is
// empty and Sender refuses it.
type Text struct {
	parts []string
}

// String returns the text exactly as it will be sent, parts joined.
func (t Text) String() string { return strings.Join(t.parts, "") }

// Parts returns how many messages the text is sent as.
func (t Text) Parts() int { return len(t.parts) }

// Part returns message i of the text, exactly as it will be sent.
func (t Text) Part(i int) string { return t.parts[i] }

// ServerText wraps a server-authored template. It skips Render, since the
// server wrote it, but it is still sent through Sender with previews
// disabled and no parse mode.
//
// A registry template longer than MaxParts messages is a programming error;
// Sender refuses the resulting Text.
func ServerText(t Template) Text {
	return Text{parts: split(t.s, MaxPartUTF16)}
}

// UserText is the set of tokens the principal typed themselves in this
// conversation. Only text with user provenance (T5) belongs here: never
// tool output, forwarded content or model output.
type UserText struct {
	tokens map[string]struct{}
}

// AllowFromUserText collects the link tokens of the given user-provenance
// texts. Render keeps a token only when it is exactly one of these: a user
// host is not enough, because a query string can be appended.
//
// The texts are normalised but not stripped of markup, so tokens are cut
// from what the principal literally typed. A link they wrote as Markdown,
// "[docs](https://a.example/x)", yields the token
// "docs](https://a.example/x)", which no rendered URL equals: the model's
// copy of that URL is defanged. That fails closed. Stripping first would
// let markup removal join characters into a token the principal never
// typed ("a.example/<b>x" becomes "a.example/x"), so it is not done.
func AllowFromUserText(texts ...string) UserText {
	u := UserText{tokens: map[string]struct{}{}}
	for _, t := range texts {
		t = normalise(t)
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

// Render turns model-authored text into Text. Whatever it cannot prove
// safe is neutralised, not passed through. Its only error is ErrTooLong,
// for text that needs more than MaxParts messages; the caller must handle
// it (outbox sends TextReplyTooLong instead).
//
//  1. normalise: Unicode format characters (Cf: zero-width, bidi) and
//     control characters other than newline are removed, and tabs and every
//     Unicode space or separator become an ASCII space. Telegram's linkifier
//     treats a tab as part of a URL, so this makes the token boundaries
//     below a subset of its own.
//  2. Markup is stripped: HTML tags and comments, Markdown links and images
//     (rewritten to "label (target)"), and the paired emphasis, strike,
//     spoiler and code markers, again until none is left (stripMarkup).
//     Sender never sets parse_mode, so this is for readability; the
//     security property is step 3, which runs last.
//  3. Every link token not exactly present in allow is defanged (see
//     findCandidates and neutralise).
//  4. The text is cut into Bot API sized parts and step 3 runs again on each
//     part, so a cut cannot leave a live piece of a token (fit).
//
// For text that fits one message, Render is idempotent: rendering its own
// output changes nothing (TestS1O2_RenderIsIdempotent, FuzzRender). Text
// cut into several messages is not promised to be: a second Render cuts
// the joined parts again, possibly elsewhere, though its output is just as
// neutralised.
//
// Text that would need more than MaxParts messages is refused with
// ErrTooLong, never truncated, so injected content cannot flood the
// principal's chat or push the bot into flood waits, and a cut can never
// fall inside a token.
func Render(model string, allow UserText) (Text, error) {
	// Each part holds at most MaxPartUTF16 units, so longer input cannot
	// fit; refusing it first also bounds the work below.
	if UTF16Len(model) > MaxParts*MaxPartUTF16 {
		return Text{}, ErrTooLong
	}
	parts, ok := fit(neutralise(stripMarkup(normalise(model)), allow), allow)
	if !ok {
		return Text{}, ErrTooLong
	}
	return Text{parts: parts}, nil
}

// MaxParts is the most messages one Render or ServerText may produce. Eight
// parts is about 32k characters, far above a normal assistant answer
// (PA_MAX_CONTEXT_TOKENS is 32k tokens for the whole context), and small
// enough that one reply cannot flood the chat.
const MaxParts = 8

// ErrTooLong is returned when text needs more than MaxParts messages.
var ErrTooLong = errors.New("pa output: text needs more than MaxParts messages")

// fit splits s into Bot API sized parts and neutralises each part again. A
// part that defanging pushed over the limit is split and neutralised once
// more; defang is idempotent, so this ends. It reports false, and stops,
// as soon as more than MaxParts parts would be needed.
func fit(s string, allow UserText) ([]string, bool) {
	var out []string
	var walk func(s string) bool
	walk = func(s string) bool {
		for _, p := range split(s, MaxPartUTF16) {
			p = neutralise(p, allow)
			if UTF16Len(p) > MaxPartUTF16 {
				if !walk(p) {
					return false
				}
				continue
			}
			if len(out) == MaxParts {
				return false
			}
			out = append(out, p)
		}
		return true
	}
	if !walk(s) {
		return nil, false
	}
	return out, true
}

// normalise removes format and control characters other than \n, and maps
// tabs and Unicode spaces and separators to ' '.
func normalise(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\n':
			return r
		case r == '\t' || unicode.In(r, unicode.Z):
			return ' '
		case unicode.Is(unicode.Cf, r) || unicode.IsControl(r):
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

// maxStripPasses bounds how often stripMarkup re-runs. Removing one piece
// of markup can join the text around it into another ("<**b>" becomes
// "<b>", "*`*" becomes "**"), so a single pass is not a fixpoint. Real text
// settles in one or two passes; text nested deeper than this is treated as
// hostile and handled by breakMarkup.
const maxStripPasses = 4

// stripMarkup strips markup until nothing more matches, so that its result
// holds no markup (and a second Render finds none). If maxStripPasses do
// not reach that point, breakMarkup removes what is left.
func stripMarkup(s string) string {
	for range maxStripPasses {
		next := stripOnce(s)
		if next == s {
			return s
		}
		s = next
	}
	if next := stripOnce(s); next != s {
		return breakMarkup(next)
	}
	return s
}

// breakMarkup makes s free of markup in one step, for text that is still
// changing after maxStripPasses: it drops every character that starts a
// tag or a paired marker (< * _ ~ | and the backtick), then puts a space
// in every "](" so no Markdown link remains. Deleting characters cannot
// create a "<" or a marker pair, and the "](" pass runs last, so the
// result is a fixpoint of stripOnce. It loses those characters, which only
// deliberately nested markup pays for.
func breakMarkup(s string) string {
	s = strings.Map(func(r rune) rune {
		if strings.ContainsRune("<*_~|`", r) {
			return -1
		}
		return r
	}, s)
	return strings.ReplaceAll(s, "](", "] (")
}

// defangLabels are the labels of the "[x]" forms defang writes. A defanged
// dot, colon or @ followed by "(" reads as a Markdown link ("[.](x)");
// rewriting it would undo the defang in a second Render, so it is left as
// it is. The link pass that runs after stripMarkup still neutralises x.
var defangLabels = map[string]bool{".": true, ":": true, "@": true}

func stripOnce(s string) string {
	s = htmlComment.ReplaceAllString(s, "")
	s = htmlTag.ReplaceAllString(s, "")
	s = mdLink.ReplaceAllStringFunc(s, func(m string) string {
		sub := mdLink.FindStringSubmatch(m)
		if defangLabels[sub[1]] {
			return m
		}
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

// Token detection mirrors the Telegram linkifier (tdlib
// td/telegram/MessageEntity.cpp: match_urls, match_tg_urls, fix_url,
// is_url_path_symbol), but from the outside in. Instead of re-implementing
// which domains Telegram accepts, the text is cut into runs at the
// characters Telegram never puts in a link; any link Telegram finds lies
// inside one run, because its domain, user-info, path and protocol symbols
// are all non-boundary characters. A run that could hold a link is a
// candidate, and a candidate is either exactly a user token or defanged as
// a whole. That fails closed: over-neutralisation (config.yaml becomes
// config[.]yaml) is accepted.

// isBoundary reports a character Telegram never includes in a link: ASCII
// space and newline, < > " « », and General Punctuation (U+2000-U+206F)
// except the joiners and the dashes U+2010-U+2015. normalise has already
// turned every other Unicode space into ' '.
func isBoundary(r rune) bool {
	switch r {
	case ' ', '\n', '<', '>', '"', '\u00ab', '\u00bb':
		return true
	}
	if r >= 0x2000 && r <= 0x206f {
		return !(r == 0x200c || r == 0x200d || (r >= 0x2010 && r <= 0x2015))
	}
	return unicode.In(r, unicode.Z)
}

// badEnd are the characters Telegram trims from the end of a link
// (bad_path_end_chars).
const badEnd = ".:;,('?!`"

// badStart are opening characters that are never the first character of a
// link: none of them is a domain, user-info or protocol symbol, so Telegram
// starts the link after them.
const badStart = "([{'`"

// trimEnd trims badEnd characters, and a closing bracket that has no
// opening bracket of its kind in the token (fix_url cuts the link at an
// unbalanced one), until neither applies.
func trimEnd(run string) string {
	for {
		t := strings.TrimRight(run, badEnd)
		for _, pair := range [...]string{"()", "[]", "{}"} {
			if strings.HasSuffix(t, pair[1:]) && !strings.Contains(t, pair[:1]) {
				t = t[:len(t)-1]
			}
		}
		if t == run {
			return t
		}
		run = t
	}
}

// isDot reports the ASCII full stop and the ideographic, full-width and
// half-width full stops, which IDNA and some clients treat as one.
func isDot(r rune) bool {
	return r == '.' || r == '\u3002' || r == '\uff0e' || r == '\uff61'
}

var (
	// schemeColon matches a scheme that needs no "//" after the colon.
	schemeColon = regexp.MustCompile(`(?i)(?:^|[^a-z0-9+.\-])(?:tg|ton|tonsite|mailto|tel|sms|intent|javascript|data|file|callto):`)
	// botMention matches @username where the username ends in "bot", which
	// Telegram requires of every bot. A bot mention is a step towards a
	// ?start= payload to another bot.
	botMention = regexp.MustCompile(`(?i)@[a-z0-9_]{0,29}bot(?:[^a-z0-9_]|$)`)
	// plainNumber is a decimal number such as 3.14 or 1,234.5: digits with
	// fewer than three dots. Telegram links a numeric host only as a
	// four-part IPv4 address (fix_url), so these are left as they are.
	// Brackets around it are not domain symbols, so "(3.5)" is kept too.
	plainNumber = regexp.MustCompile(`^[(\[]?[0-9,]*(?:\.[0-9,]*){0,2}[)\]]?$`)
)

type span struct{ start, end int }

// findCandidates returns the runs of s that could hold a link, trimmed of
// leading badStart and trailing badEnd characters and unbalanced closing
// brackets, in order. A run is a candidate when it holds a
// dot (other than in a plain number), "://", a scheme colon or a bot
// mention.
func findCandidates(s string) []span {
	var out []span
	start := -1
	flush := func(end int) {
		if start < 0 {
			return
		}
		lead := len(s[start:end]) - len(strings.TrimLeft(s[start:end], badStart))
		run := trimEnd(s[start+lead : end])
		if run != "" && isCandidate(s, start+lead, start+lead+len(run)) {
			out = append(out, span{start + lead, start + lead + len(run)})
		}
		start = -1
	}
	for i, r := range s {
		if isBoundary(r) {
			flush(i)
			continue
		}
		if start < 0 {
			start = i
		}
	}
	flush(len(s))
	return out
}

// isCandidate reports whether s[a:b] could hold a link. The defanged check
// looks at s, not at the trimmed run, so the "[" that trimming removed from
// "[.]x" still marks that dot as defanged.
func isCandidate(s string, a, b int) bool {
	run := s[a:b]
	if strings.Contains(run, "://") || schemeColon.MatchString(run) || botMention.MatchString(run) {
		return true
	}
	if !hasLiveDot(s, a, b) {
		return false
	}
	return !plainNumber.MatchString(run)
}

// defanged reports whether s[i] is the middle of "[x]", the form defang
// writes. Telegram links nothing across "[.]": neither bracket is a domain
// symbol, so the dot has no domain on either side.
func defanged(s string, i, size int) bool {
	return i > 0 && s[i-1] == '[' && i+size < len(s) && s[i+size] == ']'
}

// hasLiveDot reports a dot-class character in s[a:b] not already defanged.
func hasLiveDot(s string, a, b int) bool {
	for i, r := range s[a:b] {
		if isDot(r) && !defanged(s, a+i, utf8.RuneLen(r)) {
			return true
		}
	}
	return false
}

// defang rewrites a candidate so that no Telegram client links any part of
// it: every dot becomes "[.]", every colon "[:]" and every @ "[@]".
// "https://a.example/x" becomes "https[:]//a[.]example/x". It is idempotent:
// a character already written as "[x]" is left alone, so Render can
// neutralise again after splitting.
func defang(s string, sp span) string {
	var b strings.Builder
	for i, r := range s[sp.start:sp.end] {
		if (isDot(r) || r == ':' || r == '@') && !defanged(s, sp.start+i, utf8.RuneLen(r)) {
			if isDot(r) {
				b.WriteString("[.]")
			} else {
				b.WriteString("[" + string(r) + "]")
			}
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func neutralise(s string, allow UserText) string {
	var b strings.Builder
	last := 0
	for _, sp := range findCandidates(s) {
		tok := s[sp.start:sp.end]
		b.WriteString(s[last:sp.start])
		if allow.allows(tok) {
			b.WriteString(tok)
		} else {
			b.WriteString(defang(s, sp))
		}
		last = sp.end
	}
	b.WriteString(s[last:])
	return b.String()
}
