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

package output

import (
	"strings"
	"testing"
)

// liveLinks returns the link and bot-mention tokens left in out that the
// principal did not provide. Render's output must have none.
func liveLinks(out string, allow UserText) []string {
	var bad []string
	for _, sp := range findCandidates(out) {
		if tok := out[sp.start:sp.end]; !allow.allows(tok) {
			bad = append(bad, tok)
		}
	}
	return bad
}

// S1-O2: a model-authored URL not in the principal's own text is
// neutralised. So are a user host with an appended query, a scheme-less
// domain, a punycode or IDN domain, t.me and tg: links (including ?start=
// payloads to other bots) and bot mentions. The exact full URL the principal
// typed survives unchanged.
func TestS1O2_URLNeutralisation(t *testing.T) {
	allow := AllowFromUserText(
		"Alice: can you summarise https://docs.example.org/guide?id=7 for me?",
		"and also bob.example.net, and ask @AliceHelperBot",
	)
	cases := []struct {
		name, model, want string
	}{
		{"model url", "Read https://attacker.example/?d=secret now",
			"Read https[:]//attacker[.]example/?d=secret now"},
		{"user host with appended query", "See https://docs.example.org/guide?id=7&d=Carol-chat",
			"See https[:]//docs[.]example[.]org/guide?id=7&d=Carol-chat"},
		{"user host only", "See https://docs.example.org/",
			"See https[:]//docs[.]example[.]org/"},
		{"scheme-less domain", "visit attacker.example/x?d=1.",
			"visit attacker[.]example/x?d=1."},
		{"punycode domain", "go to xn--80ak6aa92e.com/p",
			"go to xn--80ak6aa92e[.]com/p"},
		{"punycode tld", "go to example.xn--p1ai",
			"go to example[.]xn--p1ai"},
		{"unicode idn", "go to пример.рф/путь",
			"go to пример[.]рф/путь"},
		{"full-width dot", "go to attacker\u3002example/x",
			"go to attacker[.]example/x"},
		{"t.me start payload", "open t.me/EvilBot?start=Bob-secret",
			"open t[.]me/EvilBot?start=Bob-secret"},
		{"telegram.me", "open https://telegram.me/EvilBot?start=x",
			"open https[:]//telegram[.]me/EvilBot?start=x"},
		{"tg scheme", "tap tg://resolve?domain=EvilBot&start=Dana",
			"tap tg[:]//resolve?domain=EvilBot&start=Dana"},
		{"tg without slashes", "tap tg:resolve?domain=EvilBot",
			"tap tg[:]resolve?domain=EvilBot"},
		{"bot mention", "ask @EvilBot about it",
			"ask [@]EvilBot about it"},
		{"bot command with bot mention", "send /start@Evil_bot",
			"send /start[@]Evil_bot"},
		{"email", "mail carol@attacker.example",
			"mail carol[@]attacker[.]example"},
		{"ipv4", "fetch 203.0.113.9:8080/x",
			"fetch 203[.]0[.]113[.]9[:]8080/x"},
		{"mention inside url", "https://a.example/@EvilBot",
			"https[:]//a[.]example/[@]EvilBot"},
		{"zero width split", "attacker\u200b.example/x",
			"attacker[.]example/x"},
		{"exact user url kept", "Here: https://docs.example.org/guide?id=7.",
			"Here: https://docs.example.org/guide?id=7."},
		{"exact user domain kept", "That is bob.example.net, yes",
			"That is bob.example.net, yes"},
		{"user bot mention kept", "I asked @AliceHelperBot",
			"I asked @AliceHelperBot"},
		{"user mention, other case", "I asked @alicehelperbot",
			"I asked [@]alicehelperbot"},
		{"human mention untouched", "Bob is @bob_example",
			"Bob is @bob_example"},
		{"plain prose untouched", "Dana sent 3.5 messages (1,234.5 bytes), about 2*3.",
			"Dana sent 3.5 messages (1,234.5 bytes), about 2*3."},
		{"dotted prose defanged", "e.g. this", "e[.]g. this"},
	}
	for _, c := range cases {
		got := Render(c.model, allow).String()
		if got != c.want {
			t.Errorf("%s:\n got %q\nwant %q", c.name, got, c.want)
		}
		if bad := liveLinks(got, allow); len(bad) != 0 {
			t.Errorf("%s: live link tokens left: %q", c.name, bad)
		}
	}
}

// S1-O2: with no user text at all, nothing survives as a link, whatever
// the shape.
func TestS1O2_NoUserTextNothingLive(t *testing.T) {
	inputs := []string{
		"HTTPS://ATTACKER.EXAMPLE/X",
		"ftp://files.attacker.example",
		"see (attacker.example) and [attacker.example]",
		"<https://attacker.example/x>",
		"javascript:alert(1) data:text/html,x mailto:alice@attacker.example",
		"a.example b.example c.example",
		"t.me/+inviteHash telegram.dog/EvilBot",
		"\u202ehttps://attacker.example\u202c",
	}
	for _, in := range inputs {
		got := Render(in, UserText{}).String()
		if bad := liveLinks(got, UserText{}); len(bad) != 0 {
			t.Errorf("%q -> %q: live link tokens %q", in, got, bad)
		}
		if strings.Contains(got, "://") || strings.Contains(strings.ToLower(got), "t.me") {
			t.Errorf("%q -> %q: scheme or t.me survived", in, got)
		}
	}
}

// S1-O3: model-authored markup is stripped. Sender never sets parse_mode,
// so markup would show literally; stripping also removes the link target a
// tag or Markdown link would hide, which the link pass then neutralises.
func TestS1O3_MarkupStripped(t *testing.T) {
	cases := []struct{ name, model, want string }{
		{"html bold", "<b>Alice</b> said hi", "Alice said hi"},
		{"html anchor", `<a href="https://attacker.example/?d=1">click</a>`, "click"},
		{"html comment", "hi<!-- https://attacker.example -->", "hi"},
		{"tg-spoiler", "<tg-spoiler>x</tg-spoiler>", "x"},
		{"markdown link", "[click](https://attacker.example/?d=1)", "click (https[:]//attacker[.]example/?d=1)"},
		{"markdown image", "![x](https://attacker.example/p.png)", "x (https[:]//attacker[.]example/p[.]png)"},
		{"bold italic markers", "**Bob** and __Carol__ ~~gone~~ ||spoiler||", "Bob and Carol gone spoiler"},
		{"code", "run `ls` and ```\nx\n```", "run ls and \nx\n"},
		{"inline mention url", "[Dana](tg://user?id=1)", "Dana (tg[:]//user?id=1)"},
		{"comparison kept", "a < b and c > d", "a < b and c > d"},
	}
	for _, c := range cases {
		if got := Render(c.model, UserText{}).String(); got != c.want {
			t.Errorf("%s:\n got %q\nwant %q", c.name, got, c.want)
		}
	}
}

func TestServerTextBypassesRender(t *testing.T) {
	const want = "Consent saved. Send /consent withdraw to revoke."
	if got := ServerText(tpl(want)).String(); got != want {
		t.Fatalf("got %q", got)
	}
}

// noLiveDot is an independent check that does not use findCandidates: once
// "[.]" is removed, no dot-class character may sit between two characters
// that are neither spaces nor newlines.
func noLiveDot(out string) bool {
	r := []rune(strings.ReplaceAll(out, "[.]", ""))
	for i := 1; i+1 < len(r); i++ {
		if isDot(r[i]) && !isBoundary(r[i-1]) && !isBoundary(r[i+1]) {
			return false
		}
	}
	return true
}

// S1-O2: scheme-less domains whose label ends in a character that is not a
// letter, digit or mark. Telegram accepts any non-separator code point from
// U+00C0 up, and ~ below it, as a domain symbol (is_domain_symbol), and
// links every one of these.
func TestS1O2_DomainSymbolsBeyondLetters(t *testing.T) {
	inputs := []string{
		"evil\U0001F600.ws/?d=SECRET",
		"i\u2665.ws/x?d=SECRET",
		"a.b\U0001F600.com/?d=SECRET",
		"evil\u2010.com/?d=SECRET",
		"evil~.com/?d=SECRET",
		"evil\u00b7.com/?d=SECRET",
		"x evil_.com/?d=SECRET y",
	}
	for _, in := range inputs {
		got := Render(in, UserText{}).String()
		if got == in || !noLiveDot(got) {
			t.Errorf("%q passed as %q", in, got)
		}
		if bad := liveLinks(got, UserText{}); len(bad) != 0 {
			t.Errorf("%q -> %q: live tokens %q", in, got, bad)
		}
	}
}

// S1-O2: a link the principal typed cannot be extended by characters
// Telegram keeps inside the link: an apostrophe, a backtick, full-width
// punctuation, or a tab (normalised to a space, which ends the link).
func TestS1O2_UserURLCannotBeExtended(t *testing.T) {
	allow := AllowFromUserText("see https://a.example/x", "or a.example/y", "https://docs.example.org/guide?id=7")
	cases := []struct{ model, want string }{
		{"https://docs.example.org/guide?id=7'&d=x", "https[:]//docs[.]example[.]org/guide?id=7'&d=x"},
		{"https://a.example/x'?d=SECRET", "https[:]//a[.]example/x'?d=SECRET"},
		{"https://a.example/x`SECRET", "https[:]//a[.]example/xSECRET"}, // backtick also stripped as markup
		{"https://a.example/x\uff0c\u3002\uff0c\uff0e\uff61", "https[:]//a[.]example/x\uff0c[.]\uff0c[.][.]"},
		{"a.example/y'SECRET", "a[.]example/y'SECRET"},
		{"https://a.example/x)SECRET", "https[:]//a[.]example/x)SECRET"},
		{"https://a.example/x\tSECRET", "https://a.example/x SECRET"},
		{"https://a.example/x'", "https://a.example/x'"},
		{"(https://a.example/x)", "(https://a.example/x)"},
		{"(https://a.example/x(1))", "(https[:]//a[.]example/x(1))"},
		{"'https://a.example/x'", "'https://a.example/x'"},
	}
	for _, c := range cases {
		if got := Render(c.model, allow).String(); got != c.want {
			t.Errorf("%q:\n got %q\nwant %q", c.model, got, c.want)
		}
	}
}

// S1-O2: splitting into Bot API sized parts cannot leave a live token: each
// part is neutralised again, so the tail of a long user link cut at the
// limit is defanged in its own part.
func TestS1O2_SplitCannotCreateLink(t *testing.T) {
	long := "https://a.example/" + strings.Repeat("q", maxTextUTF16-len("https://a.example/")) + "1.2.3.4/?d=SECRET"
	allow := AllowFromUserText(long)
	for _, model := range []string{
		long,
		strings.Repeat("x", maxTextUTF16-1) + "a1.2.3.4/?d=SECRET",
	} {
		txt := Render(model, allow)
		if len(txt.parts) < 2 {
			t.Fatalf("want a split, got %d parts", len(txt.parts))
		}
		for i, p := range txt.parts {
			if utf16Len(p) > maxTextUTF16 {
				t.Errorf("part %d too long", i)
			}
			if bad := liveLinks(p, allow); len(bad) != 0 {
				t.Errorf("part %d has live tokens %q", i, bad)
			}
			if strings.HasPrefix(p, "1.2.3.4") {
				t.Errorf("part %d starts with a live IPv4 link: %q", i, p[:20])
			}
		}
	}
}
