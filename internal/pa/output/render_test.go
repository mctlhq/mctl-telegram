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
			"mail carol@attacker[.]example"},
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
		{"plain prose untouched", "Dana sent 3 messages, e.g. about 2*3.",
			"Dana sent 3 messages, e.g. about 2*3."},
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
	const tpl Template = "Consent saved. Send /consent withdraw to revoke."
	if got := ServerText(tpl).String(); got != string(tpl) {
		t.Fatalf("got %q", got)
	}
}
