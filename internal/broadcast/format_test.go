package broadcast

import (
	"strings"
	"testing"
)

func TestParseFormat(t *testing.T) {
	for in, want := range map[string]Format{"": FormatPlain, "plain": FormatPlain, " HTML ": FormatHTML, "html": FormatHTML} {
		got, err := ParseFormat(in)
		if err != nil || got != want {
			t.Errorf("ParseFormat(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"markdown", "markdownv2", "text/html"} {
		if _, err := ParseFormat(in); err == nil {
			t.Errorf("ParseFormat(%q) accepted", in)
		}
	}
}

// Plain keeps the historical hash so campaigns prepared before formats
// existed still verify; html is bound to its format.
func TestContentHashFor_BindsFormat(t *testing.T) {
	const text = "Hello <b>there</b>"
	if got := ContentHashFor(FormatPlain, text); got != Hash(text) {
		t.Fatalf("plain hash changed: %s", got)
	}
	if ContentHashFor(FormatHTML, text) == ContentHashFor(FormatPlain, text) {
		t.Fatal("the same bytes must hash differently under html and plain")
	}
}

func TestParseHTML_Accepts(t *testing.T) {
	for name, in := range map[string]string{
		"bold and link": `<b>Update</b> read <a href="https://tg.mctl.ai/telegram/connect/manage">the manage page</a>.`,
		"entities":      `a &lt; b &amp;&amp; c &gt; d &quot;ok&quot;`,
		"pre code":      `<pre><code>go test ./...</code></pre>`,
		"nested":        `<b><i>both</i></b> <blockquote>quote</blockquote>`,
		"uppercase":     `<B>x</B>`,
		"unicode":       "Привет, мир 👋",
	} {
		if _, err := ParseHTML(in); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Everything Telegram would reject, or that could smuggle a link or markup
// the approver did not see, is refused at prepare time.
func TestParseHTML_Rejects(t *testing.T) {
	for name, in := range map[string]string{
		"script tag":                 `<script>alert(1)</script>`,
		"img tag":                    `<img src="https://x">`,
		"spoiler":                    `<tg-spoiler>x</tg-spoiler>`,
		"span":                       `<span class="tg-spoiler">x</span>`,
		"unclosed":                   `<b>open`,
		"mismatch":                   `<b><i>x</b></i>`,
		"stray close":                `x</b>`,
		"self closing":               `<b/>`,
		"bare lt":                    `1 < 2`,
		"bare gt":                    `2 > 1`,
		"bare amp":                   `fish & chips`,
		"numeric entity":             `&#60;`,
		"nbsp entity":                `&nbsp;`,
		"http link":                  `<a href="http://example.com">x</a>`,
		"javascript link":            `<a href="javascript:alert(1)">x</a>`,
		"tg link":                    `<a href="tg://user?id=1">x</a>`,
		"relative link":              `<a href="/docs">x</a>`,
		"credentials":                `<a href="https://user:pw@example.com/">x</a>`,
		"single quoted":              `<a href='https://example.com'>x</a>`,
		"no href":                    `<a>x</a>`,
		"html5 named entity in href": `<a href="https://example.com/a&quest;b">x</a>`,
		"numeric entity in href":     `<a href="https://example.com/&#47;x">x</a>`,
		"bare ampersand in href":     `<a href="https://example.com/?a=1&b=2">x</a>`,
		"space after open bracket":   `< b>x</b>`,
		"space after close bracket":  `<b>x</ b>`,
		"extra attribute":            `<a href="https://example.com" onclick="x">x</a>`,
		"attr on b":                  `<b class="x">x</b>`,
		"nested anchor":              `<a href="https://a.example"><a href="https://b.example">x</a></a>`,
		"tag in code":                `<pre><code><b>x</b></code></pre>`,
		"b in pre":                   `<pre><b>x</b></pre>`,
		"only tags":                  `<b></b>`,
		"space in href":              `<a href="https://example.com/a b">x</a>`,
		"encoded lt in url":          `<a href="https://example.com/&lt;">x</a>`,
	} {
		if _, err := ParseHTML(in); err == nil {
			t.Errorf("%s: %q was accepted", name, in)
		}
	}
}

func TestParseHTML_LimitsCountVisibleText(t *testing.T) {
	// Tags and entity markup do not count; the visible text does.
	ok := strings.Repeat("<b>x</b>", MaxHTMLTags/2) + strings.Repeat("y", MaxTextUnits-MaxHTMLTags/2)
	if _, err := ParseHTML(ok); err != nil {
		t.Fatalf("exactly at the visible limit must pass: %v", err)
	}
	if _, err := ParseHTML(ok + "z"); err == nil {
		t.Fatal("one visible unit over the limit must be refused")
	}
	if _, err := ParseHTML(strings.Repeat("<b>x</b>", MaxHTMLTags)); err == nil {
		t.Fatal("more than MaxHTMLTags tags must be refused")
	}
	// An emoji costs two UTF-16 units.
	if _, err := ParseHTML(strings.Repeat("👋", MaxTextUnits/2+1)); err == nil {
		t.Fatal("emoji must be counted as two units")
	}
}

func TestParseHTML_HrefAmpersandIsDecodedLikeText(t *testing.T) {
	d, err := ParseHTML(`<a href="https://example.com/?a=1&amp;b=2">x</a>`)
	if err != nil {
		t.Fatal(err)
	}
	if got := d.Links(); len(got) != 1 || got[0] != "https://example.com/?a=1&b=2" {
		t.Fatalf("links = %v", got)
	}
}

func TestHTMLDoc_LinksAndPreview(t *testing.T) {
	d, err := ParseHTML(`<b>Hi &amp; bye</b> <a href="https://example.com/?a=1&amp;b=2">go</a>`)
	if err != nil {
		t.Fatal(err)
	}
	if got := d.Links(); len(got) != 1 || got[0] != "https://example.com/?a=1&b=2" {
		t.Fatalf("links = %v", got)
	}
	if d.Visible != "Hi & bye go" {
		t.Fatalf("visible = %q", d.Visible)
	}
	p := d.Preview()
	for _, want := range []string{"<b>Hi &amp; bye</b>", `href="https://example.com/?a=1&amp;b=2"`, `rel="noopener noreferrer nofollow"`} {
		if !strings.Contains(p, want) {
			t.Errorf("preview %q lacks %q", p, want)
		}
	}
}

func TestNormalizeContent(t *testing.T) {
	got, err := NormalizeContent(FormatHTML, "\r\n <b>x</b>\r\n")
	if err != nil || got != "<b>x</b>" {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := NormalizeContent(FormatHTML, "   "); err == nil {
		t.Fatal("empty html accepted")
	}
	if _, err := NormalizeContent(FormatHTML, strings.Repeat("a", MaxHTMLRawBytes+1)); err == nil {
		t.Fatal("oversized html accepted")
	}
	// Plain text is untouched by html rules: a literal < is fine.
	if got, err := NormalizeContent(FormatPlain, "1 < 2"); err != nil || got != "1 < 2" {
		t.Fatalf("plain: %q, %v", got, err)
	}
}
