package digest

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/broadcast"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

// A digest carries values a stranger controls: a Telegram username, a display
// name, an acquisition label, a revoke reason. Each must reach the body
// escaped, and the finished body must be one the broadcast parser accepts.
func TestBuildDigestHTML_EscapesHostileValuesAndValidates(t *testing.T) {
	rows := []db.IdentityRow{
		{TelegramID: 1001, Username: `<b>x</b>&"y"`, AccessTier: "client", HasSession: true},
		{TelegramID: 1002, DisplayName: `Bob <script>`},
	}
	steps := map[int64]db.ConnectStep{1002: {RevokedReason: `a<i>&b`}}
	src := map[int64]string{1001: `<a href="https://evil.example">x</a>`}
	msg, err := buildDigestHTML(day, rows, 2, false, steps, src)
	if err != nil {
		t.Fatalf("buildDigestHTML: %v", err)
	}
	if _, err := broadcast.NormalizeContent(broadcast.FormatHTML, msg); err != nil {
		t.Fatalf("digest body is not valid broadcast HTML: %v\n%s", err, msg)
	}
	doc, err := broadcast.ParseHTML(msg)
	if err != nil {
		t.Fatal(err)
	}
	if got := doc.Links(); len(got) != 0 {
		t.Fatalf("a hostile value produced a link: %v", got)
	}
	for _, want := range []string{"&lt;b&gt;x&lt;/b&gt;&amp;&quot;y&quot;", "Bob &lt;script&gt;", "a&lt;i&gt;&amp;b", "<code>1001</code>", "<code>1002</code>"} {
		if !strings.Contains(msg, want) {
			t.Errorf("body missing %q:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "<script>") || strings.Contains(msg, "evil.example\">") {
		t.Fatalf("unescaped markup reached the body:\n%s", msg)
	}
	// What recipients read is the original text, entities decoded.
	if !strings.Contains(doc.Visible, `<b>x</b>&"y"`) {
		t.Fatalf("visible text lost the username: %q", doc.Visible)
	}
}

func TestBuildDigestHTML_EmptyIsEmpty(t *testing.T) {
	msg, err := buildDigestHTML(day, nil, 0, false, nil, nil)
	if err != nil || msg != "" {
		t.Fatalf("got %q, %v", msg, err)
	}
}

// Many new clients cannot fit one message. The rows that fit are listed and
// the rest are counted; the result still validates.
func TestBuildDigestHTML_TruncatesInsteadOfFailing(t *testing.T) {
	var rows []db.IdentityRow
	for i := 0; i < 150; i++ {
		rows = append(rows, db.IdentityRow{TelegramID: int64(2000 + i), Username: fmt.Sprintf("user_%d", i)})
	}
	msg, err := buildDigestHTML(day, rows, 150, false, nil, nil)
	if err != nil {
		t.Fatalf("buildDigestHTML: %v", err)
	}
	if _, err := broadcast.NormalizeContent(broadcast.FormatHTML, msg); err != nil {
		t.Fatalf("truncated body does not validate: %v", err)
	}
	if !strings.Contains(msg, "…and ") || !strings.Contains(msg, " more") {
		t.Fatalf("truncation not announced:\n%s", msg)
	}
	if strings.Contains(msg, "user_149") {
		t.Fatal("the last row cannot fit, yet it was listed")
	}
	if !strings.Contains(msg, "user_0") {
		t.Fatal("the first row must always be listed")
	}
}

// The plain digest path is unchanged and its tests stay as they were; this
// pins that the HTML and plain bodies describe the same people.
func TestBuildDigestHTML_SameFactsAsPlain(t *testing.T) {
	rows := []db.IdentityRow{{TelegramID: 111, Username: "alice", AccessTier: "client", HasSession: true}}
	html, err := buildDigestHTML(day, rows, 5, false, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := broadcast.ParseHTML(html)
	if err != nil {
		t.Fatal(err)
	}
	plain := buildDigestMessage(day, rows, 5, false, nil, nil)
	if strings.TrimSpace(doc.Visible) != strings.TrimSpace(plain) {
		t.Fatalf("visible html text differs from plain:\nhtml:  %q\nplain: %q", doc.Visible, plain)
	}
}

// runDigest with FormatHTML must send parse_mode=HTML and the validated body.
func TestRunDigest_HTMLSendsParseModeHTML(t *testing.T) {
	ctx := context.Background()
	store := newDigestTestStore(t)
	if _, err := store.EnsureUserByTelegramID(ctx, 700100301, "hostile<i>", "Hostile"); err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	rt := &capturingRoundTripper{}
	withStubTransport(t, rt)
	runDigest(ctx, store, "test-token", []int64{999}, false, broadcast.FormatHTML, day)
	if len(rt.bodies) != 1 {
		t.Fatalf("want one send, got %d", len(rt.bodies))
	}
	form, err := url.ParseQuery(rt.bodies[0])
	if err != nil {
		t.Fatal(err)
	}
	if form.Get("parse_mode") != "HTML" {
		t.Fatalf("parse_mode = %q", form.Get("parse_mode"))
	}
	if form.Get("link_preview_options") != `{"is_disabled":true}` {
		t.Fatalf("link_preview_options = %q", form.Get("link_preview_options"))
	}
	text := form.Get("text")
	if !strings.Contains(text, "hostile&lt;i&gt;") || strings.Contains(text, "hostile<i>") {
		t.Fatalf("username not escaped in the sent body:\n%s", text)
	}
	if _, err := broadcast.NormalizeContent(broadcast.FormatHTML, text); err != nil {
		t.Fatalf("sent body does not validate: %v", err)
	}
}

// FormatPlain keeps the old wire format: no parse mode at all.
func TestRunDigest_PlainSendsNoParseMode(t *testing.T) {
	ctx := context.Background()
	store := newDigestTestStore(t)
	if _, err := store.EnsureUserByTelegramID(ctx, 700100302, "plain_tg", "Plain"); err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	rt := &capturingRoundTripper{}
	withStubTransport(t, rt)
	runDigest(ctx, store, "test-token", []int64{999}, false, broadcast.FormatPlain, day)
	if len(rt.bodies) != 1 {
		t.Fatalf("want one send, got %d", len(rt.bodies))
	}
	form, _ := url.ParseQuery(rt.bodies[0])
	if form.Get("parse_mode") != "" {
		t.Fatalf("plain digest must not set parse_mode, got %q", form.Get("parse_mode"))
	}
}
