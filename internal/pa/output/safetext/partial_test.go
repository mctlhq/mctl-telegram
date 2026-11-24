package safetext

import (
	"errors"
	"strings"
	"testing"
)

// prefixes returns every prefix of s that ends on a rune boundary, as a
// model that streams one character at a time would produce them.
func prefixes(s string) []string {
	var out []string
	for i := range s {
		out = append(out, s[:i])
	}
	return append(out, s)
}

// TestRenderPartial_DisallowedURLNeverLive: a URL the principal did not
// type, streamed one character at a time, is in no prefix's draft in a form
// a client would link: neither with its scheme nor as a bare domain. Once
// the token is finished the draft holds exactly what Render makes of it.
func TestRenderPartial_DisallowedURLNeverLive(t *testing.T) {
	for _, full := range []string{
		"see https://evil.example/p?d=1 now",
		"see evil.example/p now",
		"[docs](https://evil.example/p) now",
		"see t.me/evil_bot?start=x now",
	} {
		for _, p := range prefixes(full) {
			txt, err := RenderPartial(p, UserText{})
			if err != nil {
				t.Fatalf("%q: %v", p, err)
			}
			got := txt.String()
			for _, live := range []string{"://", "evil.example", "t.me/"} {
				if strings.Contains(got, live) {
					t.Fatalf("prefix %q: draft %q holds the live form %q", p, got, live)
				}
			}
			// A draft is always a Render output: rendering it again
			// changes nothing.
			again, err := Render(got, UserText{})
			if err != nil || again.String() != got {
				t.Fatalf("prefix %q: draft %q is not a Render output (%q, %v)", p, got, again.String(), err)
			}
		}
		want, err := Render(full+" ", UserText{})
		if err != nil {
			t.Fatal(err)
		}
		got, err := RenderPartial(full+" ", UserText{})
		if err != nil || got.String() != want.String() {
			t.Fatalf("finished %q: draft %q, want Render's %q (%v)", full, got.String(), want.String(), err)
		}
	}
}

// TestRenderPartial_PrefixOfAllowedTokenWithheld: the principal typed
// https://a.example/x and the model writes https://a.example/xevil. While
// the model is at "...a.example/x" the text so far equals the allowed
// token, and Render alone would show it live. No prefix's draft may hold
// it. The same token, when it really ends there, is shown.
func TestRenderPartial_PrefixOfAllowedTokenWithheld(t *testing.T) {
	const allowed = "https://a.example/x"
	allow := AllowFromUserText("open " + allowed)
	for _, p := range prefixes("go to " + allowed + "evil ok") {
		txt, err := RenderPartial(p, allow)
		if err != nil {
			t.Fatalf("%q: %v", p, err)
		}
		if strings.Contains(txt.String(), "://") {
			t.Fatalf("prefix %q: draft %q shows a live link", p, txt.String())
		}
	}
	// Control: the allowed token itself is live once a boundary ends it,
	// and not before.
	if txt, err := RenderPartial("go to "+allowed, allow); err != nil || strings.Contains(txt.String(), "a.example") {
		t.Fatalf("unfinished allowed token shown: %q %v", txt.String(), err)
	}
	if txt, err := RenderPartial("go to "+allowed+" ", allow); err != nil || txt.String() != "go to "+allowed+" " {
		t.Fatalf("finished allowed token: %q %v", txt.String(), err)
	}
}

// TestRenderPartial_WithholdsOnlyTheUnfinishedRun: the cut is at the last
// boundary of the normalised text, so a zero-width character cannot end a
// run early, and a text with no boundary renders empty.
func TestRenderPartial_WithholdsOnlyTheUnfinishedRun(t *testing.T) {
	for in, want := range map[string]string{
		"":                    "",
		"Hello":               "",
		"Hello wor":           "Hello ",
		"Hello world. ":       "Hello world. ",
		"Hello\nwor":          "Hello\n",
		"see evil.exa​mple":   "see ",
		"see evil.exa​mple x": "see evil[.]example ",
	} {
		txt, err := RenderPartial(in, UserText{})
		if err != nil || txt.String() != want {
			t.Errorf("%q: %q, %v; want %q", in, txt.String(), err, want)
		}
	}
}

// TestRenderPartial_OverLimit: a partial longer than one message is more
// than one part, and one longer than Render's limit is ErrTooLong. Neither
// is cut down to something that fits: the caller skips such a draft.
func TestRenderPartial_OverLimit(t *testing.T) {
	one, err := RenderPartial(strings.Repeat("a", MaxPartUTF16-1)+" ", UserText{})
	if err != nil || one.Parts() != 1 {
		t.Fatalf("a full part: parts %d, %v", one.Parts(), err)
	}
	two, err := RenderPartial(strings.Repeat("a", MaxPartUTF16)+" b ", UserText{})
	if err != nil || two.Parts() != 2 {
		t.Fatalf("over one part: parts %d, %v; want 2 parts", two.Parts(), err)
	}
	if _, err := RenderPartial(strings.Repeat("a ", MaxParts*MaxPartUTF16), UserText{}); !errors.Is(err, ErrTooLong) {
		t.Fatalf("over the limit: %v, want ErrTooLong", err)
	}
}
