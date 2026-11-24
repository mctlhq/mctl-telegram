package safetext

import (
	"errors"
	"strings"
	"testing"
)

// A disallowed URL streamed one character at a time is never live in any
// prefix's draft.
func TestRenderPartial_DisallowedURLNeverLive(t *testing.T) {
	full := "see https://evil.example/p now"
	for _, tail := range []string{"", " "} {
		for i := 0; i <= len(full); i++ {
			txt, err := RenderPartial(full[:i]+tail, UserText{})
			if err != nil {
				t.Fatal(err)
			}
			if txt.Parts() > 0 && strings.Contains(txt.String(), "evil.example") && strings.Contains(txt.String(), "https://evil.example") {
				t.Fatalf("prefix %d: live URL in %q", i, txt.String())
			}
		}
	}
}

// A prefix equal to an allowed token is not shown while it may still grow.
func TestRenderPartial_PrefixOfAllowedTokenWithheld(t *testing.T) {
	allow := AllowFromUserText("https://a.example/x")
	full := "go to https://a.example/xevil ok"
	for i := 0; i < len(full); i++ {
		txt, err := RenderPartial(full[:i], allow)
		if err != nil {
			t.Fatal(err)
		}
		if i < len(full)-3 && strings.Contains(txt.String(), "https://a.example/x") && !strings.HasPrefix(full[:i], "go to https://a.example/x ") {
			if txt.Parts() > 0 {
				t.Fatalf("prefix %q shows the allowed token live: %q", full[:i], txt.String())
			}
		}
	}
	done, err := RenderPartial(full, allow)
	if err != nil || strings.Contains(done.String(), "https://a.example/xevil") {
		t.Fatalf("finished text not defanged: %q %v", done.String(), err)
	}
}

func TestRenderPartial_TooLong(t *testing.T) {
	_, err := RenderPartial(strings.Repeat("a ", MaxParts*MaxPartUTF16), UserText{})
	if !errors.Is(err, ErrTooLong) {
		t.Fatalf("err = %v", err)
	}
	txt, err := RenderPartial(strings.Repeat("a ", MaxPartUTF16/2+10), UserText{})
	if err == nil && txt.Parts() < 2 {
		t.Fatalf("parts = %d", txt.Parts())
	}
}
