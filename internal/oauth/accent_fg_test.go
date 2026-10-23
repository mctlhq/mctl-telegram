package oauth

import (
	"strings"
	"testing"
)

// The OAuth-flow pages add their own button CSS; like the shared ui CSS it
// must take button ink from --accent-fg, which flips with the theme. A fixed
// dark ink fails AA on the light theme's accent.
func TestOAuthExtraCSSUsesAccentFg(t *testing.T) {
	for name, css := range map[string]string{"enableExtraCSS": enableExtraCSS, "demoExtraCSS": demoExtraCSS} {
		if strings.Contains(css, "#0a0b0d") {
			t.Errorf("%s hard-codes #0a0b0d; use var(--accent-fg)", name)
		}
	}
}
