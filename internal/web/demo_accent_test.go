package web

import (
	"strings"
	"testing"
)

// demo.html styles its own numbered badges; their ink must follow the theme.
func TestDemoCSSUsesAccentFg(t *testing.T) {
	if strings.Contains(demoHTML, "#0a0b0d") {
		t.Error("demo.html hard-codes #0a0b0d; use var(--accent-fg)")
	}
}
