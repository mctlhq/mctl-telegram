package telegram

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestRenderQR(t *testing.T) {
	url := "tg://login?token=dGVzdA"
	got := renderQR(url)

	if got == "" {
		t.Fatal("renderQR returned empty string")
	}
	lines := strings.Split(strings.TrimRight(got, "\n"), "\n")
	if len(lines) < 5 {
		t.Errorf("renderQR returned too few lines: %d", len(lines))
	}
	// All lines in a QR render must have the same rune count.
	// Each module is 2 runes wide (either "██" or "  "), so byte counts differ
	// between dark and light rows — compare rune counts instead.
	width := utf8.RuneCountInString(lines[0])
	for i, l := range lines {
		if utf8.RuneCountInString(l) != width {
			t.Errorf("line %d has %d runes, want %d", i, utf8.RuneCountInString(l), width)
		}
	}
	// Width must be even (each module = 2 rune-wide chars).
	if width%2 != 0 {
		t.Errorf("renderQR width %d runes is not even", width)
	}
	// Result contains at least one dark module marker.
	if !strings.Contains(got, "\xe2\x96\x88\xe2\x96\x88") { // "██" UTF-8
		t.Error("renderQR output contains no dark modules")
	}
}

func TestRenderQR_ErrorFallback(t *testing.T) {
	// Empty URL is invalid for QR encoding but should not panic.
	got := renderQR("")
	if got == "" {
		t.Error("renderQR with empty URL returned empty string (expected fallback message)")
	}
}
