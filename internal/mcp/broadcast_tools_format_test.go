package mcp

import (
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/broadcast"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

func TestFormatArg(t *testing.T) {
	for name, c := range map[string]struct {
		in   map[string]any
		want broadcast.Format
	}{
		"absent": {map[string]any{}, broadcast.FormatPlain},
		"null":   {map[string]any{"format": nil}, broadcast.FormatPlain},
		"plain":  {map[string]any{"format": "plain"}, broadcast.FormatPlain},
		"html":   {map[string]any{"format": "html"}, broadcast.FormatHTML},
		"cased":  {map[string]any{"format": "HTML"}, broadcast.FormatHTML},
	} {
		got, err := formatArg(c.in, "format")
		if err != nil || got != c.want {
			t.Errorf("%s: got %q, %v; want %q", name, got, err, c.want)
		}
	}
	// A present but unusable value is an error, never a quiet plain: the
	// operator asked for something else and would approve the wrong thing.
	for name, in := range map[string]map[string]any{
		"number":   {"format": float64(1)},
		"bool":     {"format": true},
		"list":     {"format": []any{"html"}},
		"markdown": {"format": "markdown"},
		"empty":    {"format": "  x "},
	} {
		if got, err := formatArg(in, "format"); err == nil {
			t.Errorf("%s: accepted as %q", name, got)
		}
	}
}

func TestSummarize_ReportsFormatAndDefaultsOldRowsToPlain(t *testing.T) {
	if got := summarize(db.BroadcastCampaign{ContentFormat: "html"}).Format; got != "html" {
		t.Fatalf("html: %q", got)
	}
	if got := summarize(db.BroadcastCampaign{}).Format; got != "plain" {
		t.Fatalf("legacy row: %q", got)
	}
}
