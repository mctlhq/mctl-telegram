package web

import (
	"strings"
	"testing"
)

func TestDescribeAudience(t *testing.T) {
	for name, c := range map[string]struct {
		in   string
		want []string
	}{
		"test accounts": {
			`{"category":"product_updates","tiers":["admin","client"],"only_telegram_ids":[1001,1002,1003]}`,
			[]string{"Product updates (opt-in) for admin and client.", "only these 3 Telegram ids: 1001, 1002, 1003"},
		},
		"clients unrestricted": {
			`{"category":"maintenance","tiers":["client"]}`,
			[]string{"Maintenance notices for clients.", "No further restriction"},
		},
		"admins only": {`{"category":"security","tiers":["admin"]}`, []string{"for admins."}},
		"filters": {
			`{"category":"product_updates","tiers":["client"],"connected_via":["chatgpt"],"active_within_days":7}`,
			[]string{"connected via chatgpt", "seen in the last 7 days"},
		},
	} {
		got, ok := describeAudience(c.in)
		if !ok {
			t.Errorf("%s: not ok", name)
			continue
		}
		for _, w := range c.want {
			if !strings.Contains(got, w) {
				t.Errorf("%s: %q does not contain %q", name, got, w)
			}
		}
	}
}

// An unreadable selector must say so; it must never read as "everyone".
func TestDescribeAudience_UnreadableIsNotEveryone(t *testing.T) {
	for _, in := range []string{"", "not json", "{}", `{"category":""}`, `[1]`} {
		if got, ok := describeAudience(in); ok || got != "" {
			t.Errorf("%q: got (%q, %v), want unreadable", in, got, ok)
		}
	}
}

func TestDescribeOutcome(t *testing.T) {
	for name, c := range map[string]struct{ in, want string }{
		"all clear": {`{"eligible":3,"skipped":{"no_account":0,"policy":0,"unreachable":0,"unsubscribed":0}}`, "3 accounts will receive it. None skipped."},
		"one":       {`{"eligible":1,"skipped":{}}`, "1 account will receive it. None skipped."},
		"nobody":    {`{"eligible":0,"skipped":{"unsubscribed":2}}`, "Nobody will receive it. Skipped: 2 (no consent for this category)."},
		"mixed": {`{"eligible":2,"skipped":{"policy":1,"unreachable":1}}`,
			"2 accounts will receive it. Skipped: 1 (tier not targeted), 1 (the bot cannot reach them)."},
		"unknown reason": {`{"eligible":2,"skipped":{"new_reason":4}}`, "2 accounts will receive it. Skipped: 4 (new_reason)."},
	} {
		got, ok := describeOutcome(c.in)
		if !ok || got != c.want {
			t.Errorf("%s: got (%q, %v), want %q", name, got, ok, c.want)
		}
	}
}

func TestDescribeOutcome_UnreadableIsNotZeroSkipped(t *testing.T) {
	for _, in := range []string{"", "not json", `{"eligible":"3"}`} {
		if got, ok := describeOutcome(in); ok {
			t.Errorf("%q: got %q, want unreadable", in, got)
		}
	}
}
