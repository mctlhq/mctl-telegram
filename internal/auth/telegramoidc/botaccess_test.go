package telegramoidc

import (
	"strings"
	"testing"
)

func TestRequestedScopes(t *testing.T) {
	if got := len(requestedScopes(false)); got != 2 {
		t.Fatalf("flag off: %d scopes", got)
	}
	on := requestedScopes(true)
	if on[2] != ScopeBotAccess || len(on) != 3 {
		t.Fatalf("flag on: %v", on)
	}
}

func TestParseBotAccess(t *testing.T) {
	cases := []struct {
		name string
		raw  any
		req  bool
		want BotAccess
	}{
		{"not requested", "openid profile telegram:bot_access", false, BotAccessUnknown},
		{"nil", nil, true, BotAccessUnknown},
		{"non-string", 42, true, BotAccessUnknown},
		{"empty", "  ", true, BotAccessUnknown},
		{"granted", "openid profile telegram:bot_access", true, BotAccessGranted},
		// #930: Telegram omits the bot scope even when the user allowed
		// messages, so its absence is not a refusal.
		{"scope without bot access", "openid profile", true, BotAccessUnknown},
		{"order and spaces", "  telegram:bot_access   openid ", true, BotAccessGranted},
	}
	for _, tc := range cases {
		if got := parseBotAccess(tc.raw, tc.req); got != tc.want {
			t.Errorf("%s: got %q want %q", tc.name, got, tc.want)
		}
	}
}

func TestReportedScope(t *testing.T) {
	if got := reportedScope("openid profile"); got != "openid profile" {
		t.Errorf("string: %q", got)
	}
	if got := reportedScope(nil); got != "" {
		t.Errorf("nil: %q", got)
	}
	if got := reportedScope(42); got != "" {
		t.Errorf("non-string: %q", got)
	}
	long := strings.Repeat("x", maxReportedScopeLen+10)
	if got := reportedScope(long); len(got) != maxReportedScopeLen {
		t.Errorf("long: len %d", len(got))
	}
}
