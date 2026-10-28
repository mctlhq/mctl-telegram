package telegramoidc

import "testing"

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
		{"not granted", "openid profile", true, BotAccessNotGranted},
		{"order and spaces", "  telegram:bot_access   openid ", true, BotAccessGranted},
	}
	for _, tc := range cases {
		if got := parseBotAccess(tc.raw, tc.req); got != tc.want {
			t.Errorf("%s: got %q want %q", tc.name, got, tc.want)
		}
	}
}
