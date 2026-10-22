package toolprofile

import (
	"strings"
	"testing"
)

func TestParseBindings(t *testing.T) {
	for _, raw := range []string{"", "   ", "[]"} {
		got, err := ParseBindings(raw)
		if err != nil || !got.Empty() {
			t.Fatalf("ParseBindings(%q) = %v, %v; want empty, nil", raw, got, err)
		}
	}

	got, err := ParseBindings(`[{"client_id":"claude.ai","profile":"core-readonly"},` +
		`{"client_id":"https://platform.example.test/c.json","profile":"core-readonly"},` +
		`{"redirect_uri":"https://town.example.test/oauth/callback","profile":"core-reply"}]`)
	if err != nil {
		t.Fatalf("valid table: %v", err)
	}
	if len(got.ByClientID) != 2 || got.ByClientID["claude.ai"] != CoreReadonly || got.ByClientID["https://platform.example.test/c.json"] != CoreReadonly {
		t.Fatalf("valid table client_ids = %v", got.ByClientID)
	}
	if len(got.ByRedirectURI) != 1 || got.ByRedirectURI["https://town.example.test/oauth/callback"] != CoreReply {
		t.Fatalf("valid table redirect_uris = %v", got.ByRedirectURI)
	}

	for name, tc := range map[string]struct{ raw, want string }{
		"both keys":               {`[{"client_id":"claude.ai","redirect_uri":"https://claude.ai/cb","profile":"core-readonly"}]`, "names both client_id and redirect_uri"},
		"unknown key":             {`[{"client_id":"claude.ai","profile":"core-readonly","scope":"x"}]`, "unknown field"},
		"neither key":             {`[{"profile":"core-readonly"}]`, "client_id or redirect_uri is required"},
		"whitespace client_id":    {`[{"client_id":" claude.ai","profile":"core-readonly"}]`, "surrounding whitespace"},
		"unknown profile":         {`[{"client_id":"claude.ai","profile":"core-readnoly"}]`, `unknown profile "core-readnoly"`},
		"empty profile":           {`[{"client_id":"claude.ai"}]`, `unknown profile ""`},
		"duplicate client_id":     {`[{"client_id":"claude.ai","profile":"core-readonly"},{"client_id":"claude.ai","profile":"core-readonly"}]`, "duplicate client_id"},
		"trailing data":           {`[] []`, "trailing data"},
		"reserved client_id":      {`[{"client_id":"mctl_self_connect","profile":"core-readonly"}]`, `client_id "mctl_self_connect" cannot be bound`},
		"not an array":            {`{"client_id":"claude.ai","profile":"core-readonly"}`, "decode"},
		"whitespace redirect_uri": {`[{"redirect_uri":"https://town.example.test/cb ","profile":"core-readonly"}]`, "surrounding whitespace"},
		"relative redirect_uri":   {`[{"redirect_uri":"/oauth/callback","profile":"core-readonly"}]`, "not an absolute URL"},
		"fragment redirect_uri":   {`[{"redirect_uri":"https://town.example.test/cb#x","profile":"core-readonly"}]`, "not an absolute URL"},
		"redirect unknown prof":   {`[{"redirect_uri":"https://town.example.test/cb","profile":"core-readnoly"}]`, `unknown profile "core-readnoly"`},
		"duplicate redirect_uri":  {`[{"redirect_uri":"https://town.example.test/cb","profile":"core-readonly"},{"redirect_uri":"https://town.example.test/cb","profile":"core-reply"}]`, "duplicate redirect_uri"},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := ParseBindings(tc.raw)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ParseBindings = %v, %v; want error containing %q", got, err, tc.want)
			}
			if got != nil {
				t.Fatalf("a refused table must return no table, got %v", got)
			}
		})
	}
}

// TestBindingsResolve: a client_id binding wins over a redirect_uri one, a
// redirect_uri binds whatever client_id carries it, and an unknown (empty)
// redirect_uri matches no redirect_uri binding.
func TestBindingsResolve(t *testing.T) {
	b := Bindings{
		ByClientID:    map[string]string{"claude.ai": CoreReadonly},
		ByRedirectURI: map[string]string{"https://town.example.test/cb": CoreReply},
	}
	for _, tc := range []struct{ client, redirect, want string }{
		{"claude.ai", "", CoreReadonly},
		{"claude.ai", "https://town.example.test/cb", CoreReadonly},
		{"dcr-client-1", "https://town.example.test/cb", CoreReply},
		{"dcr-client-2", "https://town.example.test/cb", CoreReply},
		{"dcr-client-1", "https://town.example.test/cb/", ""},
		{"dcr-client-1", "", ""},
		{"other", "https://other.example.test/cb", ""},
	} {
		if got := b.Resolve(tc.client, tc.redirect); got != tc.want {
			t.Errorf("Resolve(%q, %q) = %q, want %q", tc.client, tc.redirect, got, tc.want)
		}
	}
	var zero Bindings
	if !zero.Empty() || zero.Resolve("claude.ai", "https://town.example.test/cb") != "" {
		t.Fatal("the zero table restricts a client")
	}
}

// TestCoreReadonly pins the accepted core-readonly surface and its rules.
func TestCoreReadonly(t *testing.T) {
	p, ok := Lookup(CoreReadonly)
	if !ok {
		t.Fatal("core-readonly is not defined")
	}
	want := map[string]Rule{
		"list_dialogs":        {},
		"get_messages":        {Forbidden: []string{"fetch_media"}, LimitDefault: 20, LimitMax: 50},
		"get_unread_messages": {Required: []string{"peer"}, Forbidden: []string{"fetch_media"}, LimitDefault: 20, LimitMax: 50},
		"search_messages":     {Required: []string{"peer"}, LimitDefault: 20, LimitMax: 50},
		"get_my_identity":     {},
		"get_my_send_status":  {},
		"get_my_audit_log":    {},
	}
	if len(p.Tools) != len(want) {
		t.Fatalf("core-readonly has %d tools, want %d: %v", len(p.Tools), len(want), p.Tools)
	}
	for name, w := range want {
		g, listed := p.Tools[name]
		if !listed {
			t.Fatalf("%s missing from core-readonly", name)
		}
		if strings.Join(g.Required, ",") != strings.Join(w.Required, ",") ||
			strings.Join(g.Forbidden, ",") != strings.Join(w.Forbidden, ",") ||
			g.LimitDefault != w.LimitDefault || g.LimitMax != w.LimitMax {
			t.Fatalf("%s rule = %+v, want %+v", name, g, w)
		}
	}
	if _, ok := Lookup("core-readnoly"); ok {
		t.Fatal("Lookup accepted an unknown profile name")
	}
}

// core-reply is core-readonly, rule for rule, plus the two reply tools and
// nothing else: no send_message, no pin (owner decision 2026-10-21: v2).
func TestCoreReply(t *testing.T) {
	ro, _ := Lookup(CoreReadonly)
	p, ok := Lookup(CoreReply)
	if !ok {
		t.Fatal("core-reply is not defined")
	}
	if len(p.Tools) != len(ro.Tools)+2 {
		t.Fatalf("core-reply has %d tools, want core-readonly's %d plus 2: %v", len(p.Tools), len(ro.Tools), p.Tools)
	}
	for name, w := range ro.Tools {
		g, listed := p.Tools[name]
		if !listed {
			t.Fatalf("%s is in core-readonly but not in core-reply", name)
		}
		if strings.Join(g.Required, ",") != strings.Join(w.Required, ",") ||
			strings.Join(g.Forbidden, ",") != strings.Join(w.Forbidden, ",") ||
			g.LimitDefault != w.LimitDefault || g.LimitMax != w.LimitMax {
			t.Fatalf("%s: core-reply rule %+v differs from core-readonly %+v", name, g, w)
		}
	}
	for _, name := range []string{"draft_reply", "send_reply"} {
		if _, listed := p.Tools[name]; !listed {
			t.Fatalf("%s missing from core-reply", name)
		}
		if _, listed := ro.Tools[name]; listed {
			t.Fatalf("%s is in core-readonly", name)
		}
	}
	if got, err := ParseBindings(`[{"client_id":"claude.ai","profile":"core-reply"}]`); err != nil || got.ByClientID["claude.ai"] != CoreReply {
		t.Fatalf("core-reply binding = %v, %v", got, err)
	}
}

// A profile-only tool that no profile lists would be registered and
// reachable by nobody: dead surface in the descriptor snapshot.
func TestProfileOnlyToolsAreListedByAProfile(t *testing.T) {
	for name := range profileOnlyTools {
		found := false
		for _, p := range profiles {
			if _, ok := p.Tools[name]; ok {
				found = true
			}
		}
		if !found {
			t.Errorf("profile-only tool %s is listed by no profile", name)
		}
	}
	if ProfileOnly("send_message") || !ProfileOnly("send_reply") || !ProfileOnly("draft_reply") {
		t.Fatal("ProfileOnly disagrees with the reply tools")
	}
}
