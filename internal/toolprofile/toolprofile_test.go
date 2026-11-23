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

		// Scope ceilings (#1326).
		"empty ceiling":             {`[{"client_id":"pa.example","scope_ceiling":[]}]`, "scope_ceiling: is empty"},
		"null ceiling":              {`[{"client_id":"pa.example","scope_ceiling":null}]`, "scope_ceiling: is null"},
		"null ceiling with profile": {`[{"client_id":"pa.example","profile":"core-readonly","scope_ceiling":null}]`, "scope_ceiling: is null"},
		"ceiling not a list":        {`[{"client_id":"pa.example","scope_ceiling":"telegram:dialogs:read"}]`, "is not a list of scope strings"},
		"ceiling not strings":       {`[{"client_id":"pa.example","scope_ceiling":[1]}]`, "is not a list of scope strings"},
		// encoding/json would keep the last of a repeated key, and match
		// keys case-insensitively: each of these would silently drop the
		// ceiling or move it to another client.
		"repeated ceiling, null last":         {`[{"client_id":"pa.example","profile":"core-readonly","scope_ceiling":["telegram:dialogs:read"],"scope_ceiling":null}]`, `duplicate JSON key "scope_ceiling"`},
		"repeated ceiling, list last":         {`[{"client_id":"pa.example","scope_ceiling":["telegram:dialogs:read"],"scope_ceiling":["telegram:messages:read"]}]`, `duplicate JSON key "scope_ceiling"`},
		"repeated client_id key":              {`[{"client_id":"pa.example","scope_ceiling":["telegram:dialogs:read"],"client_id":"other.example"}]`, `duplicate JSON key "client_id"`},
		"repeated profile key":                {`[{"client_id":"pa.example","profile":"core-reply","profile":"core-readonly"}]`, `duplicate JSON key "profile"`},
		"ceiling key alias, null":             {`[{"client_id":"pa.example","profile":"core-readonly","scope_ceiling":["telegram:dialogs:read"],"SCOPE_CEILING":null}]`, "keys are matched exactly"},
		"client_id key alias":                 {`[{"client_id":"pa.example","scope_ceiling":["telegram:dialogs:read"],"Client_ID":"other.example"}]`, "keys are matched exactly"},
		"ceiling key alias alone":             {`[{"client_id":"pa.example","Scope_Ceiling":["telegram:dialogs:read"]}]`, "keys are matched exactly"},
		"ceiling blank entry":                 {`[{"client_id":"pa.example","scope_ceiling":["telegram:dialogs:read",""]}]`, `entry "" is not a single scope token`},
		"ceiling space-joined":                {`[{"client_id":"pa.example","scope_ceiling":["telegram:dialogs:read telegram:messages:read"]}]`, "is not a single scope token"},
		"ceiling padded entry":                {`[{"client_id":"pa.example","scope_ceiling":[" telegram:dialogs:read"]}]`, "is not a single scope token"},
		"ceiling duplicate entry":             {`[{"client_id":"pa.example","scope_ceiling":["telegram:dialogs:read","telegram:dialogs:read"]}]`, "duplicate scope"},
		"ceiling null on redirect_uri":        {`[{"redirect_uri":"https://pa.example.test/cb","scope_ceiling":null}]`, "is null"},
		"ceiling empty on redirect_uri":       {`[{"redirect_uri":"https://pa.example.test/cb","scope_ceiling":[]}]`, "is empty"},
		"ceiling redirect bad profile":        {`[{"redirect_uri":"https://pa.example.test/cb","profile":"core-readnoly","scope_ceiling":["telegram:dialogs:read"]}]`, `unknown profile "core-readnoly"`},
		"ceiling redirect duplicate":          {`[{"redirect_uri":"https://pa.example.test/cb","scope_ceiling":["telegram:dialogs:read"]},{"redirect_uri":"https://pa.example.test/cb","profile":"core-readonly"}]`, "duplicate redirect_uri"},
		"redirect without profile or ceiling": {`[{"redirect_uri":"https://pa.example.test/cb"}]`, "unknown profile"},
		"ceiling with bad profile":            {`[{"client_id":"pa.example","profile":"core-readnoly","scope_ceiling":["telegram:dialogs:read"]}]`, `unknown profile "core-readnoly"`},
		"ceiling duplicate client":            {`[{"client_id":"pa.example","scope_ceiling":["telegram:dialogs:read"]},{"client_id":"pa.example","profile":"core-readonly"}]`, "duplicate client_id"},
		"ceiling duplicate client2":           {`[{"client_id":"pa.example","profile":"core-readonly"},{"client_id":"pa.example","scope_ceiling":["telegram:dialogs:read"]}]`, "duplicate client_id"},
		"ceiling reserved client":             {`[{"client_id":"mctl_self_connect","scope_ceiling":["telegram:dialogs:read"]}]`, "cannot be bound"},
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
		"list_folders":        {},
		"list_topics":         {},
		"get_messages":        {Forbidden: []string{"fetch_media"}, LimitDefault: 20, LimitMax: 50},
		"get_unread_messages": {Required: []string{"peer"}, Forbidden: []string{"fetch_media", "folder"}, LimitDefault: 20, LimitMax: 50},
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

// TestParseBindings_ScopeCeiling: a client_id record may carry a ceiling with
// or without a profile, and a record without one leaves the client with no
// ceiling at all.
func TestParseBindings_ScopeCeiling(t *testing.T) {
	got, err := ParseBindings(`[{"client_id":"pa.example","scope_ceiling":["telegram:dialogs:read","telegram:messages:read"]},` +
		`{"client_id":"both.example","profile":"core-readonly","scope_ceiling":["telegram:dialogs:read"]},` +
		`{"client_id":"claude.ai","profile":"core-readonly"}]`)
	if err != nil {
		t.Fatalf("valid table: %v", err)
	}
	if c, ok := got.ScopeCeiling("pa.example"); !ok || strings.Join(c, " ") != "telegram:dialogs:read telegram:messages:read" {
		t.Fatalf("pa.example ceiling = %v, %v", c, ok)
	}
	if _, bound := got.ByClientID["pa.example"]; bound {
		t.Fatalf("a ceiling-only record bound a profile: %v", got.ByClientID)
	}
	if c, ok := got.ScopeCeiling("both.example"); !ok || len(c) != 1 || got.ByClientID["both.example"] != CoreReadonly {
		t.Fatalf("both.example = ceiling %v %v, profile %q", c, ok, got.ByClientID["both.example"])
	}
	if c, ok := got.ScopeCeiling("claude.ai"); ok {
		t.Fatalf("a profile-only record has a ceiling: %v", c)
	}
	if got.Empty() {
		t.Fatal("a table with ceilings reports Empty")
	}
	ceilingOnly, err := ParseBindings(`[{"client_id":"pa.example","scope_ceiling":["telegram:dialogs:read"]}]`)
	if err != nil || ceilingOnly.Empty() {
		t.Fatalf("ceiling-only table = %v, %v; want non-empty", ceilingOnly, err)
	}
}

// TestParseBindings_ScopeCeilingByRedirectURI: a redirect_uri record may carry
// a ceiling, with or without a profile, and ScopeCeilingFor resolves it with
// the client_id ceiling winning.
func TestParseBindings_ScopeCeilingByRedirectURI(t *testing.T) {
	const cb = "https://pa.example.test/cb"
	b, err := ParseBindings(`[
	  {"redirect_uri":"` + cb + `","scope_ceiling":["telegram:dialogs:read","telegram:messages:read"]},
	  {"redirect_uri":"https://other.example.test/cb","profile":"core-readonly","scope_ceiling":["telegram:dialogs:read"]},
	  {"client_id":"pa.example","scope_ceiling":["telegram:dialogs:read"]}]`)
	if err != nil {
		t.Fatalf("ParseBindings: %v", err)
	}
	if got, ok := b.ScopeCeilingFor("any-client", cb); !ok || len(got) != 2 {
		t.Fatalf("ScopeCeilingFor(any-client, cb) = %v, %v; want the two-scope redirect ceiling", got, ok)
	}
	if _, ok := b.ScopeCeilingFor("any-client", ""); ok {
		t.Fatal("an unknown redirect_uri must match no redirect_uri ceiling")
	}
	if _, ok := b.ScopeCeilingFor("any-client", "https://unlisted.example.test/cb"); ok {
		t.Fatal("an unlisted redirect_uri matched a ceiling")
	}
	// The client_id ceiling wins over a redirect_uri ceiling for the same call.
	if got, ok := b.ScopeCeilingFor("pa.example", cb); !ok || len(got) != 1 || got[0] != "telegram:dialogs:read" {
		t.Fatalf("ScopeCeilingFor(pa.example, cb) = %v, %v; want the client_id ceiling", got, ok)
	}
	// A ceiling-only redirect record binds no profile; a record that names one does.
	if p := b.Resolve("any-client", cb); p != "" {
		t.Fatalf("a ceiling-only redirect record bound profile %q", p)
	}
	if p := b.Resolve("any-client", "https://other.example.test/cb"); p != "core-readonly" {
		t.Fatalf("redirect record with a profile resolved %q, want core-readonly", p)
	}
	if b.Empty() {
		t.Fatal("a table with redirect_uri ceilings is not empty")
	}
}
