package connection

import (
	"errors"
	"maps"
	"testing"
)

// TestCheckScopeConfig: the compiled scope tables pass the startup check,
// and each way of breaking them fails it.
func TestCheckScopeConfig(t *testing.T) {
	if err := CheckScopeConfig(); err != nil {
		t.Fatalf("the compiled tables: %v", err)
	}
	if got, ok := WriteRequestScope(ServerAlice); !ok || got != "iot:control iot:view" {
		t.Fatalf("alice write request scope %q %v", got, ok)
	}
	if got, ok := WriteRequestScope(ServerTG); ok || got != "" {
		t.Fatalf("tg has a write request scope %q", got)
	}
	// The quasar scope is not used: no table names it.
	for _, tools := range writeToolScopes {
		for tool, scope := range tools {
			if scope == "quasar" || tool == "alice_send_command" || tool == "alice_say_phrase" {
				t.Fatalf("%s needs %s: the quasar scope is not used", tool, scope)
			}
		}
	}
	restore := func() func() {
		w, wt, a := maps.Clone(writeScopes), map[Server]map[string]string{}, maps.Clone(allowedScopes)
		for s, m := range writeToolScopes {
			wt[s] = maps.Clone(m)
		}
		return func() { writeScopes, writeToolScopes, allowedScopes = w, wt, a }
	}
	cases := map[string]func(){
		"write scope that is also a read scope": func() { writeScopes[ServerAlice] = []string{"iot:view"} },
		"two scopes in one token":               func() { writeScopes[ServerAlice] = []string{"iot:control quasar"} },
		"write scope no tool needs":             func() { writeScopes[ServerAlice] = []string{"iot:control", "quasar"} },
		"write scopes of a server without reads": func() {
			writeScopes[Server("other")] = []string{"x:write"}
		},
		"empty write scope list": func() { writeScopes[ServerTG] = nil },
		"tool with a scope its server does not ask for": func() {
			writeToolScopes[ServerAlice]["alice_send_command"] = "quasar"
		},
		"tool with a read scope":    func() { writeToolScopes[ServerAlice]["alice_set_volume"] = "iot:view" },
		"write tool of a read-only": func() { writeToolScopes[ServerTG] = map[string]string{"send_message": "telegram:messages:send"} },
		"unnamed tool":              func() { writeToolScopes[ServerAlice][""] = "iot:control" },
		"malformed read scope":      func() { allowedScopes[ServerAlice] = []string{"iot:view iot:control"} },
		"no read scope":             func() { allowedScopes[ServerAlice] = nil },
	}
	for name, breakIt := range cases {
		t.Run(name, func(t *testing.T) {
			defer restore()()
			breakIt()
			if err := CheckScopeConfig(); !errors.Is(err, ErrScopeConfig) {
				t.Fatalf("err %v, want ErrScopeConfig", err)
			}
		})
	}
	if err := CheckScopeConfig(); err != nil {
		t.Fatalf("the tables were not restored: %v", err)
	}
}
