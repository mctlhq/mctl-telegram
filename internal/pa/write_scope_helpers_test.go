package pa_test

import (
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/pa/catalog"
	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
)

// testWriteScopes is the scope table of the Phase 2 harnesses that are not
// about scopes. Their write tools run on test connections that hold a read
// scope only (most of them on the tg server, which has no write scope at
// all), so here every write tool of the Phase 2 pin and of the test pins
// needs a scope such a connection holds. The tests of the scope rules
// themselves (write_scope_test.go) use the compiled table.
func testWriteScopes(t *testing.T) *connection.WriteScopes {
	t.Helper()
	pin, err := catalog.LoadPinPhase2()
	if err != nil {
		t.Fatal(err)
	}
	held := map[connection.Server]string{
		connection.ServerTG:    "telegram:messages:read",
		connection.ServerAlice: "iot:view",
	}
	tools := map[connection.Server]map[string]string{}
	for server, scope := range held {
		tools[server] = map[string]string{writeTool: scope, "alice_play_music": scope}
		for _, p := range []*catalog.Pin{pin, cardPin(), permPin()} {
			for _, sp := range p.Servers {
				for name, pt := range sp.Tools {
					if pt.Tier == catalog.TierApprove {
						tools[server][name] = scope
					}
				}
			}
		}
	}
	ws, err := connection.NewWriteScopes(tools)
	if err != nil {
		t.Fatal(err)
	}
	return &ws
}
