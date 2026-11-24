package linking_test

import (
	"context"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
	"github.com/mctlhq/mctl-telegram/internal/pa/linking"
)

const (
	aliceReadScope = "iot:view"
	aliceWideScope = "iot:control iot:view"
)

// TestLinking_WriteScopeAskedOnlyWithWritesOn: /connect asks the alice
// server for iot:control with iot:view only while PA_WRITES_ENABLED reads
// on; off, unreadable or on a server without a write scope it asks for the
// read set as it always did (#1320 P2-S14c).
func TestLinking_WriteScopeAskedOnlyWithWritesOn(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		asked := func(h *harness, server connection.Server) string {
			return mustQuery(t, h.begin(h.start(server))).Get("scope")
		}
		h := newHarness(t, s, true)
		if got := asked(h, connection.ServerAlice); got != aliceReadScope {
			t.Fatalf("writes off: asked %q", got)
		}
		if c := h.connection(connection.ServerAlice); c.RequestedScope != "" {
			t.Fatalf("writes off: the row asked for %q", c.RequestedScope)
		}

		h = newHarness(t, s, true)
		h.writes.failing.Store(true)
		if got := asked(h, connection.ServerAlice); got != aliceReadScope {
			t.Fatalf("flag unreadable: asked %q", got)
		}

		h = newHarness(t, s, true)
		h.writes.on.Store(true)
		if got := asked(h, connection.ServerTG); got != "telegram:dialogs:read telegram:messages:read" {
			t.Fatalf("tg with writes on: asked %q", got)
		}
		if got := asked(h, connection.ServerAlice); got != aliceWideScope {
			t.Fatalf("writes on: asked %q", got)
		}
		if c := h.connection(connection.ServerAlice); c.RequestedScope != aliceWideScope {
			t.Fatalf("writes on: the row asked for %q", c.RequestedScope)
		}
	})
}

// TestLinking_WriteScopeIsWhatTheServerGranted runs /connect to the active
// connection with writes on: the connection holds a write tool when the
// token response reports iot:control, and does not when the response
// reports the read scope alone, although the request was the same.
func TestLinking_WriteScopeIsWhatTheServerGranted(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		ctx := context.Background()
		ws := connection.DefaultWriteScopes()
		link := func(h *harness) connection.Connection {
			card := h.toConfirm(connection.ServerAlice, linking.Account{ID: "yandex-uid-4242", DisplayName: "Alice"})
			confirm, _ := confirmData(card)
			if handled, err := h.svc.HandleCallback(ctx, callbackUpdate(t, h.alice, confirm)); !handled || err != nil {
				t.Fatalf("confirm: handled=%v err=%v", handled, err)
			}
			c := h.connection(connection.ServerAlice)
			if c.State != connection.StateActive || c.RequestedScope != aliceWideScope {
				t.Fatalf("connection %+v", c)
			}
			return c
		}

		h := newHarness(t, s, true)
		h.writes.on.Store(true)
		if c := link(h); c.GrantedScope != aliceWideScope || !ws.Holds(c, "alice_set_volume") {
			t.Fatalf("granted as asked: %+v", c)
		}

		h = newHarness(t, s, true)
		h.writes.on.Store(true)
		h.as[connection.ServerAlice].grantScope = aliceReadScope
		if c := link(h); c.GrantedScope != aliceReadScope || ws.HoldsAny(c) || !connection.ScopeAccepted(c) {
			t.Fatalf("narrowed by the server: %+v holds=%v", c, ws.HoldsAny(c))
		}
	})
}
