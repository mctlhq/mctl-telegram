package connection_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
)

const (
	aliceRead = "iot:view"
	aliceWide = "iot:control iot:view"
)

// TestWriteScope_TokenResponseDecidesWhatIsHeld: the scope a connection
// holds is the one its token response reported, judged against what the
// connection asked for, and never the request itself (#1320 P2-S14c).
func TestWriteScope_TokenResponseDecidesWhatIsHeld(t *testing.T) {
	cases := []struct {
		name, requested, reported string
		granted                   string
		mismatch                  bool
	}{
		{"read asked, read granted", "", aliceRead, aliceRead, false},
		{"wide asked, wide granted", aliceWide, "iot:view iot:control", aliceWide, false},
		{"wide asked, narrowed to read", aliceWide, aliceRead, aliceRead, false},
		{"read asked, wide granted", "", aliceWide, "", true},
		{"read asked by name, wide granted", aliceRead, aliceWide, "", true},
		{"wide asked, control alone", aliceWide, "iot:control", "", true},
		{"wide asked, quasar added", aliceWide, aliceWide + " quasar", "", true},
		{"wide asked, another scope", aliceWide, "iot:view quasar", "", true},
		{"wide asked, empty scope", aliceWide, "", "", true},
		{"wide asked, comma separated", aliceWide, "iot:control,iot:view", "", true},
		{"wide asked, double space", aliceWide, "iot:control  iot:view", "", true},
		{"a request this build never makes", "iot:control", "iot:control", "", true},
		{"a request in another order", "iot:view iot:control", aliceWide, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := connection.VerifyTokenResponseFor(connection.ServerAlice, tc.requested,
				tokenResponse("fake-at-ws", "fake-rt-ws", tc.reported))
			err := got.Err
			if tc.mismatch {
				if !errors.Is(err, connection.ErrScopeMismatch) {
					t.Fatalf("err %v, want ErrScopeMismatch", err)
				}
				return
			}
			if err != nil || got.Granted != tc.granted {
				t.Fatalf("granted %q (%v), want %q", got.Granted, err, tc.granted)
			}
		})
	}
	// A response without a scope field says nothing about what was
	// granted: it is not read as the request.
	for _, raw := range []string{
		`{"access_token":"fake-at-ws","token_type":"Bearer"}`,
		`{"access_token":"fake-at-ws","token_type":"Bearer","scope":null}`,
		`{"access_token":"fake-at-ws","token_type":"Bearer","scope":["iot:control","iot:view"]}`,
	} {
		if err := connection.VerifyTokenResponseFor(connection.ServerAlice, aliceWide, []byte(raw)).Err; !errors.Is(err, connection.ErrScopeMismatch) {
			t.Fatalf("%s: err %v, want ErrScopeMismatch", raw, err)
		}
	}
	// tg has no write scope: nothing wider than its read set is accepted,
	// whatever the request says.
	if err := connection.VerifyTokenResponseFor(connection.ServerTG, tgScope+" telegram:messages:send",
		tokenResponse("fake-at-ws", "", tgScope+" telegram:messages:send")).Err; !errors.Is(err, connection.ErrScopeMismatch) {
		t.Fatalf("tg wide: err %v", err)
	}
}

// TestWriteScope_Holds: a write tool is held only by a connection whose
// granted scope is accepted for what it asked and contains the tool's
// scope. A view-only connection, a scope that cannot be read and a tool
// the table does not know hold nothing.
func TestWriteScope_Holds(t *testing.T) {
	ws := connection.DefaultWriteScopes()
	conn := func(requested, granted string) connection.Connection {
		return connection.Connection{Server: connection.ServerAlice, RequestedScope: requested, GrantedScope: granted}
	}
	wide := conn(aliceWide, aliceWide)
	tools := ws.Tools(connection.ServerAlice)
	if want := []string{"alice_control_device", "alice_control_room", "alice_media_control", "alice_play_music",
		"alice_set_light", "alice_set_volume", "alice_trigger_scenario"}; !slices.Equal(tools, want) {
		t.Fatalf("alice write tools %v", tools)
	}
	for _, tool := range tools {
		if need, ok := ws.Needs(connection.ServerAlice, tool); !ok || need != "iot:control" {
			t.Errorf("%s needs %q %v", tool, need, ok)
		}
		if !ws.Holds(wide, tool) {
			t.Errorf("a write connection does not hold %s", tool)
		}
	}
	if !ws.HoldsAny(wide) || !connection.ScopeAccepted(wide) {
		t.Fatal("a write connection holds nothing")
	}
	none := map[string]connection.Connection{
		"view-only":                        conn("", aliceRead),
		"asked wide, narrowed to read":     conn(aliceWide, aliceRead),
		"wide granted, never asked":        conn("", aliceWide),
		"wide granted, read asked by name": conn(aliceRead, aliceWide),
		"empty granted scope":              conn(aliceWide, ""),
		"granted scope with two spaces":    conn(aliceWide, "iot:control  iot:view"),
		"granted scope in another order":   conn(aliceWide, "iot:view iot:control"),
		"granted scope with a comma":       conn(aliceWide, "iot:control,iot:view"),
		"control alone":                    conn(aliceWide, "iot:control"),
		"quasar added":                     conn(aliceWide, aliceWide+" quasar"),
		"another server":                   {Server: connection.ServerTG, RequestedScope: aliceWide, GrantedScope: aliceWide},
		"unknown server":                   {Server: connection.Server("other"), RequestedScope: aliceWide, GrantedScope: aliceWide},
	}
	for name, c := range none {
		for _, tool := range tools {
			if ws.Holds(c, tool) {
				t.Errorf("%s holds %s", name, tool)
			}
		}
		if ws.HoldsAny(c) {
			t.Errorf("%s holds a write tool", name)
		}
	}
	// A view-only connection is still accepted for reading; the two
	// narrowed or unreadable shapes are accepted for nothing.
	if !connection.ScopeAccepted(none["view-only"]) || !connection.ScopeAccepted(none["asked wide, narrowed to read"]) {
		t.Fatal("a read connection is not accepted for reading")
	}
	for _, name := range []string{"wide granted, never asked", "empty granted scope", "granted scope with two spaces", "control alone", "quasar added"} {
		if connection.ScopeAccepted(none[name]) {
			t.Errorf("%s is accepted", name)
		}
	}
	// Tools that need the quasar scope, a read tool and an unknown name.
	for _, tool := range []string{"alice_send_command", "alice_say_phrase", "alice_list_devices", "send_message", ""} {
		if _, ok := ws.Needs(connection.ServerAlice, tool); ok || ws.Holds(wide, tool) {
			t.Errorf("%q is a write tool a connection holds", tool)
		}
	}
	// The zero table and a table with a malformed entry.
	if (connection.WriteScopes{}).Holds(wide, "alice_set_volume") {
		t.Fatal("the zero table holds a tool")
	}
	for _, bad := range []map[connection.Server]map[string]string{
		{connection.Server("other"): {"x": "iot:control"}},
		{connection.ServerAlice: {"": "iot:control"}},
		{connection.ServerAlice: {"alice_set_volume": ""}},
		{connection.ServerAlice: {"alice_set_volume": "iot:control iot:view"}},
	} {
		if _, err := connection.NewWriteScopes(bad); !errors.Is(err, connection.ErrScopeConfig) {
			t.Errorf("table %v: err %v", bad, err)
		}
	}
}

// writeConn drives a new alice connection, begun for writes when wide, to
// pending_return.
func (e *env) writeConn(t *testing.T, principal int64, wide bool) connection.Connection {
	t.Helper()
	ctx := context.Background()
	begin := e.m.Begin
	if wide {
		begin = e.m.BeginForWrites
	}
	c, err := begin(ctx, principal, connection.ServerAlice)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if c, err = e.m.StartOAuth(ctx, principal, c.ID, c.AuthorityRevision); err != nil {
		t.Fatalf("start oauth: %v", err)
	}
	if c, err = e.m.StoreAuthorizationCode(ctx, principal, c.ID, c.AuthorityRevision, connection.NewSecret("fake-code-"+c.ID)); err != nil {
		t.Fatalf("store code: %v", err)
	}
	return c
}

// TestWriteScope_ConnectionRecordsWhatWasGranted drives the manager: the
// row keeps what the connection asked for from its first state, and what
// the exchange stores is what the response reported.
func TestWriteScope_ConnectionRecordsWhatWasGranted(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		ctx := context.Background()
		ws := connection.DefaultWriteScopes()
		e := newEnv(t, s)
		alice, _ := principals(t, s)

		// Begin asks for the read set and BeginForWrites for the wide one;
		// on tg, which has no write scope, the two are the same.
		if c := e.writeConn(t, alice, false); c.RequestedScope != "" {
			t.Fatalf("a read connection asked for %q", c.RequestedScope)
		}
		tg, err := e.m.BeginForWrites(ctx, alice, connection.ServerTG)
		if err != nil || tg.RequestedScope != "" {
			t.Fatalf("tg begun for writes asked for %q (%v)", tg.RequestedScope, err)
		}

		// Asked wide, granted wide: the write scope is held, and it
		// survives a read of the row.
		alice, _ = principals(t, s)
		c := e.writeConn(t, alice, true)
		if c.RequestedScope != aliceWide {
			t.Fatalf("requested %q, want %q", c.RequestedScope, aliceWide)
		}
		got, err := e.m.CompleteExchange(ctx, alice, c.ID, c.AuthorityRevision, "acct-alice-home",
			tokenResponse("fake-at-w1", "fake-rt-w1", "iot:view iot:control"))
		if err != nil || got.GrantedScope != aliceWide || got.RequestedScope != aliceWide {
			t.Fatalf("wide exchange: %+v %v", got, err)
		}
		if stored, err := e.m.Get(ctx, alice, c.ID); err != nil || stored.GrantedScope != aliceWide ||
			stored.RequestedScope != aliceWide || !ws.Holds(stored, "alice_set_volume") {
			t.Fatalf("stored wide connection %+v (%v)", stored, err)
		}

		// Asked wide, the response reports the read scope alone: the
		// connection is recorded as narrowed, works for reading and holds
		// no write tool.
		alice, _ = principals(t, s)
		c = e.writeConn(t, alice, true)
		got, err = e.m.CompleteExchange(ctx, alice, c.ID, c.AuthorityRevision, "acct-alice-home",
			tokenResponse("fake-at-w2", "fake-rt-w2", aliceRead))
		if err != nil || got.State != connection.StatePendingConfirm {
			t.Fatalf("narrowed exchange: %+v %v", got, err)
		}
		stored, err := e.m.Get(ctx, alice, c.ID)
		if err != nil || stored.GrantedScope != aliceRead || stored.RequestedScope != aliceWide {
			t.Fatalf("stored narrowed connection %+v (%v)", stored, err)
		}
		if ws.HoldsAny(stored) || !connection.ScopeAccepted(stored) {
			t.Fatalf("a narrowed connection: holds a write tool %v, accepted %v", ws.HoldsAny(stored), connection.ScopeAccepted(stored))
		}

		// Asked for the read set, the response reports the wide one: the
		// exchange fails and the tokens are revoked, as before (S1-T9).
		alice, _ = principals(t, s)
		c = e.writeConn(t, alice, false)
		got, err = e.m.CompleteExchange(ctx, alice, c.ID, c.AuthorityRevision, "acct-alice-home",
			tokenResponse("fake-at-w3", "fake-rt-w3", aliceWide))
		if !errors.Is(err, connection.ErrScopeMismatch) || got.State != connection.StateFailed {
			t.Fatalf("unasked wide scope: %+v %v", got, err)
		}
		if r := e.revoker.revoked(); !slices.Contains(r, "fake-at-w3") {
			t.Fatal("the tokens of an unasked wide grant were not revoked")
		}

		// Asked wide, the response has no readable scope: nothing is
		// stored, so nothing is held.
		for _, resp := range [][]byte{
			tokenResponse("fake-at-w4", "fake-rt-w4", ""),
			tokenResponse("fake-at-w4", "fake-rt-w4", aliceWide+" quasar"),
			tokenResponse("fake-at-w4", "fake-rt-w4", "iot:control"),
		} {
			alice, _ = principals(t, s)
			c = e.writeConn(t, alice, true)
			got, err = e.m.CompleteExchange(ctx, alice, c.ID, c.AuthorityRevision, "acct-alice-home", resp)
			if !errors.Is(err, connection.ErrScopeMismatch) || got.State != connection.StateFailed || ws.HoldsAny(got) {
				t.Fatalf("response %s: %+v %v", resp, got, err)
			}
		}
	})
}

// TestWriteScope_RefreshKeepsTheGrant: a refresh must report exactly the
// scope the connection holds. A read connection is not widened by one and
// a write connection is not silently narrowed.
func TestWriteScope_RefreshKeepsTheGrant(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		ctx := context.Background()
		active := func(e *env, principal int64, wide bool, granted string) connection.Connection {
			c := e.writeConn(t, principal, wide)
			c, err := e.m.CompleteExchange(ctx, principal, c.ID, c.AuthorityRevision, "acct-alice-home",
				tokenResponse("fake-at-r-"+c.ID, "fake-rt-r-"+c.ID, granted))
			if err != nil {
				t.Fatalf("exchange: %v", err)
			}
			if c, err = e.m.Confirm(ctx, principal, c.ID, c.AuthorityRevision); err != nil {
				t.Fatalf("confirm: %v", err)
			}
			return c
		}
		cases := []struct {
			name           string
			wide           bool
			granted, fresh string
			ok             bool
		}{
			{"write connection, same scope", true, aliceWide, "iot:view iot:control", true},
			{"read connection, same scope", false, aliceRead, aliceRead, true},
			{"read connection widened", false, aliceRead, aliceWide, false},
			{"narrowed connection widened", true, aliceRead, aliceWide, false},
			{"write connection narrowed", true, aliceWide, aliceRead, false},
			{"write connection, no scope", true, aliceWide, "", false},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				e := newEnv(t, s)
				alice, _ := principals(t, s)
				acceptConsent(t, s, alice)
				c := active(e, alice, tc.wide, tc.granted)
				_, err := e.m.Refresh(ctx, alice, c.ID, func(context.Context, connection.Server, connection.Secret) ([]byte, error) {
					return tokenResponse("fake-at-fresh", "fake-rt-fresh", tc.fresh), nil
				})
				got, gerr := e.m.Get(ctx, alice, c.ID)
				if gerr != nil {
					t.Fatal(gerr)
				}
				if tc.ok {
					if err != nil || got.State != connection.StateActive || got.GrantedScope != tc.granted {
						t.Fatalf("refresh: %+v %v", got, err)
					}
					return
				}
				if !errors.Is(err, connection.ErrScopeMismatch) || got.State != connection.StateFailed {
					t.Fatalf("refresh: %+v %v, want failed with ErrScopeMismatch", got, err)
				}
			})
		}
	})
}
