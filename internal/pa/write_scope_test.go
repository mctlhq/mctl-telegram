package pa_test

import (
	"context"
	"database/sql"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/pa"
	"github.com/mctlhq/mctl-telegram/internal/pa/approval"
	"github.com/mctlhq/mctl-telegram/internal/pa/catalog"
	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
	"github.com/mctlhq/mctl-telegram/internal/pa/connector"
	"github.com/mctlhq/mctl-telegram/internal/pa/output/safetext"
)

const (
	aliceViewScope = "iot:view"
	aliceWideScope = "iot:control iot:view"
)

// linkAlice links an alice connection for principal and activates it. wide
// is whether /connect ran with writes on, so that the connection asked for
// iot:control too; granted is the scope the token response reports.
// Activating it supersedes the principal's earlier alice connection.
func (e *dispatchEnv) linkAlice(principal int64, account string, wide bool, granted string) connection.Connection {
	e.t.Helper()
	ctx := context.Background()
	begin := e.mgr.Begin
	if wide {
		begin = e.mgr.BeginForWrites
	}
	c, err := begin(ctx, principal, connection.ServerAlice)
	if err != nil {
		e.t.Fatal(err)
	}
	if c, err = e.mgr.StartOAuth(ctx, principal, c.ID, c.AuthorityRevision); err != nil {
		e.t.Fatal(err)
	}
	if c, err = e.mgr.StoreAuthorizationCode(ctx, principal, c.ID, c.AuthorityRevision, connection.NewSecret("fake-code-"+c.ID)); err != nil {
		e.t.Fatal(err)
	}
	resp := `{"access_token":"fake-at-` + account + `","token_type":"Bearer","expires_in":3600,"refresh_token":"fake-rt-` + account + `","scope":"` + granted + `"}`
	if c, err = e.mgr.CompleteExchange(ctx, principal, c.ID, c.AuthorityRevision, account, []byte(resp)); err != nil {
		e.t.Fatal(err)
	}
	if c, err = e.mgr.Confirm(ctx, principal, c.ID, c.AuthorityRevision); err != nil {
		e.t.Fatal(err)
	}
	return c
}

func (e *dispatchEnv) conn(principal int64, id string) connection.Connection {
	e.t.Helper()
	c, err := e.mgr.Get(context.Background(), principal, id)
	if err != nil {
		e.t.Fatal(err)
	}
	return c
}

var aliceWriteTools = []string{"alice_control_device", "alice_control_room", "alice_media_control", "alice_play_music",
	"alice_set_light", "alice_set_volume", "alice_trigger_scenario"}

// TestWriteScope_OnlyAConnectionThatHoldsTheScopeGetsAWriteTool runs the
// compiled scope table (#1320 P2-S14c). A view-only alice connection with
// writes on gets no write tool and no standing permission, and the
// principal is told to connect again. A connection that asked for
// iot:control holds it only when the token response reported it: one the
// service narrowed, and one whose stored scope cannot be read, hold
// nothing.
func TestWriteScope_OnlyAConnectionThatHoldsTheScopeGetsAWriteTool(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newActionEnvScopes(t, s, nil)

		// The view-only connection every principal has today.
		if e.home.GrantedScope != aliceViewScope || e.home.RequestedScope != "" {
			t.Fatalf("fixture connection %+v", e.home)
		}
		if got, why := e.offered(alice, e.home, aliceWriteTools...); len(got) != 0 || why != pa.WithheldScope {
			t.Fatalf("view-only connection: offered %v (%s)", got, why)
		}
		e.refused(alice, grantCmd, safetext.TextWriteScopeNeeded)
		e.nothingGranted("view-only connection")
		// It still reads: nothing about it changed.
		if c := e.conn(alice, e.home.ID); c.State != connection.StateActive || !connection.ScopeAccepted(c) {
			t.Fatalf("view-only connection after the refusals: %+v", c)
		}

		// Asked for iot:control, and the response reports the read scope
		// alone: no write tool, although it was asked for.
		narrowed := e.linkAlice(bob, "acct-bob-home-2", true, aliceViewScope)
		if narrowed.RequestedScope != aliceWideScope || narrowed.GrantedScope != aliceViewScope {
			t.Fatalf("narrowed connection %+v", narrowed)
		}
		if got, why := e.offered(bob, narrowed, aliceWriteTools...); len(got) != 0 || why != pa.WithheldScope {
			t.Fatalf("narrowed connection: offered %v (%s)", got, why)
		}
		e.refused(bob, grantCmd, safetext.TextWriteScopeNeeded)

		// Connected again with access for actions.
		wide := e.linkAlice(alice, "acct-alice-home-2", true, "iot:view iot:control")
		if wide.RequestedScope != aliceWideScope || wide.GrantedScope != aliceWideScope {
			t.Fatalf("write connection %+v", wide)
		}
		if got, why := e.offered(alice, wide, aliceWriteTools...); !slices.Equal(got, aliceWriteTools) || why != pa.WithheldNone {
			t.Fatalf("write connection: offered %v (%s)", got, why)
		}
		// A tool that needs the quasar scope, a read tool and a tool of
		// another server are held by nothing.
		if got, why := e.offered(alice, wide, permTool, "alice_send_command", "alice_say_phrase", "alice_list_devices", writeTool); !slices.Equal(got, []string{permTool}) || why != pa.WithheldScope {
			t.Fatalf("write connection: offered %v (%s)", got, why)
		}
		// Not another principal's connection, and not a connection that
		// is no longer active.
		if got, why := e.offered(bob, wide, permTool); len(got) != 0 || why != pa.WithheldScope {
			t.Fatalf("Bob on Alice's connection: offered %v (%s)", got, why)
		}
		if got, why := e.offered(alice, e.home, permTool); len(got) != 0 || why != pa.WithheldScope {
			t.Fatalf("superseded connection: offered %v (%s)", got, why)
		}
		grant := e.button(e.one(alice, grantCmd), safetext.LabelPermissionGrant)

		// The stored scope is read again at the press. One that cannot be
		// read holds nothing: nothing is granted and no tool is offered.
		for _, unreadable := range []string{"iot:control  iot:view", "", "iot:control,iot:view", aliceViewScope} {
			if _, err := s.DB.Exec(`UPDATE pa_connections SET granted_scope = $1 WHERE id = $2`, unreadable, wide.ID); err != nil {
				t.Fatal(err)
			}
			if got, why := e.offered(alice, wide, aliceWriteTools...); len(got) != 0 || why != pa.WithheldScope {
				t.Fatalf("granted scope %q: offered %v (%s)", unreadable, got, why)
			}
		}
		if r := e.press(alice, grant); r != pa.ReplyPermissionRefused {
			t.Fatalf("press on a connection without the scope answered %q", r)
		}
		e.nothingGranted("connection without the scope at the press")
		e.refused(alice, grantCmd, safetext.TextWriteScopeNeeded)

		// A scope the row holds without having asked for it is not
		// accepted either.
		if _, err := s.DB.Exec(`UPDATE pa_connections SET granted_scope = $1, requested_scope = '' WHERE id = $2`, aliceWideScope, wide.ID); err != nil {
			t.Fatal(err)
		}
		if got, why := e.offered(alice, wide, permTool); len(got) != 0 || why != pa.WithheldScope {
			t.Fatalf("a wide scope nobody asked for: offered %v (%s)", got, why)
		}

		// With the scope back, the grant goes through.
		if _, err := s.DB.Exec(`UPDATE pa_connections SET granted_scope = $1, requested_scope = $1 WHERE id = $2`, aliceWideScope, wide.ID); err != nil {
			t.Fatal(err)
		}
		if r := e.press(alice, e.button(e.one(alice, grantCmd), safetext.LabelPermissionGrant)); r != pa.ReplyPermissionGranted {
			t.Fatalf("grant on the write connection answered %q", r)
		}
		if rows := e.rows(); len(rows) != 1 || rows[0].conn != wide.ID || rows[0].revoked != 0 {
			t.Fatalf("permission rows %+v", rows)
		}
	})
}

// aliceEP is a fake alice server behind connector.WriteEndpoint: it counts
// the calls it was handed.
type aliceEP struct {
	mu    sync.Mutex
	tools []string
}

func (f *aliceEP) Server() string { return "alice" }

func (f *aliceEP) CallToolExact(_ context.Context, _ connection.Secret, tool string, _ []byte) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tools = append(f.tools, tool)
	return []byte(`{"content":[{"type":"text","text":"done"}]}`), nil
}

func (f *aliceEP) sent() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.tools)
}

// scopeFresh is a fresh listing that matches the approvals of
// TestWriteScope_ExecutorSendsOnlyOnAHeldScope on any server.
// It counts its calls, and onCall runs inside one: between the executor's
// first read of the connection and the transaction that commits the
// dispatch.
type scopeFresh struct {
	calls  atomic.Int64
	onCall func()
}

func (f *scopeFresh) FreshTool(context.Context, connector.FreshRequest) (connector.FreshTool, error) {
	f.calls.Add(1)
	if f.onCall != nil {
		f.onCall()
	}
	return connector.FreshTool{
		SchemaSHA: shaHex([]byte("schema")), DescriptionSHA: shaHex([]byte("description")),
		AnnotationSHA: shaHex([]byte("annotations")), Tier: catalog.TierApprove, Class: catalog.ClassWrite,
	}, nil
}

// TestWriteScope_ExecutorSendsOnlyOnAHeldScope: an approved action is sent
// only on a connection that holds its tool's scope, read in the executor's
// own transaction, under the compiled table. It does not rest on the claim
// or the card having checked.
func TestWriteScope_ExecutorSendsOnlyOnAHeldScope(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		home, fresh := &aliceEP{}, &scopeFresh{}
		e := newWriteEnv(t, s, func(c *connector.WriteConfig) {
			c.Scopes = nil
			c.Endpoints["alice"] = home
			c.Fresh = fresh
		})
		sent := func() int { return len(e.ep.sent()) + len(home.sent()) }
		e.flags.Store(&connector.Flags{ExternalTools: true, Writes: true, Servers: map[string]bool{"tg": true, "alice": true}})
		approved := func(conn connection.Connection, tool string) approval.Approval {
			t.Helper()
			canon, err := catalog.CanonicalArgs([]byte(`{"device_id":"dev-1","volume":3}`))
			if err != nil {
				t.Fatal(err)
			}
			b := e.binding(shaHex(canon))
			b.ConnectionID, b.AuthorityRevision, b.Server, b.Tool = conn.ID, conn.AuthorityRevision, string(conn.Server), tool
			a, err := approval.New(b, e.h.Now())
			if err != nil {
				t.Fatal(err)
			}
			if a, err = e.sealer.Seal(a, canon); err != nil {
				t.Fatal(err)
			}
			return e.save(a)
		}
		refused := func(step string, a approval.Approval) {
			t.Helper()
			if out := e.dispatch(a.ID); out.Status != connector.StatusRefused || out.Reason != connector.ReasonWriteScopeMissing {
				t.Fatalf("%s: %+v", step, out)
			}
			// Refused before the server is asked for its tools.
			if n, listed := sent(), fresh.calls.Load(); n != 0 || listed != 0 {
				t.Fatalf("%s: %d writes sent, %d listings", step, n, listed)
			}
		}

		// A view-only connection, and a tg connection, which has no write
		// scope at all.
		view := e.activeAlice(alice, "acct-alice-home")
		refused("view-only connection", approved(view, "alice_set_volume"))
		refused("tg connection", approved(e.connA, writeTool))

		// Asked for iot:control, narrowed by the service.
		narrowed := e.linkAlice(alice, "acct-alice-home-2", true, aliceViewScope)
		refused("narrowed connection", approved(narrowed, "alice_set_volume"))

		// A write connection: a tool that needs another scope is refused,
		// its own tool is sent.
		wide := e.linkAlice(alice, "acct-alice-home-3", true, aliceWideScope)
		refused("a tool that needs the quasar scope", approved(wide, "alice_send_command"))
		a := approved(wide, "alice_set_volume")
		// The scope is read when the action is sent, not when it was
		// approved.
		if _, err := s.DB.Exec(`UPDATE pa_connections SET granted_scope = 'iot:control  iot:view' WHERE id = $1`, wide.ID); err != nil {
			t.Fatal(err)
		}
		if out := e.dispatch(a.ID); out.Status != connector.StatusRefused || sent() != 0 {
			t.Fatalf("unreadable granted scope: %+v, %d writes sent", out, sent())
		}
		if _, err := s.DB.Exec(`UPDATE pa_connections SET granted_scope = $1 WHERE id = $2`, aliceWideScope, wide.ID); err != nil {
			t.Fatal(err)
		}
		// The service narrows the grant while the call is being prepared:
		// the row locked by the transaction that commits the dispatch no
		// longer holds the scope, and nothing is sent.
		fresh.onCall = func() {
			if _, err := s.DB.Exec(`UPDATE pa_connections SET granted_scope = $1 WHERE id = $2`, aliceViewScope, wide.ID); err != nil {
				t.Error(err)
			}
		}
		if out := e.dispatch(approved(wide, "alice_set_volume").ID); out.Status != connector.StatusRefused ||
			out.Reason != connector.ReasonWriteScopeMissing || sent() != 0 || fresh.calls.Load() != 1 {
			t.Fatalf("scope narrowed before the commit: %+v, %d writes sent, %d listings", out, sent(), fresh.calls.Load())
		}
		fresh.onCall = nil
		if _, err := s.DB.Exec(`UPDATE pa_connections SET granted_scope = $1 WHERE id = $2`, aliceWideScope, wide.ID); err != nil {
			t.Fatal(err)
		}
		if out := e.dispatch(approved(wide, "alice_set_volume").ID); out.Status != connector.StatusOK || !slices.Equal(home.sent(), []string{"alice_set_volume"}) || len(e.ep.sent()) != 0 {
			t.Fatalf("write connection: %+v, sent %v", out, home.sent())
		}
	})
}

// TestWriteScope_RefusedCallTellsThePrincipalOnce: an action asked of a
// connection that does not hold its scope is refused before anything is
// written or sent, and the principal is told once to connect the service
// again, however often the model asks. The connection keeps reading.
func TestWriteScope_RefusedCallTellsThePrincipalOnce(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		// The write tool of the test pin needs a scope the tg connection
		// was never given.
		ws, err := connection.NewWriteScopes(map[connection.Server]map[string]string{
			connection.ServerTG: {writeTool: "telegram:messages:send"},
		})
		if err != nil {
			t.Fatal(err)
		}
		e := newCardEnvOn(t, s, cardPin(), nil, func(c *connector.CardConfig) { c.Scopes = &ws })
		notice := safetext.TextWriteScopeNeeded.String()
		told := func() int {
			n := 0
			for _, m := range e.h.MessagesTo(alice) {
				if m.Text == notice {
					if len(m.Buttons) != 0 {
						t.Fatalf("the notice carries a keyboard: %+v", m.Buttons)
					}
					n++
				}
			}
			return n
		}
		for i := range 3 {
			a := e.call(e.token, writeCall(writeArgs))
			e.h.Loop().WaitDeliveries()
			if a.code != http.StatusForbidden || a.Stop != connector.ReasonWriteScopeMissing {
				t.Fatalf("call %d answered %+v", i, a)
			}
			if n := told(); n != 1 {
				t.Fatalf("after call %d the principal was told %d times, want once", i, n)
			}
		}
		e.nothingWritten()
		if got := e.strings(`SELECT kind || '/' || connection_id FROM pa_outbox WHERE kind IN ('write_scope_needed', 'action_consent_needed')`); !slices.Equal(got, []string{"write_scope_needed/" + e.connA.ID}) {
			t.Fatalf("notice rows %v", got)
		}
		if a := e.call(e.token, req("tg", "get_messages", e.connA.ID)); a.code != http.StatusOK {
			t.Fatalf("a read on the same connection: %+v", a)
		}
	})
}

// TestWriteScope_ReconnectSupersedesAndRevokes: connecting the service
// again replaces the view-only connection through the ordinary transition,
// which revokes its standing permissions and cancels its waiting actions;
// the new connection holds what its own token response reported.
func TestWriteScope_ReconnectSupersedesAndRevokes(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newActionEnv(t, s)
		// Under the test table the view-only connection can be granted a
		// permission, and the tg connection has a card waiting.
		if r := e.press(alice, e.button(e.one(alice, grantCmd), safetext.LabelPermissionGrant)); r != pa.ReplyPermissionGranted {
			t.Fatalf("grant answered %q", r)
		}
		row := e.emit(writeArgs)
		waiting := approval.Approval{}
		e.inTx(func(tx *sql.Tx) error {
			var err error
			waiting, err = approval.New(func() approval.Binding {
				b := e.binding(shaHex([]byte(`{}`)))
				b.ConnectionID, b.AuthorityRevision, b.Server, b.Tool = e.home.ID, e.home.AuthorityRevision, "alice", permTool
				return b
			}(), e.h.Now())
			if err != nil {
				return err
			}
			if waiting, err = e.sealer.Seal(waiting, []byte(`{}`)); err != nil {
				return err
			}
			return s.CreatePAApproval(context.Background(), tx, waiting)
		})

		wide := e.linkAlice(alice, "acct-alice-home-2", true, aliceWideScope)
		if old := e.conn(alice, e.home.ID); old.State == connection.StateActive {
			t.Fatalf("the view-only connection is still active: %+v", old)
		}
		if rows := e.rows(); len(rows) != 1 || rows[0].conn != e.home.ID || rows[0].revoked == 0 {
			t.Fatalf("the old connection's permission was not revoked: %+v", rows)
		}
		if got := e.strings(`SELECT status FROM pa_approvals WHERE id = $1`, waiting.ID); !slices.Equal(got, []string{"cancelled"}) {
			t.Fatalf("the old connection's waiting action: %v", got)
		}
		// Another connection's card is not touched.
		if got := e.strings(`SELECT status FROM pa_approvals WHERE id = $1`, row.id); !slices.Equal(got, []string{"pending"}) {
			t.Fatalf("the tg connection's card: %v", got)
		}
		if ws := connection.DefaultWriteScopes(); !ws.Holds(wide, permTool) || ws.HoldsAny(e.conn(alice, e.home.ID)) {
			t.Fatal("the new connection does not hold the write scope, or the old one does")
		}
		// Nothing is offered on the old connection any more.
		if got, why := e.offered(alice, e.home, permTool); len(got) != 0 || why != pa.WithheldScope {
			t.Fatalf("superseded connection: offered %v (%s)", got, why)
		}
		if got, why := e.offered(alice, wide, permTool); !slices.Equal(got, []string{permTool}) || why != pa.WithheldNone {
			t.Fatalf("new connection: offered %v (%s)", got, why)
		}
	})
}
