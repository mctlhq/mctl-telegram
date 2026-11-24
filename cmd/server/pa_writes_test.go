package main

// pa_writes_test.go drives the wired write path (pa_writes.go, #1320 slice
// P2-S14) over the HTTP routes: the real run loop, tool route, card
// emitter, webhook and write executor built by buildPA, on SQLite and on
// Postgres, with the authorization server, the alice MCP endpoint and the
// Bot API faked. The test plays the worker: it claims the run and posts
// the model's tool calls.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/mctlhq/mctl-telegram/internal/auth/localjwt"
	"github.com/mctlhq/mctl-telegram/internal/config"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/pa"
	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
	"github.com/mctlhq/mctl-telegram/internal/pa/connector"
	"github.com/mctlhq/mctl-telegram/internal/pa/output/safetext"
)

// Synthetic speaker, in the text alice_list_devices answers with.
const (
	paKitchenID      = "spk-kitchen-0001"
	paKitchenSpeaker = "- **Kitchen speaker** (Комната: Kitchen, ID: `" + paKitchenID + "`, Статус: online)"
	// paSayCanonical is the canonical form of the arguments the tests send
	// in another key order: what an approval seals and a dispatch sends.
	paSayCanonical = `{"device":"` + paKitchenID + `","phrase":"Dinner is ready"}`
	paSaySent      = `{ "phrase": "Dinner is ready", "device": "` + paKitchenID + `" }`
	paSayTool      = "alice_say_phrase"
)

// paFakeAlice is the alice MCP endpoint: the committed tools/list of
// mctl-alice, an identity, one speaker, and a record of every approved
// call's exact bytes.
type paFakeAlice struct {
	mu    sync.Mutex
	reads []string
	exact []string
	// drifted makes the listing describe alice_say_phrase in other words
	// than the pin holds.
	drifted atomic.Bool
}

var _ connector.WriteEndpoint = (*paFakeAlice)(nil)

func (a *paFakeAlice) Server() string { return "alice" }

func (a *paFakeAlice) ListTools(context.Context, connection.Secret) ([][]byte, error) {
	page, err := os.ReadFile(filepath.Join("..", "..", "internal", "pa", "catalog", "testdata", "alice.tools.json"))
	if a.drifted.Load() {
		page = bytes.Replace(page, []byte("Make Alice speak a specific phrase aloud"), []byte("Make Alice speak any phrase aloud"), 1)
	}
	return [][]byte{page}, err
}

func (a *paFakeAlice) CallTool(_ context.Context, _ connection.Secret, tool string, _ json.RawMessage) ([]byte, error) {
	a.mu.Lock()
	a.reads = append(a.reads, tool)
	a.mu.Unlock()
	switch tool {
	case "alice_get_my_identity":
		return []byte(`{"content":[{"type":"text","text":"{}"}],"structuredContent":{"account_id":"acct-carol-0001"}}`), nil
	case "alice_list_devices":
		text := "### Умный дом Яндекса\n\n**Колонки с Алисой (1):**\n" + paKitchenSpeaker + "\n"
		return json.Marshal(map[string]any{"content": []map[string]string{{"type": "text", "text": text}}})
	}
	return []byte(`{"content":[{"type":"text","text":"nothing"}]}`), nil
}

func (a *paFakeAlice) CallToolExact(_ context.Context, _ connection.Secret, tool string, args []byte) ([]byte, error) {
	a.mu.Lock()
	a.exact = append(a.exact, tool+" "+string(args))
	a.mu.Unlock()
	return []byte(`{"content":[{"type":"text","text":"done"}]}`), nil
}

func (a *paFakeAlice) sent() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.exact)
}

// paReadOnlyAlice is an alice endpoint that cannot send approved bytes.
type paReadOnlyAlice struct{ inner *paFakeAlice }

func (a paReadOnlyAlice) Server() string { return "alice" }
func (a paReadOnlyAlice) ListTools(ctx context.Context, s connection.Secret) ([][]byte, error) {
	return a.inner.ListTools(ctx, s)
}
func (a paReadOnlyAlice) CallTool(ctx context.Context, s connection.Secret, tool string, args json.RawMessage) ([]byte, error) {
	return a.inner.CallTool(ctx, s, tool, args)
}

// enablePAAliceEnv is enablePAToolsEnv with alice enabled instead of tg,
// on the same fake authorization server and hosts.
func enablePAAliceEnv(t *testing.T) {
	t.Helper()
	enablePAToolsEnv(t)
	for k, v := range map[string]string{
		"PA_SERVER_TG_ENABLED":                   "false",
		"PA_SERVER_ALICE_ENABLED":                "true",
		"PA_SERVER_ALICE_CLIENT_ID":              paTGClientID,
		"PA_SERVER_ALICE_ALLOWED_HOSTS":          "as.tg.example.test,mcp.tg.example.test",
		"PA_SERVER_ALICE_ISSUER":                 paTGIssuer,
		"PA_SERVER_ALICE_AUTHORIZATION_ENDPOINT": paTGAuthz,
		"PA_SERVER_ALICE_TOKEN_ENDPOINT":         paTGToken,
		"PA_SERVER_ALICE_REVOCATION_ENDPOINT":    paTGRevoke,
		"PA_SERVER_ALICE_MCP_URL":                paTGMCP,
		"PA_SERVER_ALICE_RESOURCE":               paTGMCP,
		"PA_EXTERNAL_TOOLS_ENABLED":              "true",
	} {
		t.Setenv(k, v)
	}
}

// fakePAAliceNet is fakePAServerNet with ep as the alice MCP endpoint.
func fakePAAliceNet(t *testing.T, principal int64, ep connector.MCPEndpoint) *paToolsFakes {
	t.Helper()
	f := fakePAServerNet(t, principal)
	inner := newPAServerNet
	newPAServerNet = func(s config.PAServer) (paServerNet, error) {
		n, err := inner(s)
		if s.Name == connection.ServerAlice {
			n.Endpoint = ep
		}
		return n, err
	}
	return f
}

// paTestGate is an action gate the wiring tests put in (newPAWriteGate):
// it offers every tool it is asked about unless told otherwise. The real
// gate, with its consent and scope checks, is P2-S14c's.
type paTestGate struct {
	mu sync.Mutex
	// only, when set, is what the gate answers instead of everything.
	only     []string
	withheld string
	err      error
	asked    [][]string
}

func (g *paTestGate) Offer(_ context.Context, tx *sql.Tx, principal int64, connectionID string, tools []string) ([]string, string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if tx == nil || principal <= 0 || connectionID == "" {
		return nil, "", errors.New("the gate was asked outside a claim")
	}
	g.asked = append(g.asked, slices.Clone(tools))
	if g.err != nil {
		return nil, "", g.err
	}
	if g.withheld != "" {
		return nil, g.withheld, nil
	}
	if g.only != nil {
		return slices.Clone(g.only), "", nil
	}
	return tools, "", nil
}

func (g *paTestGate) set(f func(*paTestGate)) {
	g.mu.Lock()
	defer g.mu.Unlock()
	f(g)
}

// paShippedGate is newPAWriteGate as the source declares it, kept before
// any test overrides it.
var paShippedGate = newPAWriteGate

// withPAGate wires g as the action gate of every write path the test
// builds.
func withPAGate(t *testing.T, g paWriteGate) {
	t.Helper()
	prev := newPAWriteGate
	newPAWriteGate = func(*db.Store, func() (bool, error)) paWriteGate { return g }
	t.Cleanup(func() { newPAWriteGate = prev })
}

// paPostgresStoreConn is a store on a fresh schema of TEST_DATABASE_URL.
func paPostgresStoreConn(t *testing.T, dsn string) (*db.Store, *sql.DB) {
	t.Helper()
	ctx := context.Background()
	admin, err := db.Open(ctx, dsn, 2, 1)
	if err != nil {
		t.Skipf("postgres not available: %v", err)
	}
	if err := admin.PingContext(ctx); err != nil {
		_ = admin.Close()
		t.Skipf("postgres not available: %v", err)
	}
	schema := fmt.Sprintf("pa_writes_%d", time.Now().UnixNano())
	if _, err := admin.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		_ = admin.Close()
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(`DROP SCHEMA ` + schema + ` CASCADE`)
		_ = admin.Close()
	})
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	conn, err := db.Open(ctx, u.String(), 5, 2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := db.MigrateCached(ctx, conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db.NewStore(conn, nil), conn
}

// forEachPAStore runs fn on SQLite and, with TEST_DATABASE_URL set, on
// Postgres.
func forEachPAStore(t *testing.T, fn func(t *testing.T, store *db.Store, conn *sql.DB)) {
	t.Helper()
	t.Run("sqlite", func(t *testing.T) {
		store, conn := paTestStoreConn(t)
		fn(t, store, conn)
	})
	t.Run("postgres", func(t *testing.T) {
		dsn := os.Getenv("TEST_DATABASE_URL")
		if dsn == "" {
			t.Skip("TEST_DATABASE_URL not set")
		}
		store, conn := paPostgresStoreConn(t, dsn)
		fn(t, store, conn)
	})
}

// paWritesE2E is paE2E on alice, with the worker's side of a run.
type paWritesE2E struct {
	*paE2E
	alice *paFakeAlice
	pool  string
	// gate is the action gate the write path was built with.
	gate *paTestGate
	// connID is Carol's alice connection; token the claimed run's.
	connID string
	token  string
	tools  []string
	// hint is the claim's actions_hint.
	hint string
}

// newPAWritesE2E builds the runtime with PA_WRITES_ENABLED set to writes
// and links Carol's alice account through the OAuth pages.
func newPAWritesE2E(t *testing.T, store *db.Store, conn *sql.DB, writes string) *paWritesE2E {
	t.Helper()
	const carol = 4242003
	e := &paWritesE2E{paE2E: &paE2E{t: t, user: carol, upd: 7000, conn: conn, server: "alice"}, alice: &paFakeAlice{}, gate: &paTestGate{}}
	e.f = fakePAAliceNet(t, carol, e.alice)
	e.sent = recordPASends(t)
	enablePAAliceEnv(t)
	t.Setenv(connector.WritesFlagEnv, writes)
	withPAGate(t, e.gate)
	_, e.rt = buildEnabledPA(t, store)
	e.mux = chi.NewRouter()
	e.rt.Mount(e.mux)

	iss, err := localjwt.NewIssuer([]byte(testPASigningKey), testPABaseURL)
	if err != nil {
		t.Fatal(err)
	}
	e.pool, err = iss.Mint(localjwt.Claims{
		Subject: "pool:main", Audience: []string{localjwt.PoolAudience}, Jti: "pool-jti-writes",
		OriginalIssuedAt: time.Now().Add(-time.Minute).Unix(),
	}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	e.consent()
	card := e.toCard()
	e.press(card.buttons[0])
	if got := e.last().text; got != safetext.ServerText(safetext.TextConnected).String() {
		t.Fatalf("after confirm: %q", got)
	}
	conns, err := e.rt.Connections().List(context.Background(), carol)
	if err != nil || len(conns) != 1 || conns[0].State != connection.StateActive || conns[0].Server != connection.ServerAlice {
		t.Fatalf("connections %+v err %v", conns, err)
	}
	e.connID = conns[0].ID
	return e
}

func (e *paWritesE2E) post(route, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, route, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	e.mux.ServeHTTP(w, req)
	return w
}

// claim sends Carol's message and claims its run as the worker does.
func (e *paWritesE2E) claim() {
	e.t.Helper()
	e.text("tell the kitchen that dinner is ready")
	w := e.post(pa.RouteClaim, e.pool, "")
	var claim struct {
		Token       string   `json:"token"`
		ToolSet     []string `json:"tool_set"`
		ActionsHint string   `json:"actions_hint"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &claim) != nil || claim.Token == "" {
		e.t.Fatalf("claim: %d %s", w.Code, w.Body.String())
	}
	e.token, e.tools, e.hint = claim.Token, claim.ToolSet, claim.ActionsHint
}

type paToolAnswer struct {
	code   int
	Status string `json:"status"`
	Stop   string `json:"stop"`
	raw    string
}

// call posts one tool call of the claimed run.
func (e *paWritesE2E) call(tool, args string) paToolAnswer {
	e.t.Helper()
	body := `{"server":"alice","tool":"` + tool + `","connection_id":"` + e.connID + `","arguments":` + args + `}`
	w := e.post(connector.RouteTool, e.token, body)
	a := paToolAnswer{code: w.Code, raw: w.Body.String()}
	_ = json.Unmarshal(w.Body.Bytes(), &a)
	// A card is queued in the call's transaction and sent after it.
	e.rt.loop.WaitDeliveries()
	return a
}

func (e *paWritesE2E) count(query string, args ...any) int {
	e.t.Helper()
	var n int
	if err := e.conn.QueryRowContext(context.Background(), query, args...).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

// cards are the approval cards sent to Carol: messages with the two
// buttons of a card.
func (e *paWritesE2E) cards() []paSend {
	var out []paSend
	for _, s := range e.sent.get() {
		if s.chat == e.user && len(s.buttons) == 2 && strings.Contains(s.text, "Dinner is ready") {
			out = append(out, s)
		}
	}
	return out
}

// carded claims a run, makes the model's write call and returns the one
// card it produced.
func (e *paWritesE2E) carded() paSend {
	e.t.Helper()
	e.claim()
	if !slices.Contains(e.tools, "alice/"+paSayTool) {
		e.t.Fatalf("writes on: tool set %v has no alice/%s", e.tools, paSayTool)
	}
	if a := e.call(paSayTool, paSaySent); a.code != http.StatusOK || a.Status != connector.StatusApprovalPending {
		e.t.Fatalf("write call: %+v", a)
	}
	cards := e.cards()
	if len(cards) != 1 {
		e.t.Logf("sent: %+v", e.sent.get())
	}
	if len(cards) != 1 || e.count(`SELECT COUNT(*) FROM pa_approvals WHERE principal = $1`, e.user) != 1 {
		e.t.Fatalf("one write call made %d cards: %+v", len(cards), cards)
	}
	if len(e.alice.sent()) != 0 {
		e.t.Fatalf("sent before an approval: %v", e.alice.sent())
	}
	return cards[0]
}

// TestPAWrites_EndToEnd is the write path as the service runs it, with
// PA_WRITES_ENABLED=true: a model's write call yields exactly one card and
// sends nothing; Approve dispatches exactly once, with the approved bytes;
// a second tap dispatches nothing more; Cancel dispatches nothing; and
// with the switch turned off between the card and the tap, the tap
// dispatches nothing.
func TestPAWrites_EndToEnd(t *testing.T) {
	want := []string{paSayTool + " " + paSayCanonical}
	t.Run("approve dispatches once with the approved bytes", func(t *testing.T) {
		forEachPAStore(t, func(t *testing.T, store *db.Store, conn *sql.DB) {
			e := newPAWritesE2E(t, store, conn, "true")
			if e.rt.writes == nil {
				t.Fatal("PA_WRITES_ENABLED=true built no write path")
			}
			card := e.carded()
			// The server's own rule: one card per run (S2-A7).
			if a := e.call(paSayTool, `{"device":"`+paKitchenID+`","phrase":"And again"}`); a.code != http.StatusConflict || a.Stop != connector.ReasonCardAlreadySent {
				t.Fatalf("a second write call of the run: %+v", a)
			}
			if n := e.count(`SELECT COUNT(*) FROM pa_approvals WHERE principal = $1`, e.user); n != 1 {
				t.Fatalf("%d approvals after a second write call", n)
			}
			e.press(card.buttons[0])
			if got := e.alice.sent(); !slices.Equal(got, want) {
				t.Fatalf("after Approve the server got %q, want %q", got, want)
			}
			// A double tap, and a tap on Cancel after the approval.
			e.press(card.buttons[0])
			e.press(card.buttons[1])
			if got := e.alice.sent(); !slices.Equal(got, want) {
				t.Fatalf("after a second tap the server got %q, want %q", got, want)
			}
			// /permissions is wired with the write path.
			e.text("/permissions")
			if got := e.last().text; got == safetext.ServerText(safetext.TextPermissionsUnavailable).String() || got == "" {
				t.Fatalf("/permissions with writes on: %q", got)
			}
		})
	})
	t.Run("a drifted definition gets no card", func(t *testing.T) {
		forEachPAStore(t, func(t *testing.T, store *db.Store, conn *sql.DB) {
			e := newPAWritesE2E(t, store, conn, "true")
			e.text("tell the kitchen dinner is ready")
			e.claim()
			e.alice.drifted.Store(true)
			if a := e.call(paSayTool, paSaySent); a.code == http.StatusOK || len(e.cards()) != 0 {
				t.Fatalf("a drifted tool got a card: %+v %v", a, e.cards())
			}
		})
	})
	t.Run("cancel dispatches nothing", func(t *testing.T) {
		forEachPAStore(t, func(t *testing.T, store *db.Store, conn *sql.DB) {
			e := newPAWritesE2E(t, store, conn, "true")
			card := e.carded()
			e.press(card.buttons[1])
			e.press(card.buttons[0])
			if got := e.alice.sent(); len(got) != 0 {
				t.Fatalf("after Cancel the server got %q", got)
			}
		})
	})
	// The executor reads the server's listing again at dispatch
	// (connector.PinFresh, S2-A5): a definition that changed after the
	// card was sent is not called.
	t.Run("a definition that drifted between the card and the tap", func(t *testing.T) {
		forEachPAStore(t, func(t *testing.T, store *db.Store, conn *sql.DB) {
			e := newPAWritesE2E(t, store, conn, "true")
			card := e.carded()
			e.alice.drifted.Store(true)
			e.press(card.buttons[0])
			if got := e.alice.sent(); len(got) != 0 {
				t.Fatalf("the server got %q", got)
			}
		})
	})
	// Every switch that cuts the write path, turned off (or made
	// unreadable) after the card was sent and before the tap.
	for env, v := range map[string]string{
		connector.WritesFlagEnv:        "false",
		connector.WritesFlagEnv + " ":  "TRUE",
		connector.ExternalToolsFlagEnv: "false",
		"PA_SERVER_ALICE_ENABLED":      "false",
	} {
		env = strings.TrimSpace(env)
		t.Run("off between the card and the tap "+env+"="+v, func(t *testing.T) {
			forEachPAStore(t, func(t *testing.T, store *db.Store, conn *sql.DB) {
				e := newPAWritesE2E(t, store, conn, "true")
				card := e.carded()
				t.Setenv(env, v)
				e.press(card.buttons[0])
				if got := e.alice.sent(); len(got) != 0 {
					t.Fatalf("the server got %q", got)
				}
				// Turning it back on does not revive the tap.
				t.Setenv(env, "true")
				e.press(card.buttons[0])
				if got := e.alice.sent(); len(got) != 0 {
					t.Fatalf("after the switch came back the server got %q", got)
				}
			})
		})
	}
}

// TestPAWrites_OffIsPhase1: with PA_WRITES_ENABLED false, unset or
// unreadable nothing of the write path is built, a claim offers no write
// tool, a forged write call is refused and makes no card, and
// /permissions is not available. An unreadable value is off, never on.
func TestPAWrites_OffIsPhase1(t *testing.T) {
	for _, v := range []string{"false", "", "TRUE", "1", "yes", "on"} {
		t.Run("PA_WRITES_ENABLED="+v, func(t *testing.T) {
			forEachPAStore(t, func(t *testing.T, store *db.Store, conn *sql.DB) {
				e := newPAWritesE2E(t, store, conn, v)
				if e.rt.writes != nil {
					t.Fatalf("PA_WRITES_ENABLED=%q built a write path", v)
				}
				e.claim()
				for _, name := range e.tools {
					if !strings.HasPrefix(name, "alice/alice_get_") && !strings.HasPrefix(name, "alice/alice_list_") {
						t.Fatalf("writes off: the claim offers %s (%v)", name, e.tools)
					}
				}
				a := e.call(paSayTool, paSaySent)
				if a.code == http.StatusOK || a.Status != "" {
					t.Fatalf("a forged write call was answered %+v", a)
				}
				if n := e.count(`SELECT COUNT(*) FROM pa_approvals`); n != 0 || len(e.cards()) != 0 || len(e.alice.sent()) != 0 {
					t.Fatalf("a forged write call left %d approvals, cards %v, calls %v", n, e.cards(), e.alice.sent())
				}
				e.text("/permissions")
				if got := e.last().text; got != safetext.ServerText(safetext.TextPermissionsUnavailable).String() {
					t.Fatalf("/permissions with writes off: %q", got)
				}
			})
		})
	}
}

// TestPAWrites_SwitchOffAtClaim: a built write path offers no write tool
// in a claim made while a switch is off, and refuses the forged call.
func TestPAWrites_SwitchOffAtClaim(t *testing.T) {
	store, conn := paTestStoreConn(t)
	e := newPAWritesE2E(t, store, conn, "true")
	t.Setenv(connector.WritesFlagEnv, "false")
	e.claim()
	if slices.ContainsFunc(e.tools, func(s string) bool { return strings.Contains(s, paSayTool) }) || len(e.tools) == 0 {
		t.Fatalf("PA_WRITES_ENABLED turned off: tool set %v", e.tools)
	}
	if a := e.call(paSayTool, paSaySent); a.code == http.StatusOK {
		t.Fatalf("a forged write call was answered %+v", a)
	}
	if n := e.count(`SELECT COUNT(*) FROM pa_approvals`); n != 0 || len(e.alice.sent()) != 0 {
		t.Fatalf("%d approvals, calls %v", n, e.alice.sent())
	}
}

// TestPAWrites_OfferedByGate is the claim's write tools: only with every
// switch on, and only the listed tools the action gate offers. A gate
// cannot add a tool, a gate that failed is an error, and no gate is none.
func TestPAWrites_OfferedByGate(t *testing.T) {
	ctx := context.Background()
	store, _ := paTestStoreConn(t)
	tx, err := store.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback() })
	const carol = 4242003
	all := []string{"alice/alice_media_control", "alice/alice_say_phrase", "alice/alice_send_command", "alice/alice_set_volume"}
	on := func() connector.Flags {
		return connector.Flags{ExternalTools: true, Writes: true, Servers: map[string]bool{"alice": true}, ServerErrs: map[string]error{}}
	}
	alice := connection.Connection{ID: "c-alice", Server: connection.ServerAlice, State: connection.StateActive, GrantedScope: "iot:view"}
	gate := &paTestGate{}
	w := &paWrites{tools: paWriteTools, gate: gate}
	offered := func(w *paWrites, f connector.Flags, c connection.Connection) ([]string, string) {
		t.Helper()
		got, why, err := w.offered(ctx, tx, f, carol, c)
		if err != nil {
			t.Fatalf("offered: %v", err)
		}
		slices.Sort(got)
		return got, why
	}
	if got, why := offered(w, on(), alice); !slices.Equal(got, all) || why != "" {
		t.Fatalf("a gate that offers everything: %v %q", got, why)
	}
	// The gate is asked about bare tool names, the listed ones.
	if len(gate.asked) != 1 || !slices.Equal(gate.asked[0], paWriteTools[connection.ServerAlice]) {
		t.Fatalf("the gate was asked %v", gate.asked)
	}
	// The gate narrows the list and cannot add to it.
	gate.set(func(g *paTestGate) {
		g.only = []string{paSayTool, "alice_set_light", "alice_list_devices", "tg_send_message"}
	})
	if got, why := offered(w, on(), alice); !slices.Equal(got, []string{"alice/" + paSayTool}) || why != "" {
		t.Fatalf("a gate that offers one tool and three unlisted: %v %q", got, why)
	}
	gate.set(func(g *paTestGate) { g.only = []string{} })
	if got, why := offered(w, on(), alice); len(got) != 0 || why != "" {
		t.Fatalf("a gate that offers nothing: %v %q", got, why)
	}
	gate.set(func(g *paTestGate) { g.only, g.withheld = nil, pa.ActionsHintConsent })
	if got, why := offered(w, on(), alice); len(got) != 0 || why != pa.ActionsHintConsent {
		t.Fatalf("a gate that withholds: %v %q", got, why)
	}
	// A gate that could not be read is an error, never "none".
	gate.set(func(g *paTestGate) { g.withheld, g.err = "", os.ErrDeadlineExceeded })
	if got, why, err := w.offered(ctx, tx, on(), carol, alice); !errors.Is(err, os.ErrDeadlineExceeded) || got != nil || why != "" {
		t.Fatalf("a failed gate: %v %q %v", got, why, err)
	}
	gate.set(func(g *paTestGate) { g.err = nil })

	// Every switch cuts the offer before the gate is asked.
	asked := len(gate.asked)
	for name, f := range map[string]connector.Flags{
		"writes off":         {ExternalTools: true, Servers: map[string]bool{"alice": true}},
		"writes unreadable":  {ExternalTools: true, Writes: true, WritesErr: os.ErrInvalid, Servers: map[string]bool{"alice": true}},
		"external tools off": {Writes: true, Servers: map[string]bool{"alice": true}},
		"server off":         {ExternalTools: true, Writes: true, Servers: map[string]bool{"alice": false, "tg": true}},
		"server unreadable":  {ExternalTools: true, Writes: true, Servers: map[string]bool{"alice": true}, ServerErrs: map[string]error{"alice": os.ErrInvalid}},
	} {
		if got, why := offered(w, f, alice); len(got) != 0 || why != "" {
			t.Errorf("%s: offered %v %q", name, got, why)
		}
	}
	if len(gate.asked) != asked {
		t.Errorf("the gate was asked with a switch off: %v", gate.asked[asked:])
	}
	// No gate: nothing, with every switch on. This is the default.
	if got, why := offered(&paWrites{tools: paWriteTools}, on(), alice); len(got) != 0 || why != "" {
		t.Errorf("no gate: offered %v %q", got, why)
	}
	// No write path: nothing, whatever the switches say.
	if got, why := offered(nil, on(), alice); len(got) != 0 || why != "" {
		t.Errorf("no write path: offered %v %q", got, why)
	}
	// A tg connection has no write tool, and the gate is not asked.
	tg := alice
	tg.Server = connection.ServerTG
	f := on()
	f.Servers["tg"] = true
	if got, _ := offered(w, f, tg); len(got) != 0 || len(gate.asked) != asked {
		t.Errorf("tg: offered %v, gate asked %v", got, gate.asked[asked:])
	}
}

// TestPAWrites_NoGateOffersNothing: the service as it ships. No action
// gate is wired (newPAWriteGate returns none until P2-S14c), so with
// PA_WRITES_ENABLED and every other switch on the write path is built and
// no claim is offered a write tool; a forged call of one is refused and
// leaves nothing.
func TestPAWrites_NoGateOffersNothing(t *testing.T) {
	if g := paShippedGate(nil, nil); g != nil {
		t.Fatalf("a gate is wired by default: %T", g)
	}
	forEachPAStore(t, func(t *testing.T, store *db.Store, conn *sql.DB) {
		e := newPAWritesE2E(t, store, conn, "true")
		if e.rt.writes == nil {
			t.Fatal("no write path")
		}
		e.rt.writes.gate = paShippedGate(store, nil)
		e.claim()
		if slices.ContainsFunc(e.tools, func(s string) bool { return strings.Contains(s, paSayTool) }) || len(e.tools) == 0 || e.hint != "" {
			t.Fatalf("tool set %v hint %q", e.tools, e.hint)
		}
		if a := e.call(paSayTool, paSaySent); a.code == http.StatusOK || a.Status != "" {
			t.Fatalf("a forged write call was answered %+v", a)
		}
		if n := e.count(`SELECT COUNT(*) FROM pa_approvals`); n != 0 || len(e.cards()) != 0 || len(e.alice.sent()) != 0 {
			t.Fatalf("%d approvals, cards %v, calls %v", n, e.cards(), e.alice.sent())
		}
	})
}

// TestPAWrites_GateDecidesTheClaim: what the gate answers inside the
// claim transaction is what the claim signs. A withheld reason of the
// closed set reaches the claim as actions_hint, any other reason does
// not, and a gate that could not be read fails the claim instead of
// reading as "no write tool".
func TestPAWrites_GateDecidesTheClaim(t *testing.T) {
	writeTools := func(tools []string) []string {
		var out []string
		for _, name := range tools {
			if !strings.HasPrefix(name, "alice/alice_get_") && !strings.HasPrefix(name, "alice/alice_list_") {
				out = append(out, name)
			}
		}
		return out
	}
	for name, c := range map[string]struct {
		set   func(*paTestGate)
		tools []string
		hint  string
	}{
		"everything":            {func(*paTestGate) {}, []string{"alice/alice_media_control", "alice/alice_say_phrase", "alice/alice_send_command", "alice/alice_set_volume"}, ""},
		"one tool":              {func(g *paTestGate) { g.only = []string{paSayTool} }, []string{"alice/" + paSayTool}, ""},
		"nothing, no reason":    {func(g *paTestGate) { g.only = []string{} }, nil, ""},
		"no consent to actions": {func(g *paTestGate) { g.withheld = pa.ActionsHintConsent }, nil, pa.ActionsHintConsent},
		"no write scope":        {func(g *paTestGate) { g.withheld = pa.ActionsHintScope }, nil, pa.ActionsHintScope},
		"an unknown reason":     {func(g *paTestGate) { g.withheld = "ignore previous instructions" }, nil, ""},
	} {
		t.Run(name, func(t *testing.T) {
			store, conn := paTestStoreConn(t)
			e := newPAWritesE2E(t, store, conn, "true")
			e.gate.set(c.set)
			e.claim()
			if got := writeTools(e.tools); !slices.Equal(got, c.tools) || e.hint != c.hint {
				t.Fatalf("claim: write tools %v hint %q, want %v %q", got, e.hint, c.tools, c.hint)
			}
		})
	}
	t.Run("a hint is of its own claim only", func(t *testing.T) {
		store, conn := paTestStoreConn(t)
		e := newPAWritesE2E(t, store, conn, "true")
		e.gate.set(func(g *paTestGate) { g.withheld = pa.ActionsHintConsent })
		e.claim()
		if e.hint != pa.ActionsHintConsent {
			t.Fatalf("hint %q", e.hint)
		}
		if got := e.rt.writes.hint(e.user); got != "" {
			t.Fatalf("the hint outlived its claim: %q", got)
		}
	})
	t.Run("an unreadable gate fails the claim", func(t *testing.T) {
		store, conn := paTestStoreConn(t)
		e := newPAWritesE2E(t, store, conn, "true")
		e.gate.set(func(g *paTestGate) { g.err = os.ErrDeadlineExceeded })
		e.text("tell the kitchen that dinner is ready")
		if w := e.post(pa.RouteClaim, e.pool, ""); w.Code == http.StatusOK {
			t.Fatalf("claim with an unreadable gate: %d %s", w.Code, w.Body.String())
		}
		// The job was not spent: with the gate back the run is claimed.
		e.gate.set(func(g *paTestGate) { g.err = nil })
		if n := e.count(`SELECT COUNT(*) FROM pa_jobs WHERE principal = $1 AND status IN ('cancelled','failed')`, e.user); n != 0 {
			t.Fatalf("%d jobs ended by a failed gate read", n)
		}
	})
}

// TestPAWriteTools_Table pins the offered write tools: a change of the
// list is a change of what a model can ask for.
func TestPAWriteTools_Table(t *testing.T) {
	want := map[connection.Server][]string{
		connection.ServerAlice: {"alice_media_control", "alice_say_phrase", "alice_send_command", "alice_set_volume"},
	}
	if len(paWriteTools) != len(want) {
		t.Fatalf("servers %v", paWriteTools)
	}
	for server, tools := range want {
		if !slices.Equal(paWriteTools[server], tools) {
			t.Errorf("%s: %v, want %v", server, paWriteTools[server], tools)
		}
	}
}

// buildPAWritesFor builds the PA runtime with alice enabled on the
// endpoint ep and PA_WRITES_ENABLED set to writes.
func buildPAWritesFor(t *testing.T, ep connector.MCPEndpoint, writes string) (*paRuntime, error) {
	t.Helper()
	fakePAAliceNet(t, 4242003, ep)
	recordPASends(t)
	enablePAAliceEnv(t)
	t.Setenv(connector.WritesFlagEnv, writes)
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	store, _ := paTestStoreConn(t)
	return buildPA(context.Background(), cfg, store, localjwt.NewRevocationCache(store, localjwt.DefaultRevocationCacheTTL), nil)
}

// TestBuildPAWrites_RefusesAHalfWiredStart: with PA_WRITES_ENABLED true a
// missing prerequisite refuses the start; the same configuration with the
// flag false starts, with no write path. The complete configuration
// starts with one.
func TestBuildPAWrites_RefusesAHalfWiredStart(t *testing.T) {
	setTools := func(t *testing.T, tools []string) {
		t.Helper()
		prev := paWriteTools
		paWriteTools = map[connection.Server][]string{connection.ServerAlice: tools}
		t.Cleanup(func() { paWriteTools = prev })
	}
	cases := map[string]struct {
		ep    func() connector.MCPEndpoint
		tools []string
	}{
		"an endpoint that cannot send approved bytes": {ep: func() connector.MCPEndpoint { return paReadOnlyAlice{inner: &paFakeAlice{}} }},
		// alice_set_light needs a light reader and alice_trigger_scenario
		// a scenario reader; neither exists.
		"a tool whose reader is missing":   {tools: []string{"alice_set_light"}},
		"a scenario tool with no reader":   {tools: []string{"alice_trigger_scenario"}},
		"a tool with no card":              {tools: []string{"alice_control_device"}},
		"a tool the Phase 2 pin lacks":     {tools: []string{"alice_open_the_door"}},
		"a read tool listed as a write":    {tools: []string{"alice_list_devices"}},
		"one good tool and one without it": {tools: []string{paSayTool, "alice_set_light"}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			for _, writes := range []string{"true", "false"} {
				if c.tools != nil {
					setTools(t, c.tools)
				}
				var ep connector.MCPEndpoint = &paFakeAlice{}
				if c.ep != nil {
					ep = c.ep()
				}
				rt, err := buildPAWritesFor(t, ep, writes)
				switch {
				case writes == "true" && (err == nil || rt != nil):
					t.Fatalf("writes on: runtime=%v err=%v, want a refused start", rt != nil, err)
				case writes == "false" && (err != nil || rt == nil || rt.writes != nil):
					t.Fatalf("writes off: runtime=%v err=%v, want a start with no write path", rt != nil, err)
				}
			}
		})
	}
	// The complete configuration starts.
	if rt, err := buildPAWritesFor(t, &paFakeAlice{}, "true"); err != nil || rt == nil || rt.writes == nil {
		t.Fatalf("complete configuration: runtime=%v err=%v", rt != nil, err)
	}
}

// TestBuildPAWrites_SealerKey: the approval sealer is keyed by
// ENCRYPTION_KEY, and a key it refuses stops the start.
func TestBuildPAWrites_SealerKey(t *testing.T) {
	ep := &paFakeAlice{}
	fakePAAliceNet(t, 4242003, ep)
	recordPASends(t)
	enablePAAliceEnv(t)
	t.Setenv(connector.WritesFlagEnv, "true")
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	store, _ := paTestStoreConn(t)
	rt, err := buildPA(context.Background(), cfg, store, localjwt.NewRevocationCache(store, localjwt.DefaultRevocationCacheTTL), nil)
	if err != nil || rt == nil || rt.writes == nil {
		t.Fatalf("runtime=%v err=%v", rt != nil, err)
	}
	short := *cfg
	short.EncryptionKey = cfg.EncryptionKey[:len(cfg.EncryptionKey)-1]
	w, err := buildPAWrites(&short, rt.tools, store, nil, pa.NewAllowlist(cfg.PAAllowedPrincipals), nil)
	if err == nil || w != nil {
		t.Fatalf("a short key: writes=%v err=%v, want a refused start", w != nil, err)
	}
}

// TestBuildPAWrites_NoWriteServer: writes on with only tg enabled builds
// no write path and still starts: a server switch is not a crash.
func TestBuildPAWrites_NoWriteServer(t *testing.T) {
	store, _ := paTestStoreConn(t)
	fakePAServerNet(t, 4242003)
	recordPASends(t)
	enablePAToolsEnv(t)
	t.Setenv("PA_EXTERNAL_TOOLS_ENABLED", "true")
	t.Setenv(connector.WritesFlagEnv, "true")
	_, rt := buildEnabledPA(t, store)
	if rt.writes != nil {
		t.Fatal("a write path with no server that has write tools")
	}
}

// TestPAWritesEnabled reads the startup switch: true only for "true", and
// an unreadable switch of either layer is off with its error.
func TestPAWritesEnabled(t *testing.T) {
	for _, c := range []struct {
		ext, writes string
		on, err     bool
	}{
		{"true", "true", true, false},
		{"false", "true", true, false},
		{"", "true", true, false},
		{"true", "false", false, false},
		{"true", "", false, false},
		{"true", "TRUE", false, true},
		{"true", "1", false, true},
		{"true", " true ", true, false},
		{"maybe", "true", false, true},
	} {
		env := map[string]string{connector.ExternalToolsFlagEnv: c.ext, connector.WritesFlagEnv: c.writes}
		on, err := paWritesEnabled(connector.EnvFlags(func(k string) string { return env[k] }))
		if on != c.on || (err != nil) != c.err {
			t.Errorf("external=%q writes=%q: on=%v err=%v, want on=%v err=%v", c.ext, c.writes, on, err, c.on, c.err)
		}
	}
}
