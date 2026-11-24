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
	"github.com/mctlhq/mctl-telegram/internal/pa/convo"
	"github.com/mctlhq/mctl-telegram/internal/pa/output/safetext"
)

// Synthetic speaker, as the structured listing of alice_list_devices
// reports it.
const (
	paKitchenID      = "spk-kitchen-0001"
	paKitchenSpeaker = `{"id":"` + paKitchenID + `","name":"Kitchen speaker","type":"devices.types.smart_speaker.yandex.station","is_speaker":true,"room":"Kitchen","household":"Home"}`
	// paDeskLamp is a light of the same home.
	paDeskLampID = "lamp-desk-0003"
	paDeskLamp   = `{"id":"` + paDeskLampID + `","name":"Desk lamp","type":"devices.types.light","is_speaker":false,"room":"Study","household":"Home"}`
	// paPlayCanonical is the canonical form of the arguments the tests
	// send in another key order: what an approval seals and a dispatch
	// sends. The call is eval A1: "play jazz on the kitchen speaker".
	paPlayCanonical = `{"device":"` + paKitchenID + `","query":"jazz"}`
	paPlaySent      = `{ "query": "jazz", "device": "` + paKitchenID + `" }`
	paPlayTool      = "alice_play_music"
)

// paFakeAlice is the alice MCP endpoint: the committed tools/list of
// mctl-alice, an identity, one speaker and one light, and a record of every approved
// call's exact bytes.
type paFakeAlice struct {
	mu    sync.Mutex
	reads []string
	exact []string
	// drifted makes the listing describe alice_play_music in other words
	// than the pin holds.
	drifted atomic.Bool
	// summary, when set, is the text alice_get_home_summary returns: a
	// read whose content the tests choose.
	summary atomic.Value
}

var _ connector.WriteEndpoint = (*paFakeAlice)(nil)

func (a *paFakeAlice) Server() string { return "alice" }

func (a *paFakeAlice) ListTools(context.Context, connection.Secret) ([][]byte, error) {
	page, err := os.ReadFile(filepath.Join("..", "..", "internal", "pa", "catalog", "testdata", "alice.tools.json"))
	if a.drifted.Load() {
		page = bytes.Replace(page, []byte("Start music on one Yandex Alice smart speaker"), []byte("Start any audio on one Yandex Alice smart speaker"), 1)
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
	case "alice_get_home_summary":
		if text, ok := a.summary.Load().(string); ok {
			out, err := json.Marshal(map[string]any{"content": []map[string]string{{"type": "text", "text": text}}})
			return out, err
		}
	case "alice_list_devices":
		return []byte(`{"content":[{"type":"text","text":"two devices"}],"structuredContent":{"only_speakers":false,"devices":[` + paKitchenSpeaker + `,` + paDeskLamp + `]}}`), nil
	}
	return []byte(`{"content":[{"type":"text","text":"nothing"}]}`), nil
}

func (a *paFakeAlice) CallToolExact(_ context.Context, _ connection.Secret, tool string, args []byte) ([]byte, error) {
	a.mu.Lock()
	a.exact = append(a.exact, tool+" "+string(args))
	a.mu.Unlock()
	return []byte(`{"content":[{"type":"text","text":"done"}]}`), nil
}

// read is every tool read so far, in order.
func (a *paFakeAlice) read() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.reads)
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
// gate, with its consent and scope checks, is pa.ActionGate
// (TestPAWrites_ShippedGate runs it).
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
// and links Carol's alice account through the OAuth pages. The action
// gate is the test's own (paTestGate); the scope table is the compiled
// one.
func newPAWritesE2E(t *testing.T, store *db.Store, conn *sql.DB, writes string) *paWritesE2E {
	t.Helper()
	return newPAWritesE2EGate(t, store, conn, writes, false)
}

// newPAWritesE2EGate is newPAWritesE2E; with shipped, the write path is
// built as the service builds it: the action gate newPAWriteGate returns
// and the compiled scope table.
func newPAWritesE2EGate(t *testing.T, store *db.Store, conn *sql.DB, writes string, shipped bool) *paWritesE2E {
	t.Helper()
	return newPAWritesE2EEnv(t, store, conn, writes, shipped, nil)
}

// newPAWritesE2EEnv is newPAWritesE2EGate with env set over the harness's
// own environment before the runtime is built.
func newPAWritesE2EEnv(t *testing.T, store *db.Store, conn *sql.DB, writes string, shipped bool, env map[string]string) *paWritesE2E {
	t.Helper()
	const carol = 4242003
	e := &paWritesE2E{paE2E: &paE2E{t: t, user: carol, upd: 7000, conn: conn, server: "alice"}, alice: &paFakeAlice{}, gate: &paTestGate{}}
	e.f = fakePAAliceNet(t, carol, e.alice)
	e.sent = recordPASends(t)
	enablePAAliceEnv(t)
	t.Setenv(connector.WritesFlagEnv, writes)
	for k, v := range env {
		t.Setenv(k, v)
	}
	if !shipped {
		withPAGate(t, e.gate)
	}
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
	// Carol accepted the consent to actions (P2-S14c): without it every
	// card and dispatch below is refused action_consent_required.
	tx, err := conn.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AcceptPAActionConsent(context.Background(), tx, carol, convo.ActionConsentVersion,
		convo.ActionConsentTextSHA256For(false), time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
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
	e.text("play jazz on the kitchen speaker")
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
		if s.chat == e.user && len(s.buttons) == 2 && strings.Contains(s.text, "jazz") {
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
	if !slices.Contains(e.tools, "alice/"+paPlayTool) {
		e.t.Fatalf("writes on: tool set %v has no alice/%s", e.tools, paPlayTool)
	}
	if a := e.call(paPlayTool, paPlaySent); a.code != http.StatusOK || a.Status != connector.StatusApprovalPending {
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
	want := []string{paPlayTool + " " + paPlayCanonical}
	t.Run("approve dispatches once with the approved bytes", func(t *testing.T) {
		forEachPAStore(t, func(t *testing.T, store *db.Store, conn *sql.DB) {
			e := newPAWritesE2E(t, store, conn, "true")
			if e.rt.writes == nil {
				t.Fatal("PA_WRITES_ENABLED=true built no write path")
			}
			card := e.carded()
			// The server's own rule: one card per run (S2-A7).
			if a := e.call(paPlayTool, `{"device":"`+paKitchenID+`","query":"blues"}`); a.code != http.StatusConflict || a.Stop != connector.ReasonCardAlreadySent {
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
	t.Run("a grant reads the devices it lists", func(t *testing.T) {
		forEachPAStore(t, func(t *testing.T, store *db.Store, conn *sql.DB) {
			e := newPAWritesE2E(t, store, conn, "true")
			grants := func() int { return e.count(`SELECT COUNT(*) FROM pa_permissions WHERE principal = $1`, e.user) }
			// A device the server does not list: read, and refused.
			reads := len(e.alice.read())
			e.text("/permissions grant alice_set_volume spk-attic-0009 5")
			if s := e.last(); len(s.buttons) != 0 || s.button != "" || grants() != 0 {
				t.Fatalf("a grant for an unlisted device: %+v, %d rows", s, grants())
			}
			// Refused after the listing was read, not for want of a reader.
			if got := e.alice.read(); len(got) != reads+1 || got[len(got)-1] != "alice_list_devices" {
				t.Fatalf("a grant for an unlisted device read %q", got[reads:])
			}
			// The listed speaker, on Carol's write connection: a screen
			// with a button, then one row.
			reads = len(e.alice.read())
			e.text("/permissions grant alice_set_volume " + paKitchenID + " 5")
			screen := e.last()
			if !strings.Contains(screen.text, paKitchenID) || (screen.button == "" && len(screen.buttons) == 0) {
				t.Fatalf("grant screen: %+v", screen)
			}
			if len(e.alice.read()) == reads {
				t.Fatal("the grant read no device listing")
			}
			button := screen.button
			if button == "" {
				button = screen.buttons[0]
			}
			e.press(button)
			if grants() != 1 {
				t.Fatalf("%d permission rows after the press: %+v", grants(), e.last())
			}
		})
	})
	t.Run("a drifted definition gets no card", func(t *testing.T) {
		forEachPAStore(t, func(t *testing.T, store *db.Store, conn *sql.DB) {
			e := newPAWritesE2E(t, store, conn, "true")
			e.text("play jazz on the kitchen speaker")
			e.claim()
			e.alice.drifted.Store(true)
			if a := e.call(paPlayTool, paPlaySent); a.code == http.StatusOK || len(e.cards()) != 0 {
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
				a := e.call(paPlayTool, paPlaySent)
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
	if slices.ContainsFunc(e.tools, func(s string) bool { return strings.Contains(s, paPlayTool) }) || len(e.tools) == 0 {
		t.Fatalf("PA_WRITES_ENABLED turned off: tool set %v", e.tools)
	}
	if a := e.call(paPlayTool, paPlaySent); a.code == http.StatusOK {
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
	all := []string{"alice/alice_media_control", "alice/alice_play_music", "alice/alice_set_light", "alice/alice_set_volume"}
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
		g.only = []string{paPlayTool, "alice_trigger_scenario", "alice_list_devices", "tg_send_message"}
	})
	if got, why := offered(w, on(), alice); !slices.Equal(got, []string{"alice/" + paPlayTool}) || why != "" {
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

// TestPAWrites_NoGateOffersNothing: a write path without an action gate,
// which is what a gate that could not be built leaves (newPAWriteGate).
// With PA_WRITES_ENABLED and every other switch on the write path is
// built and no claim is offered a write tool; a forged call of one is
// refused and leaves nothing.
func TestPAWrites_NoGateOffersNothing(t *testing.T) {
	// A gate that cannot be built is no gate, not a gate that offers.
	if g := paShippedGate(nil, nil); g != nil {
		t.Fatalf("a gate was built over nothing: %T", g)
	}
	forEachPAStore(t, func(t *testing.T, store *db.Store, conn *sql.DB) {
		e := newPAWritesE2E(t, store, conn, "true")
		if e.rt.writes == nil {
			t.Fatal("no write path")
		}
		if g := paShippedGate(store, nil); g != nil {
			t.Fatalf("a gate was built without the writes switch: %T", g)
		}
		e.rt.writes.gate = paShippedGate(store, nil)
		e.claim()
		if slices.ContainsFunc(e.tools, func(s string) bool { return strings.Contains(s, paPlayTool) }) || len(e.tools) == 0 || e.hint != "" {
			t.Fatalf("tool set %v hint %q", e.tools, e.hint)
		}
		if a := e.call(paPlayTool, paPlaySent); a.code == http.StatusOK || a.Status != "" {
			t.Fatalf("a forged write call was answered %+v", a)
		}
		if n := e.count(`SELECT COUNT(*) FROM pa_approvals`); n != 0 || len(e.cards()) != 0 || len(e.alice.sent()) != 0 {
			t.Fatalf("%d approvals, cards %v, calls %v", n, e.cards(), e.alice.sent())
		}
	})
}

// TestPAWrites_ShippedGate is the write path built as the service builds
// it, with the action gate newPAWriteGate returns (pa.ActionGate) and the
// compiled scope table (#1320 P2-S14c): a principal who consented to the
// data flow only is offered no write tool and the claim says the consent
// to actions is missing; with that consent, a connection made for reading
// is offered none and the claim says to connect again; with the consent
// and a write connection the claim carries the write tools that
// connection holds, and no hint.
func TestPAWrites_ShippedGate(t *testing.T) {
	writeTools := func(tools []string) []string {
		var out []string
		for _, name := range tools {
			if !strings.HasPrefix(name, "alice/alice_get_") && !strings.HasPrefix(name, "alice/alice_list_") {
				out = append(out, name)
			}
		}
		return out
	}
	// What a write connection holds under the compiled table: every
	// listed tool.
	held := []string{"alice/alice_media_control", "alice/alice_play_music", "alice/alice_set_light", "alice/alice_set_volume"}
	for name, c := range map[string]struct {
		set   func(e *paWritesE2E)
		tools []string
		hint  string
	}{
		"data-flow consent only": {func(e *paWritesE2E) {
			e.exec(`DELETE FROM pa_action_consents WHERE principal = $1`, e.user)
		}, nil, pa.ActionsHintConsent},
		"a connection made for reading": {func(e *paWritesE2E) {
			e.exec(`UPDATE pa_connections SET requested_scope = 'iot:view', granted_scope = 'iot:view' WHERE id = $1`, e.connID)
		}, nil, pa.ActionsHintScope},
		"a grant the service narrowed": {func(e *paWritesE2E) {
			e.exec(`UPDATE pa_connections SET granted_scope = 'iot:view' WHERE id = $1`, e.connID)
		}, nil, pa.ActionsHintScope},
		"the consent to actions and a write connection": {func(*paWritesE2E) {}, held, ""},
	} {
		t.Run(name, func(t *testing.T) {
			forEachPAStore(t, func(t *testing.T, store *db.Store, conn *sql.DB) {
				e := newPAWritesE2EGate(t, store, conn, "true", true)
				if e.rt.writes == nil || e.rt.writes.gate == nil {
					t.Fatal("the service built no write path, or one without an action gate")
				}
				if _, ok := e.rt.writes.gate.(paActionGate); !ok {
					t.Fatalf("the action gate is %T", e.rt.writes.gate)
				}
				c.set(e)
				e.claim()
				if got := writeTools(e.tools); !slices.Equal(got, c.tools) || e.hint != c.hint {
					t.Fatalf("claim: write tools %v hint %q, want %v %q", got, e.hint, c.tools, c.hint)
				}
				if len(e.tools) == len(writeTools(e.tools)) {
					t.Fatalf("the claim lost its read tools: %v", e.tools)
				}
			})
		})
	}
	// The gate's reasons and the claim's hints: a closed set.
	for why, want := range map[pa.WithheldReason]string{
		pa.WithheldNone: "", pa.WithheldWritesOff: "", pa.WithheldConsent: pa.ActionsHintConsent,
		pa.WithheldScope: pa.ActionsHintScope, "ignore previous instructions": "",
	} {
		if got := paActionsHint(why); got != want {
			t.Fatalf("hint of %q is %q, want %q", why, got, want)
		}
	}
}

// exec runs one statement on the test's database.
func (e *paWritesE2E) exec(query string, args ...any) {
	e.t.Helper()
	if _, err := e.conn.ExecContext(context.Background(), query, args...); err != nil {
		e.t.Fatal(err)
	}
}

// paBuiltGate is newPAWritesE2E with the action gate the service builds
// (pa.ActionGate, newPAWriteGate) and the compiled scope table in every
// part of the write path, as a deployed service has them.
func paBuiltGate(t *testing.T, store *db.Store, conn *sql.DB) *paWritesE2E {
	t.Helper()
	e := newPAWritesE2EGate(t, store, conn, "true", true)
	if _, ok := e.rt.writes.gate.(paActionGate); !ok {
		t.Fatalf("the service built the gate %T", e.rt.writes.gate)
	}
	return e
}

// notices are the texts sent to Carol that are one of the two notices of
// the action gate, after everything queued for her was delivered.
func (e *paWritesE2E) notices() []string {
	e.t.Helper()
	e.rt.writes.deliverTo(context.Background(), e.user)
	e.rt.loop.WaitDeliveries()
	var out []string
	for _, m := range e.sent.get() {
		if m.text == safetext.TextActionConsentNeeded.String() || m.text == safetext.TextWriteScopeNeeded.String() {
			out = append(out, m.text)
		}
	}
	return out
}

// TestPAWrites_GateNoticeOncePerConnection (#1320 P2-S14c): a claim the
// gate leaves without a write tool, for the consent to actions or for the
// connection's scope, also tells the principal what to do, in a fixed
// notice queued in the claim's transaction. It is sent once per
// connection, however many claims the gate answers the same way; a claim
// that carries a write tool queues none.
func TestPAWrites_GateNoticeOncePerConnection(t *testing.T) {
	// again asks the gate as two more claims would, each in a transaction
	// of its own.
	again := func(t *testing.T, e *paWritesE2E, hint string) {
		t.Helper()
		for range 2 {
			tx, err := e.conn.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			got, why, err := e.rt.writes.gate.Offer(context.Background(), tx, e.user, e.connID, []string{"alice_set_volume"})
			if err != nil || len(got) != 0 || why != hint {
				t.Fatalf("asked again: %v %q %v", got, why, err)
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
		}
	}
	for name, c := range map[string]struct {
		set  func(e *paWritesE2E)
		hint string
		kind string
		text string
	}{
		"no consent to actions": {func(e *paWritesE2E) {
			e.exec(`DELETE FROM pa_action_consents WHERE principal = $1`, e.user)
		}, pa.ActionsHintConsent, "action_consent_needed", safetext.TextActionConsentNeeded.String()},
		"a connection made for reading": {func(e *paWritesE2E) {
			read, ok := connection.CanonicalScope(connection.ServerAlice)
			if !ok {
				e.t.Fatal("alice has no read scope")
			}
			e.exec(`UPDATE pa_connections SET requested_scope = $1, granted_scope = $1 WHERE id = $2`, read, e.connID)
		}, pa.ActionsHintScope, "write_scope_needed", safetext.TextWriteScopeNeeded.String()},
	} {
		t.Run(name, func(t *testing.T) {
			forEachPAStore(t, func(t *testing.T, store *db.Store, conn *sql.DB) {
				e := paBuiltGate(t, store, conn)
				c.set(e)
				if got := e.notices(); len(got) != 0 {
					t.Fatalf("notices before any claim: %q", got)
				}
				e.claim()
				if e.hint != c.hint {
					t.Fatalf("hint %q, want %q", e.hint, c.hint)
				}
				again(t, e, c.hint)
				if n := e.count(`SELECT COUNT(*) FROM pa_outbox WHERE principal = $1 AND kind = $2 AND connection_id = $3`, e.user, c.kind, e.connID); n != 1 {
					t.Fatalf("%d %s rows, want one", n, c.kind)
				}
				if got := e.notices(); !slices.Equal(got, []string{c.text}) {
					t.Fatalf("notices %q, want one %q", got, c.text)
				}
			})
		})
	}
	// A reason outside the closed set of hints (here: the gate's own
	// switch reads off) reaches the claim as no hint and queues nothing.
	t.Run("writes off is not a hint", func(t *testing.T) {
		forEachPAStore(t, func(t *testing.T, store *db.Store, conn *sql.DB) {
			e := paBuiltGate(t, store, conn)
			e.exec(`DELETE FROM pa_action_consents WHERE principal = $1`, e.user)
			g := paShippedGate(store, func() (bool, error) { return false, nil })
			if g == nil {
				t.Fatal("no gate was built")
			}
			tx, err := conn.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			got, why, err := g.Offer(context.Background(), tx, e.user, e.connID, []string{"alice_set_volume"})
			if err != nil || len(got) != 0 || why != "" {
				t.Fatalf("writes off: %v %q %v", got, why, err)
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
			if n := e.count(`SELECT COUNT(*) FROM pa_outbox WHERE principal = $1 AND kind IN ('action_consent_needed', 'write_scope_needed')`, e.user); n != 0 {
				t.Fatalf("%d notice rows with writes off", n)
			}
		})
	})
	// A connection that holds some of the listed tools is offered those:
	// the claim carries a write tool, so it carries no hint
	// (paWrites.offered) and the principal gets no notice either.
	t.Run("some tools held queues no notice", func(t *testing.T) {
		forEachPAStore(t, func(t *testing.T, store *db.Store, conn *sql.DB) {
			e := paBuiltGate(t, store, conn)
			tx, err := conn.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			// alice_say_phrase needs a scope no connection holds.
			got, _, err := e.rt.writes.gate.Offer(context.Background(), tx, e.user, e.connID, []string{"alice_say_phrase", "alice_set_volume"})
			if err != nil || !slices.Equal(got, []string{"alice_set_volume"}) {
				t.Fatalf("offered %v %v", got, err)
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
			if n := e.count(`SELECT COUNT(*) FROM pa_outbox WHERE principal = $1 AND kind IN ('action_consent_needed', 'write_scope_needed')`, e.user); n != 0 {
				t.Fatalf("%d notice rows for a claim that carries a write tool", n)
			}
		})
	})
	t.Run("a claim with a write tool queues no notice", func(t *testing.T) {
		forEachPAStore(t, func(t *testing.T, store *db.Store, conn *sql.DB) {
			e := paBuiltGate(t, store, conn)
			e.claim()
			if !slices.Contains(e.tools, "alice/alice_set_volume") || e.hint != "" {
				t.Fatalf("tools %v hint %q", e.tools, e.hint)
			}
			if n := e.count(`SELECT COUNT(*) FROM pa_outbox WHERE principal = $1 AND kind IN ('action_consent_needed', 'write_scope_needed')`, e.user); n != 0 || len(e.notices()) != 0 {
				t.Fatalf("%d notice rows, sent %q", n, e.notices())
			}
		})
	})
}

// TestPAWrites_ConnectAsksForWriteScopeOnlyWithAWritePath (#1320
// P2-S14c): /connect asks the authorization server for the write scopes
// only in a process that has a write path and reads the flag on. A
// service started with writes off asks for the read scopes also after
// the flag turns on, and one started with writes on asks for the read
// scopes as soon as the flag turns off.
func TestPAWrites_ConnectAsksForWriteScopeOnlyWithAWritePath(t *testing.T) {
	const read = ""
	wide, ok := connection.WriteRequestScope(connection.ServerAlice)
	if !ok || wide == read {
		t.Fatalf("alice write request scope %q", wide)
	}
	// reconnect drops Carol's connection and links alice again, and
	// returns the scope the new connection records as asked for: the
	// write set, or nothing for a connection that asked for the read set.
	reconnect := func(e *paWritesE2E) string {
		e.t.Helper()
		e.exec(`DELETE FROM pa_connections WHERE principal = $1`, e.user)
		card := e.toCard()
		e.press(card.buttons[0])
		var asked string
		if err := e.conn.QueryRowContext(context.Background(),
			`SELECT requested_scope FROM pa_connections WHERE principal = $1`, e.user).Scan(&asked); err != nil {
			e.t.Fatal(err)
		}
		return asked
	}
	for name, c := range map[string]struct {
		start, later, want string
	}{
		"write path and flag on":              {"true", "true", wide},
		"write path, flag turned off later":   {"true", "false", read},
		"no write path, flag turned on later": {"false", "true", read},
		"no write path and flag off":          {"false", "false", read},
	} {
		t.Run(name, func(t *testing.T) {
			forEachPAStore(t, func(t *testing.T, store *db.Store, conn *sql.DB) {
				e := newPAWritesE2E(t, store, conn, c.start)
				if built := e.rt.writes != nil; built != (c.start == "true") {
					t.Fatalf("write path built: %v", built)
				}
				t.Setenv(connector.WritesFlagEnv, c.later)
				if got := reconnect(e); got != c.want {
					t.Fatalf("/connect asked for %q, want %q", got, c.want)
				}
			})
		})
	}
}

// TestPAWrites_ConsentCommandShowsActions (#1320 P2-S14c): /consent of
// the built service. With PA_WRITES_ENABLED true it shows the consent to
// actions to a principal who has consented to the data flow only, with a
// button that records it; with the switch off it shows nothing of the
// kind, and the principal's state is what it was.
func TestPAWrites_ConsentCommandShowsActions(t *testing.T) {
	t.Run("writes on", func(t *testing.T) {
		forEachPAStore(t, func(t *testing.T, store *db.Store, conn *sql.DB) {
			e := paBuiltGate(t, store, conn)
			e.exec(`DELETE FROM pa_action_consents WHERE principal = $1`, e.user)
			e.text("/consent")
			prompt := e.last()
			if prompt.text != convo.ActionConsentText || prompt.button == "" {
				t.Fatalf("/consent sent %q with button %q", prompt.text, prompt.button)
			}
			e.press(prompt.button)
			if n := e.count(`SELECT COUNT(*) FROM pa_action_consents WHERE principal = $1 AND state = 'accepted' AND version = $2 AND text_sha256 = $3`,
				e.user, convo.ActionConsentVersion, convo.ActionConsentTextSHA256For(false)); n != 1 {
				t.Fatalf("%d accepted consents to actions after the press", n)
			}
			e.claim()
			if !slices.Contains(e.tools, "alice/alice_set_volume") || e.hint != "" {
				t.Fatalf("after accepting: tools %v hint %q", e.tools, e.hint)
			}
		})
	})
	// A service started with writes off has no write path until it
	// restarts: the flag turned on later does not make /consent ask for a
	// consent to actions this process cannot carry out.
	t.Run("no write path, flag turned on later", func(t *testing.T) {
		forEachPAStore(t, func(t *testing.T, store *db.Store, conn *sql.DB) {
			e := newPAWritesE2E(t, store, conn, "false")
			if e.rt.writes != nil {
				t.Fatal("a write path was built with writes off")
			}
			e.exec(`DELETE FROM pa_action_consents WHERE principal = $1`, e.user)
			t.Setenv(connector.WritesFlagEnv, "true")
			e.text("/consent")
			for _, m := range e.sent.get() {
				if m.text == convo.ActionConsentText || m.text == convo.ActionConsentTextRU {
					t.Fatal("/consent offered the consent to actions with no write path")
				}
			}
		})
	})
	// Turning the flag off is read at once, with the write path built.
	t.Run("flag turned off later", func(t *testing.T) {
		forEachPAStore(t, func(t *testing.T, store *db.Store, conn *sql.DB) {
			e := paBuiltGate(t, store, conn)
			e.exec(`DELETE FROM pa_action_consents WHERE principal = $1`, e.user)
			t.Setenv(connector.WritesFlagEnv, "false")
			before := len(e.sent.get())
			e.text("/consent")
			for _, m := range e.sent.get()[before:] {
				if m.text == convo.ActionConsentText || m.text == convo.ActionConsentTextRU {
					t.Fatal("/consent offered the consent to actions after the flag was turned off")
				}
			}
		})
	})
	t.Run("writes off", func(t *testing.T) {
		forEachPAStore(t, func(t *testing.T, store *db.Store, conn *sql.DB) {
			e := newPAWritesE2E(t, store, conn, "false")
			e.exec(`DELETE FROM pa_action_consents WHERE principal = $1`, e.user)
			e.text("/consent")
			for _, m := range e.sent.get() {
				if m.text == convo.ActionConsentText || m.text == convo.ActionConsentTextRU {
					t.Fatal("/consent showed the consent to actions with writes off")
				}
			}
			if n := e.count(`SELECT COUNT(*) FROM pa_action_consents WHERE principal = $1`, e.user); n != 0 {
				t.Fatalf("%d consent-to-actions rows with writes off", n)
			}
		})
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
		"everything":            {func(*paTestGate) {}, []string{"alice/alice_media_control", "alice/alice_play_music", "alice/alice_set_light", "alice/alice_set_volume"}, ""},
		"one tool":              {func(g *paTestGate) { g.only = []string{paPlayTool} }, []string{"alice/" + paPlayTool}, ""},
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
		e.text("play jazz on the kitchen speaker")
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
		connection.ServerAlice: {"alice_media_control", "alice_play_music", "alice_set_light", "alice_set_volume"},
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
		// alice_trigger_scenario needs a reader of scenario steps; none
		// exists.
		"a tool whose reader is missing": {tools: []string{"alice_trigger_scenario"}},
		"a tool with no card":            {tools: []string{"alice_control_device"}},
		"a tool the Phase 2 pin lacks":   {tools: []string{"alice_open_the_door"}},
		"a read tool listed as a write":  {tools: []string{"alice_list_devices"}},
		// In the pin, with a card path, behind a scope no write
		// connection asks for.
		"a tool no connection can hold":    {tools: []string{"alice_say_phrase"}},
		"one good tool and one without it": {tools: []string{paPlayTool, "alice_trigger_scenario"}},
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
