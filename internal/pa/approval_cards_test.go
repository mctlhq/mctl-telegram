package pa_test

// Acceptance tests of approval cards (#1320 slice P2-S5): the tool route
// emitting a card instead of calling an approve-tier tool
// (connector.Cards), the card as the bot sends it, and its Approve and
// Cancel buttons through the webhook into the write executor. Real approval
// ledger, callbacks, outbox, run loop, conversations and executor, on
// SQLite and, with TEST_DATABASE_URL, on Postgres.
//
// Two things are injected here because no production wiring has them yet:
// a pin with an approve-tier tool (production loads the Phase 1 pin, which
// has none), and the admission of that tool into the run (cardJobs): the
// run loop admits only Phase 1 reads until P2-S13 and P2-S14.
//
// Threat model rows: S2-X5 (T4), S2-A7 and S2-A10 (T7), the card half of
// S2-D7 (T5), T10 (the 4 KiB card), T14 (plain text, server keyboard).

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"database/sql"

	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/pa"
	"github.com/mctlhq/mctl-telegram/internal/pa/approval"
	"github.com/mctlhq/mctl-telegram/internal/pa/catalog"
	"github.com/mctlhq/mctl-telegram/internal/pa/connector"
	"github.com/mctlhq/mctl-telegram/internal/pa/jobs"
	"github.com/mctlhq/mctl-telegram/internal/pa/output/safetext"
)

// cardPin is a pin whose tg server has one approve-tier write next to a
// read. It stands in for the pin the write path will run on.
func cardPin() *catalog.Pin {
	return &catalog.Pin{Servers: map[string]catalog.ServerPin{"tg": {Tools: map[string]catalog.PinnedTool{
		writeTool: {
			Tier: catalog.TierApprove, Class: catalog.ClassWrite, Lowerable: catalog.LowerableNever,
			InputSchema: json.RawMessage(`{"type":"object","properties":{"text":{"type":"string"},"to":{"type":"string"}}}`),
		},
		"get_messages": {Tier: catalog.TierAuto, Class: catalog.ClassRead},
	}}}}
}

// cardJobs admits the approve-tier tool into a run by the run loop's own
// admission of a read of the job's set, so the ledger checks and the call
// counter are the real ones.
type cardJobs struct {
	*failingJobs
}

func (c *cardJobs) AdmitToolCall(ctx context.Context, j pa.PAJob, server, tool string) (pa.Policy, error) {
	if server == "tg" && tool == writeTool {
		return c.failingJobs.AdmitToolCall(ctx, j, "tg", "get_messages")
	}
	return c.failingJobs.AdmitToolCall(ctx, j, server, tool)
}

// cardStore fails the card's outbox insert while failCard is set.
type cardStore struct {
	*db.Store
	failCard atomic.Bool
}

func (c *cardStore) EnqueuePAOutbox(ctx context.Context, tx *sql.Tx, item jobs.OutboxItem, now time.Time) error {
	if c.failCard.Load() && item.Kind == jobs.OutboxApprovalCard {
		return errors.New("injected outbox failure")
	}
	return c.Store.EnqueuePAOutbox(ctx, tx, item, now)
}

type cardEnv struct {
	*writeEnv
	cstore *cardStore
	cards  *connector.Cards
	token  string

	mu       sync.Mutex
	approved []string
	outcomes []connector.WriteOutcome
}

// newCardEnv is a write env whose dispatcher emits cards, whose bot sends
// them and whose webhook handles their buttons. Alice's run is claimed.
func newCardEnv(t *testing.T, s *db.Store) *cardEnv {
	t.Helper()
	e := &cardEnv{writeEnv: newWriteEnv(t, s, nil), cstore: &cardStore{Store: s}}
	var code int
	if e.token, _, _, code = e.h.Claim(); code != http.StatusOK || e.token == "" {
		t.Fatalf("claim: %d", code)
	}
	var err error
	e.cards, err = connector.NewCards(connector.CardConfig{
		Store: e.cstore, Sealer: e.sealer, Pin: cardPin(), Fresh: e.fresh, Now: e.h.Now,
		Deliver: func(ctx context.Context, p int64) { e.h.Loop().DeliverAfter(ctx, p) },
	})
	if err != nil {
		t.Fatal(err)
	}
	e.reconfigure(func(c *connector.DispatcherConfig) {
		c.Cards = e.cards
		c.Jobs = &cardJobs{failingJobs: e.jobs}
	})
	e.h.EnableApprovalCards(e.cards, s, func(ctx context.Context, principal int64, id string) {
		out, err := e.x.DispatchApproved(ctx, principal, id)
		if err != nil {
			t.Errorf("dispatch approved: %v", err)
		}
		e.mu.Lock()
		e.approved = append(e.approved, id)
		e.outcomes = append(e.outcomes, out)
		e.mu.Unlock()
	})
	return e
}

func writeCall(args string) string {
	return `{"server":"tg","tool":"` + writeTool + `","arguments":` + args + `}`
}

type cardRow struct {
	id, status, approve, cancel string
	created, expires            int64
}

func (e *cardEnv) approvals(principal int64) []cardRow {
	e.t.Helper()
	rows, err := e.store.DB.Query(`SELECT id, status, approve_cb_id, cancel_cb_id, created_at_ms, expires_at_ms
		FROM pa_approvals WHERE principal = $1 ORDER BY created_at_ms, id`, principal)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []cardRow
	for rows.Next() {
		var r cardRow
		if err := rows.Scan(&r.id, &r.status, &r.approve, &r.cancel, &r.created, &r.expires); err != nil {
			e.t.Fatal(err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		e.t.Fatal(err)
	}
	return out
}

// emit sends the write call and returns the one pending approval it made.
func (e *cardEnv) emit(args string) cardRow {
	e.t.Helper()
	before := len(e.approvals(alice))
	a := e.call(e.token, writeCall(args))
	if a.code != http.StatusOK || a.Status != connector.StatusApprovalPending {
		e.t.Fatalf("answer %+v", a)
	}
	rows := e.approvals(alice)
	if len(rows) != before+1 || rows[len(rows)-1].status != "pending" {
		e.t.Fatalf("approvals after the call: %+v", rows)
	}
	return rows[len(rows)-1]
}

func (e *cardEnv) cardCallbacks(principal int64) []string {
	return e.strings(`SELECT action FROM pa_callbacks WHERE principal = $1 AND action LIKE 'approval%' ORDER BY action`, principal)
}

func (e *cardEnv) cardRows() []string {
	return e.strings(`SELECT status FROM pa_outbox WHERE kind = 'approval_card' ORDER BY id`)
}

// nothingWritten asserts the refused call left no approval, callback or
// card and reached no server.
func (e *cardEnv) nothingWritten() {
	e.t.Helper()
	if rows := e.approvals(alice); len(rows) != 0 {
		e.t.Fatalf("approval rows: %+v", rows)
	}
	if cbs := e.cardCallbacks(alice); len(cbs) != 0 {
		e.t.Fatalf("callbacks: %v", cbs)
	}
	if rows := e.cardRows(); len(rows) != 0 {
		e.t.Fatalf("card rows: %v", rows)
	}
	e.noCalls()
}

func (e *cardEnv) noCalls() {
	e.t.Helper()
	if sent := e.ep.sent(); len(sent) != 0 {
		e.t.Fatalf("the write was called %d times", len(sent))
	}
	if calls, _, _ := e.tg.snapshot(); len(calls) != 0 {
		e.t.Fatalf("a tool was called: %v", calls)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.approved) != 0 {
		e.t.Fatalf("the executor was handed %v", e.approved)
	}
}

func (e *cardEnv) lastReply(user int64) pa.Reply {
	r := e.h.Replies(user)
	if len(r) == 0 {
		return ""
	}
	return r[len(r)-1]
}

// press presses data as user and returns the reply it queued, "" if none.
func (e *cardEnv) press(user int64, data string) pa.Reply {
	e.t.Helper()
	before := len(e.h.Replies(user))
	if code := e.h.Press(user, data); code != http.StatusOK {
		e.t.Fatalf("press: %d", code)
	}
	after := e.h.Replies(user)
	if len(after) == before {
		return ""
	}
	if len(after) != before+1 {
		e.t.Fatalf("press queued %d replies", len(after)-before)
	}
	return after[len(after)-1]
}

func (e *cardEnv) handed() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.approved)
}

// cards returns the messages to chat that carry a keyboard.
func (e *cardEnv) sentCards(chat int64) []pa.SentCard {
	var out []pa.SentCard
	for _, m := range e.h.MessagesTo(chat) {
		if len(m.Buttons) != 0 {
			out = append(out, m)
		}
	}
	return out
}

// TestApprovalCard_Emitted: a call of an approve-tier tool makes no
// downstream call. One approval with the arguments sealed, its two
// callbacks and the card are written; the call counts toward the run's cap;
// the card is one plain message with the tool, the exact arguments and
// exactly two buttons carrying opaque ids.
func TestApprovalCard_Emitted(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newCardEnv(t, s)
		row := e.emit(writeArgs)
		e.noCalls()
		if n := e.toolCalls(e.job); n != 1 {
			t.Fatalf("tool_calls = %d, want the card call counted", n)
		}
		if got := time.Duration(row.expires-row.created) * time.Millisecond; got != 5*time.Minute {
			t.Fatalf("approval lives %v, want 5m", got)
		}
		if got := e.cardCallbacks(alice); !slices.Equal(got, []string{pa.ActionApprovalApprove, pa.ActionApprovalCancel}) {
			t.Fatalf("callbacks %v", got)
		}
		for _, id := range []string{row.approve, row.cancel} {
			var exp int64
			if err := s.DB.QueryRow(`SELECT expires_at_ms FROM pa_callbacks WHERE principal = $1 AND id = $2`, alice, id).Scan(&exp); err != nil {
				t.Fatal(err)
			}
			if exp != row.expires {
				t.Fatalf("callback expires at %d, approval at %d", exp, row.expires)
			}
			if len(id) == 0 || len(id) > 64 || id == row.id || strings.Contains(id, row.id) {
				t.Fatalf("callback id %q is not an opaque id of at most 64 bytes", id)
			}
		}
		if row.approve == row.cancel {
			t.Fatal("one id for both buttons")
		}
		// The arguments are in the row, sealed: not readable from it.
		var sealed []byte
		if err := s.DB.QueryRow(`SELECT sealed_args FROM pa_approvals WHERE principal = $1 AND id = $2`, alice, row.id).Scan(&sealed); err != nil {
			t.Fatal(err)
		}
		if len(sealed) == 0 || strings.Contains(string(sealed), "Carol") {
			t.Fatalf("sealed_args: %d bytes, plain text inside: %v", len(sealed), strings.Contains(string(sealed), "Carol"))
		}

		cards := e.sentCards(alice)
		if len(cards) != 1 {
			t.Fatalf("%d cards sent: %+v", len(cards), e.h.MessagesTo(alice))
		}
		c := cards[0]
		want := safetext.TextCardHead.String() + "\n\n" + safetext.TextCardAction.String() + "\n" + writeTool + " (tg)\n\n" +
			safetext.TextCardArgs.String() + "\n" + writeArgs + "\n\n" + safetext.TextCardFoot.String()
		if c.Text != want {
			t.Fatalf("card text:\n got %q\nwant %q", c.Text, want)
		}
		wantKB := [][][2]string{{{"Approve", row.approve}, {"Cancel", row.cancel}}}
		if len(c.Buttons) != 1 || !slices.Equal(c.Buttons[0], wantKB[0]) {
			t.Fatalf("keyboard %v, want %v", c.Buttons, wantKB)
		}
		if got := e.cardRows(); !slices.Equal(got, []string{"sent"}) {
			t.Fatalf("card rows %v", got)
		}
		if bob := e.h.MessagesTo(bob); len(bob) != 0 {
			t.Fatalf("Bob was sent %+v", bob)
		}
	})
}

// TestApprovalCard_CountsTowardTheCallCap: card calls use the run's call
// budget like any call, so a run cannot ask for more cards than calls.
func TestApprovalCard_CountsTowardTheCallCap(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newCardEnv(t, s)
		max := jobs.DefaultLimits().MaxToolCalls
		for range max {
			e.emit(writeArgs)
		}
		a := e.call(e.token, writeCall(writeArgs))
		if a.code != http.StatusConflict || a.Stop != connector.ReasonToolCap {
			t.Fatalf("call over the cap: %+v", a)
		}
		if n := len(e.approvals(alice)); n != max {
			t.Fatalf("%d approvals, want %d", n, max)
		}
		e.noCalls()
	})
}

// TestApprovalCard_OutboxFailureLeavesNoApproval: the approval, its
// callbacks and the card commit together or not at all.
func TestApprovalCard_OutboxFailureLeavesNoApproval(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newCardEnv(t, s)
		e.cstore.failCard.Store(true)
		a := e.call(e.token, writeCall(writeArgs))
		if a.code != http.StatusInternalServerError || a.Stop != connector.ReasonInternal {
			t.Fatalf("answer %+v", a)
		}
		e.nothingWritten()
		if cards := e.sentCards(alice); len(cards) != 0 {
			t.Fatalf("a card was sent: %+v", cards)
		}
		// The same call works once the outbox does.
		e.cstore.failCard.Store(false)
		e.emit(writeArgs)
	})
}

// TestApprovalCard_TooLargeIsRefused: arguments over 4 KiB, or a card that
// does not fit one message, get no card and no approval. Nothing is shown
// cut.
func TestApprovalCard_TooLargeIsRefused(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newCardEnv(t, s)
		frame := len(`{"text":"","to":"Carol"}`)
		over := `{"text":"` + strings.Repeat("a", connector.MaxCardArgsBytes-frame+1) + `","to":"Carol"}`
		if len(over) != connector.MaxCardArgsBytes+1 {
			t.Fatalf("fixture is %d bytes", len(over))
		}
		// 4 KiB is counted in bytes: Cyrillic text of half as many
		// characters is over it while it would still fit one message.
		cyr := `{"text":"` + strings.Repeat("ж", (connector.MaxCardArgsBytes-frame)/2+1) + `","to":"Carol"}`
		if len(cyr) <= connector.MaxCardArgsBytes || safetext.UTF16Len(cyr) > 2200 {
			t.Fatalf("fixture is %d bytes, %d UTF-16 units", len(cyr), safetext.UTF16Len(cyr))
		}
		for name, args := range map[string]string{
			"one byte over 4 KiB":            over,
			"over 4 KiB, within one message": cyr,
			// Within 4 KiB of arguments, but the message would not hold
			// them with the card's own text.
			"over one message": over[:len(over)-3] + `"}`,
		} {
			a := e.call(e.token, writeCall(args))
			if a.code != http.StatusRequestEntityTooLarge || a.Stop != connector.ReasonCardTooLarge {
				t.Fatalf("%s: answer %+v", name, a)
			}
		}
		e.nothingWritten()
		if n := e.fresh.asked(); n != 0 {
			t.Fatalf("tools/list read %d times for a call that gets no card", n)
		}
		// A long text that fits is shown whole.
		long := `{"text":"` + strings.Repeat("b", 3000) + `","to":"Carol"}`
		e.emit(long)
		cards := e.sentCards(alice)
		if len(cards) != 1 || !strings.Contains(cards[0].Text, long) {
			t.Fatalf("the 3000 character card: %d cards", len(cards))
		}
	})
}

// TestApprovalCard_Refusals: no card while writes are off or their switch
// is unreadable, for arguments the tool does not declare, for a value the
// card cannot show exactly, and when the fresh listing differs.
func TestApprovalCard_Refusals(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newCardEnv(t, s)
		on := *e.flags.Load()

		off := on
		off.Writes = false
		e.flags.Store(&off)
		if a := e.call(e.token, writeCall(writeArgs)); a.code != http.StatusForbidden || a.Stop != connector.ReasonWritesOff {
			t.Fatalf("writes off: %+v", a)
		}
		unreadable := on
		unreadable.WritesErr = errors.New("injected flag read error")
		e.flags.Store(&unreadable)
		if a := e.call(e.token, writeCall(writeArgs)); a.code != http.StatusForbidden || a.Stop != connector.ReasonWritesOff {
			t.Fatalf("writes unreadable: %+v", a)
		}
		if n := e.fresh.asked(); n != 0 {
			t.Fatalf("tools/list read %d times with writes off", n)
		}
		e.flags.Store(&on)

		if a := e.call(e.token, writeCall(`{"text":"x","to":"Carol","silent":true}`)); a.code != http.StatusBadRequest || a.Stop != connector.ReasonBadRequest {
			t.Fatalf("undeclared argument: %+v", a)
		}
		if a := e.call(e.token, writeCall("{\"text\":\"x‮y\",\"to\":\"Carol\"}")); a.code != http.StatusUnprocessableEntity || a.Stop != connector.ReasonCardUnshowable {
			t.Fatalf("bidi override in an argument: %+v", a)
		}

		e.fresh.mu.Lock()
		e.fresh.err = catalog.ErrToolChanged
		e.fresh.mu.Unlock()
		if a := e.call(e.token, writeCall(writeArgs)); a.code != http.StatusForbidden || a.Stop != connector.ReasonToolChanged {
			t.Fatalf("changed tool: %+v", a)
		}
		e.fresh.mu.Lock()
		e.fresh.err = nil
		e.fresh.tool.Tier = catalog.TierAuto
		e.fresh.mu.Unlock()
		if a := e.call(e.token, writeCall(writeArgs)); a.code != http.StatusForbidden || a.Stop != connector.ReasonToolChanged {
			t.Fatalf("tier changed: %+v", a)
		}
		e.nothingWritten()
	})
}

// TestApprovalCard_NoFreshSurface: without a fresh tools/list there is
// nothing to bind the approval to, so no card.
func TestApprovalCard_NoFreshSurface(t *testing.T) {
	e := newCardEnv(t, sqliteStore(t))
	cards, err := connector.NewCards(connector.CardConfig{Store: e.cstore, Sealer: e.sealer, Pin: cardPin(), Now: e.h.Now})
	if err != nil {
		t.Fatal(err)
	}
	e.reconfigure(func(c *connector.DispatcherConfig) { c.Cards = cards })
	if a := e.call(e.token, writeCall(writeArgs)); a.code != http.StatusForbidden || a.Stop != connector.ReasonNoWritePath {
		t.Fatalf("answer %+v", a)
	}
	e.nothingWritten()
}

// TestApprovalCard_WithoutCardsTheRouteIsPhase1: with no card emitter, as
// in every deployed wiring, the write tool is what it was: not in the
// run's set, refused, nothing written.
func TestApprovalCard_WithoutCardsTheRouteIsPhase1(t *testing.T) {
	e := newCardEnv(t, sqliteStore(t))
	e.reconfigure(func(c *connector.DispatcherConfig) {
		c.Cards = nil
		c.Jobs = e.jobs
	})
	if a := e.call(e.token, writeCall(writeArgs)); a.code == http.StatusOK || a.Status != "" {
		t.Fatalf("answer %+v", a)
	}
	e.nothingWritten()
}

// TestApprovalCard_CoversOnlyApproveTier: the card path takes exactly the
// approve-tier tools of its pin. On the Phase 1 pin, the one production
// loads, that is no tool at all.
func TestApprovalCard_CoversOnlyApproveTier(t *testing.T) {
	sealer, err := approval.NewSealer(writeMasterKey)
	if err != nil {
		t.Fatal(err)
	}
	p1, err := catalog.LoadPin()
	if err != nil {
		t.Fatal(err)
	}
	p2, err := catalog.LoadPinPhase2()
	if err != nil {
		t.Fatal(err)
	}
	for name, pin := range map[string]*catalog.Pin{"phase 1": p1, "phase 2": p2} {
		cards, err := connector.NewCards(connector.CardConfig{Store: &cardStore{}, Sealer: sealer, Pin: pin})
		if err != nil {
			t.Fatal(err)
		}
		covered := 0
		for server, sp := range pin.Servers {
			for tool, pt := range sp.Tools {
				if got, want := cards.Covers(server, tool), pt.Tier == catalog.TierApprove; got != want {
					t.Errorf("%s: Covers(%s, %s) = %v, tier %q", name, server, tool, got, pt.Tier)
				}
				if cards.Covers(server, tool) {
					covered++
				}
			}
		}
		if name == "phase 1" && covered != 0 {
			t.Errorf("the Phase 1 pin has %d card tools", covered)
		}
		if name == "phase 2" && covered == 0 {
			t.Error("the Phase 2 pin has no card tool: the test checks nothing")
		}
		if cards.Covers("tg", "no_such_tool") || cards.Covers("no_such_server", writeTool) {
			t.Errorf("%s: an unpinned tool is covered", name)
		}
	}
}

// TestApprovalCard_TaintedConversationIsFlagged: once external content
// entered the conversation, the card says its values may come from it.
func TestApprovalCard_TaintedConversationIsFlagged(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newCardEnv(t, s)
		e.emit(writeArgs)
		// A tool result is external content.
		if a := e.call(e.token, req("tg", "get_messages", "")); a.code != http.StatusOK {
			t.Fatalf("read: %+v", a)
		}
		e.emit(`{"text":"second","to":"Carol"}`)
		cards := e.sentCards(alice)
		if len(cards) != 2 {
			t.Fatalf("%d cards", len(cards))
		}
		warn := safetext.TextCardExternal.String()
		if strings.Contains(cards[0].Text, warn) {
			t.Fatal("the card of a clean conversation carries the external-content warning")
		}
		if !strings.Contains(cards[1].Text, warn) {
			t.Fatalf("the card of a tainted conversation has no warning: %q", cards[1].Text)
		}
	})
}

// TestApprovalCard_RussianCard: the card a Russian chat gets is the
// Russian frame around the same values.
func TestApprovalCard_RussianCard(t *testing.T) {
	e := newCardEnv(t, sqliteStore(t))
	row := e.emit(writeArgs)
	card, err := e.cards.RenderApprovalCard(context.Background(), alice, row.approve)
	if err != nil {
		t.Fatal(err)
	}
	ru := card.Text.In(safetext.LangRU).String()
	want := safetext.TextCardHead.In(safetext.LangRU) + "\n\n" + safetext.TextCardAction.In(safetext.LangRU) + "\n" + writeTool + " (tg)\n\n" +
		safetext.TextCardArgs.In(safetext.LangRU) + "\n" + writeArgs + "\n\n" + safetext.TextCardFoot.In(safetext.LangRU)
	if ru != want || ru == card.Text.In(safetext.LangEN).String() {
		t.Fatalf("Russian card:\n got %q\nwant %q", ru, want)
	}
	for _, b := range pa.ApprovalCardButtons() {
		if b.Label.In(safetext.LangRU) == "" || b.Label.In(safetext.LangRU) == b.Label.In(safetext.LangEN) {
			t.Errorf("button %q has no Russian label", b.Label.String())
		}
	}
}

// TestApprovalCard_RenderIsPerPrincipal: the deliverer builds a card only
// for the principal the approval belongs to, and only while it is pending.
func TestApprovalCard_RenderIsPerPrincipal(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newCardEnv(t, s)
		row := e.emit(writeArgs)
		ctx := context.Background()
		if _, err := e.cards.RenderApprovalCard(ctx, bob, row.approve); !errors.Is(err, pa.ErrCardGone) {
			t.Fatalf("Bob's render of Alice's card: %v", err)
		}
		// The Cancel id does not name the card either.
		if _, err := e.cards.RenderApprovalCard(ctx, alice, row.cancel); !errors.Is(err, pa.ErrCardGone) {
			t.Fatalf("render by the cancel id: %v", err)
		}
		if got := e.press(alice, row.cancel); got != pa.ReplyApprovalCancelled {
			t.Fatalf("cancel: %q", got)
		}
		if _, err := e.cards.RenderApprovalCard(ctx, alice, row.approve); !errors.Is(err, pa.ErrCardGone) {
			t.Fatalf("render of a cancelled approval: %v", err)
		}
	})
}

// TestApprovalCard_StaleCardIsNotSent: a card that could not be sent until
// its buttons were about to stop working is dropped, not sent late.
func TestApprovalCard_StaleCardIsNotSent(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newCardEnv(t, s)
		e.h.FailSends(errors.New("injected send failure"))
		e.emit(writeArgs)
		if cards := e.sentCards(alice); len(cards) != 0 {
			t.Fatalf("sent through a failing sender: %+v", cards)
		}
		e.h.FailSends(nil)
		e.h.Advance(4*time.Minute + 30*time.Second)
		e.h.DeliverNow(alice)
		if cards := e.sentCards(alice); len(cards) != 0 {
			t.Fatalf("a card with 30 seconds left was sent: %+v", cards)
		}
		if got := e.cardRows(); !slices.Equal(got, []string{"dropped"}) {
			t.Fatalf("card rows %v, want dropped", got)
		}
	})
}

// TestS2D7_CardShowsTheBytesThatAreSent: the card is built from the sealed
// arguments of the approval row, and the executor sends those same bytes:
// what the principal read on the card is what the server receives.
func TestS2D7_CardShowsTheBytesThatAreSent(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newCardEnv(t, s)
		// The worker's spelling differs from the canonical form (key order,
		// spacing, an escaped character); the card and the call both use
		// the canonical bytes.
		row := e.emit(`{ "to": "Carol", "text": "<b>1 & 2</b>" }`)
		cards := e.sentCards(alice)
		if len(cards) != 1 {
			t.Fatalf("%d cards", len(cards))
		}
		if got := e.press(alice, row.approve); got != "" {
			t.Fatalf("approve queued the reply %q", got)
		}
		sent := e.ep.sent()
		if len(sent) != 1 {
			t.Fatalf("%d calls", len(sent))
		}
		if string(sent[0]) != writeArgs {
			t.Fatalf("sent %q, want the canonical %q", sent[0], writeArgs)
		}
		lines := strings.Split(cards[0].Text, "\n")
		if !slices.Contains(lines, string(sent[0])) {
			t.Fatalf("no line of the card is the bytes that were sent:\n%s", cards[0].Text)
		}
	})
}

// TestS2X5_AnotherPrincipalsButtonIsUnknown: Bob sends the callback data of
// Alice's card, and a guessed id. Each is answered as an unknown button,
// Alice's approval stays pending with both buttons live, and nothing is
// called. Alice's own tap then works, and Bob still learns nothing.
func TestS2X5_AnotherPrincipalsButtonIsUnknown(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newCardEnv(t, s)
		row := e.emit(writeArgs)
		for name, data := range map[string]string{
			"Alice's approve id": row.approve,
			"Alice's cancel id":  row.cancel,
			"the approval id":    row.id,
			"a guessed id":       approval.NewID(),
		} {
			if got := e.press(bob, data); got != pa.ReplyUnknownButton {
				t.Fatalf("Bob pressed %s: reply %q, want unknown button", name, got)
			}
		}
		if got := e.approvalState(row.id); got != "pending" {
			t.Fatalf("Alice's approval is %s", got)
		}
		if got := e.cardCallbacks(alice); len(got) != 2 {
			t.Fatalf("Alice's callbacks after Bob's presses: %v", got)
		}
		if rows := e.approvals(bob); len(rows) != 0 {
			t.Fatalf("Bob has approvals: %+v", rows)
		}
		e.noCalls()

		// Alice's button still works: Bob's presses consumed nothing.
		if got := e.press(alice, row.approve); got != "" {
			t.Fatalf("Alice's approve queued %q", got)
		}
		if sent := e.ep.sent(); len(sent) != 1 || e.handed() != 1 {
			t.Fatalf("%d calls, %d dispatches after Alice's approve", len(sent), e.handed())
		}
		// The spent id answers its owner from the approval row, and nobody
		// else.
		for _, data := range []string{row.approve, row.cancel} {
			if got := e.press(bob, data); got != pa.ReplyUnknownButton {
				t.Fatalf("Bob pressed Alice's spent id: reply %q, want unknown button", got)
			}
		}
		if sent := e.ep.sent(); len(sent) != 1 || e.handed() != 1 {
			t.Fatalf("%d calls, %d dispatches at the end", len(sent), e.handed())
		}
	})
}

// TestS2A7_DoubleTapDispatchesOnce: Telegram redelivers the update of the
// Approve tap, and the principal taps Approve again, then Cancel. The call
// is made once; the later taps read "already approved".
func TestS2A7_DoubleTapDispatchesOnce(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newCardEnv(t, s)
		row := e.emit(writeArgs)
		update := e.h.NextUpdateID()
		if code := e.h.PressUpdate(update, alice, row.approve); code != http.StatusOK {
			t.Fatalf("approve: %d", code)
		}
		if sent := e.ep.sent(); len(sent) != 1 || e.handed() != 1 {
			t.Fatalf("%d calls, %d dispatches after the first tap", len(sent), e.handed())
		}
		replies := len(e.h.Replies(alice))
		// The same update again: a duplicate, nothing runs and nothing is
		// answered twice.
		if code := e.h.PressUpdate(update, alice, row.approve); code != http.StatusOK {
			t.Fatalf("redelivery: %d", code)
		}
		if got := len(e.h.Replies(alice)); got != replies {
			t.Fatalf("the redelivered update queued %d replies", got-replies)
		}
		// Two more taps, each its own update.
		if got := e.press(alice, row.approve); got != pa.ReplyApprovalAlreadyDone {
			t.Fatalf("second tap: reply %q, want already done", got)
		}
		if got := e.press(alice, row.cancel); got != pa.ReplyApprovalAlreadyDone {
			t.Fatalf("cancel after approve: reply %q, want already done", got)
		}
		if sent := e.ep.sent(); len(sent) != 1 || e.handed() != 1 {
			t.Fatalf("%d calls, %d dispatches after four taps", len(sent), e.handed())
		}
		if got := e.approvalState(row.id); got != "done/erased" {
			t.Fatalf("approval is %s", got)
		}
		if got := e.dispatches(); len(got) != 1 {
			t.Fatalf("dispatch records %v", got)
		}
	})
}

// TestS2A7_ConcurrentTapsDispatchOnce: two Approve taps delivered at the
// same time, as two updates. One approves and dispatches; the other is
// answered "already approved".
func TestS2A7_ConcurrentTapsDispatchOnce(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newCardEnv(t, s)
		row := e.emit(writeArgs)
		before := len(e.h.Replies(alice))
		for i, code := range e.h.PressConcurrently(alice, row.approve, 2) {
			if code != http.StatusOK {
				t.Fatalf("tap %d: %d", i, code)
			}
		}
		if sent := e.ep.sent(); len(sent) != 1 || e.handed() != 1 {
			t.Fatalf("%d calls, %d dispatches after two concurrent taps", len(sent), e.handed())
		}
		if got := e.h.Replies(alice)[before:]; !slices.Equal(got, []pa.Reply{pa.ReplyApprovalAlreadyDone}) {
			t.Fatalf("replies to the two taps: %v, want one already done", got)
		}
		if got := e.dispatches(); len(got) != 1 {
			t.Fatalf("dispatch records %v", got)
		}
	})
}

// TestS2A7_ApproveStepRefusesAnApprovedRow: the approve step itself refuses
// a row that is not pending, whatever let the tap reach it. Here the spent
// Approve callback is put back, as a lost delete would leave it: the tap
// resolves, and the ledger still answers "already approved".
func TestS2A7_ApproveStepRefusesAnApprovedRow(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newCardEnv(t, s)
		row := e.emit(writeArgs)
		if got := e.press(alice, row.approve); got != "" {
			t.Fatalf("approve queued %q", got)
		}
		before := e.approvalState(row.id)
		e.inTx(func(tx *sql.Tx) error {
			return s.CreatePACallback(context.Background(), tx, alice, row.approve, pa.ActionApprovalApprove, e.h.Now().Add(time.Minute))
		})
		if got := e.press(alice, row.approve); got != pa.ReplyApprovalAlreadyDone {
			t.Fatalf("tap on the restored button: reply %q, want already done", got)
		}
		if got := e.approvalState(row.id); got != before {
			t.Fatalf("approval went from %s to %s", before, got)
		}
		if sent := e.ep.sent(); len(sent) != 1 || e.handed() != 1 {
			t.Fatalf("%d calls, %d dispatches", len(sent), e.handed())
		}
	})
}

// TestApprovalCard_Cancel: Cancel ends the approval and erases its
// arguments; nothing is called, and both buttons then read "cancelled".
func TestApprovalCard_Cancel(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newCardEnv(t, s)
		row := e.emit(writeArgs)
		if got := e.press(alice, row.cancel); got != pa.ReplyApprovalCancelled {
			t.Fatalf("cancel: %q", got)
		}
		if got := e.approvalState(row.id); got != "cancelled/erased" {
			t.Fatalf("approval is %s", got)
		}
		if got := e.cardCallbacks(alice); len(got) != 0 {
			t.Fatalf("callbacks left: %v", got)
		}
		for _, data := range []string{row.cancel, row.approve} {
			if got := e.press(alice, data); got != pa.ReplyApprovalCancelled {
				t.Fatalf("tap after cancel: %q", got)
			}
		}
		e.noCalls()
	})
}

// TestApprovalCard_ExpiredButtons: after five minutes neither button does
// anything, and the principal is told the approval is no longer valid.
func TestApprovalCard_ExpiredButtons(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newCardEnv(t, s)
		row := e.emit(writeArgs)
		e.h.Advance(5*time.Minute + time.Second)
		for _, data := range []string{row.approve, row.cancel} {
			if got := e.press(alice, data); got != pa.ReplyApprovalExpired {
				t.Fatalf("tap after expiry: %q", got)
			}
		}
		e.noCalls()
		if got := e.approvalState(row.id); strings.HasPrefix(got, "approved") || strings.HasPrefix(got, "done") {
			t.Fatalf("approval is %s", got)
		}
	})
}

// TestApprovalCard_CrossedActionChangesNothing: a callback row whose action
// does not match the button it was issued for (a corrupted or forged row)
// neither approves nor cancels.
func TestApprovalCard_CrossedActionChangesNothing(t *testing.T) {
	e := newCardEnv(t, sqliteStore(t))
	row := e.emit(writeArgs)
	if _, err := e.store.DB.Exec(`UPDATE pa_callbacks SET action = $1 WHERE principal = $2 AND id = $3`,
		pa.ActionApprovalApprove, alice, row.cancel); err != nil {
		t.Fatal(err)
	}
	if got := e.press(alice, row.cancel); got != pa.ReplyUnknownButton {
		t.Fatalf("cancel id stored as approve: reply %q", got)
	}
	if got := e.approvalState(row.id); got != "pending" {
		t.Fatalf("approval is %s", got)
	}
	e.noCalls()
}

// TestApprovalCard_ConsentButtonStillWorks: the callback router still
// serves the consent prompt's button, and without the approval ledger a
// card's action is an unknown button.
func TestApprovalCard_ConsentButtonStillWorks(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newCardEnv(t, s)
		row := e.emit(writeArgs)
		// The whole consent flow for Bob, through the same router.
		e.h.Consent(bob)
		if got := e.lastReply(bob); got != pa.ReplyConsentAccepted {
			t.Fatalf("Bob's consent: %q", got)
		}
		if got := e.approvalState(row.id); got != "pending" {
			t.Fatalf("approval is %s", got)
		}
		// As deployed: no ledger behind the router.
		e.h.EnableApprovalCards(e.cards, nil, func(context.Context, int64, string) {
			t.Error("dispatch without a ledger")
		})
		if got := e.press(alice, row.approve); got != pa.ReplyUnknownButton {
			t.Fatalf("approve without a ledger: %q", got)
		}
		e.noCalls()
		if got := e.approvalState(row.id); got != "pending" {
			t.Fatalf("approval is %s", got)
		}
	})
}
