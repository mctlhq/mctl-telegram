package bot

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

// --- harness -------------------------------------------------------------

func newBotTestStore(t *testing.T) *db.Store {
	t.Helper()
	ctx := context.Background()
	conn, err := db.Open(ctx, "file:"+t.Name()+"?mode=memory&cache=shared", 0, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := db.Migrate(ctx, conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db.NewStore(conn, nil)
}

// countingCounter records outcomes so "dropped safely and counted" is
// assertable rather than assumed.
type countingCounter struct {
	mu   sync.Mutex
	hits map[string]int
}

func newCounter() *countingCounter { return &countingCounter{hits: map[string]int{}} }

func (c *countingCounter) CountUpdate(kind, outcome string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.hits[kind+"/"+outcome]++
}

func (c *countingCounter) get(key string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hits[key]
}

// fakeTelegram serves one canned getUpdates batch, then empty batches. It also
// records the offsets it was asked for, which is how the acknowledgement
// ordering is verified.
type fakeTelegram struct {
	mu       sync.Mutex
	batches  [][]byte
	offsets  []string
	served   int32
	failWith int
}

func (f *fakeTelegram) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.offsets = append(f.offsets, r.URL.Query().Get("offset"))
		n := int(atomic.AddInt32(&f.served, 1)) - 1
		var body []byte
		if n < len(f.batches) {
			body = f.batches[n]
		}
		fail := f.failWith
		f.mu.Unlock()

		if fail != 0 {
			w.WriteHeader(fail)
			_, _ = w.Write([]byte(`{"ok":false,"error_code":409,"description":"Conflict: terminated by other getUpdates request"}`))
			return
		}
		if body == nil {
			body = []byte(`{"ok":true,"result":[]}`)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}
}

func (f *fakeTelegram) seenOffsets() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.offsets))
	copy(out, f.offsets)
	return out
}

func batch(updates ...string) []byte {
	return []byte(`{"ok":true,"result":[` + strings.Join(updates, ",") + `]}`)
}

func msgUpdate(updateID, chatID int64, text string) string {
	return fmt.Sprintf(`{"update_id":%d,"message":{"chat":{"id":%d},"text":%q,"from":{"id":%d}}}`,
		updateID, chatID, text, chatID)
}

func cbUpdate(updateID, chatID int64, data string) string {
	return fmt.Sprintf(`{"update_id":%d,"callback_query":{"id":"cb-1","data":%q,"message":{"chat":{"id":%d}}}}`,
		updateID, data, chatID)
}

// knownChats builds a resolver over an explicit allowlist.
func knownChats(ids ...int64) func(context.Context, int64) (bool, error) {
	set := map[int64]bool{}
	for _, id := range ids {
		set[id] = true
	}
	return func(_ context.Context, chatID int64) (bool, error) { return set[chatID], nil }
}

// --- tests ---------------------------------------------------------------

// TestReceiver_ValidUpdateReachesHandlerOnce is the primary invariant: an
// update that parses, comes from a known chat and has a registered handler is
// dispatched exactly one time.
func TestReceiver_ValidUpdateReachesHandlerOnce(t *testing.T) {
	store := newBotTestStore(t)
	fake := &fakeTelegram{batches: [][]byte{batch(msgUpdate(100, 42, "hello"))}}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	var calls int32
	reg := NewRegistry(knownChats(42))
	reg.Register(db.KindMessage, HandlerFunc(func(_ context.Context, tx *sql.Tx, d Delivery) (string, error) {
		atomic.AddInt32(&calls, 1)
		if tx == nil {
			t.Error("handler received a nil transaction; its writes would not be atomic with the processed mark")
		}
		if d.UpdateID != 100 {
			t.Errorf("update_id = %d, want 100", d.UpdateID)
		}
		if !d.ChatID.Valid || d.ChatID.Int64 != 42 {
			t.Errorf("chat_id = %+v, want 42 -- the handler cannot route without it", d.ChatID)
		}
		return "", nil
	}))

	c := newCounter()
	r := NewReceiver(store, reg, c, "test-token", Options{BaseURL: srv.URL, PollTimeout: 1})
	if err := r.pollOnce(context.Background()); err != nil {
		t.Fatalf("pollOnce: %v", err)
	}

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("handler called %d times, want 1", got)
	}
	if got := c.get("message/handled"); got != 1 {
		t.Errorf("handled counter = %d, want 1", got)
	}
}

// TestReceiver_DuplicateUpdateIDDispatchesOnce covers Telegram's at-least-once
// redelivery: the same update_id arriving twice must not produce a second
// dispatch or a second side effect.
func TestReceiver_DuplicateUpdateIDDispatchesOnce(t *testing.T) {
	store := newBotTestStore(t)
	// Same update_id in two consecutive batches, which is exactly what a
	// redelivery looks like.
	fake := &fakeTelegram{batches: [][]byte{
		batch(msgUpdate(7, 42, "first")),
		batch(msgUpdate(7, 42, "first")),
	}}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	var calls int32
	reg := NewRegistry(knownChats(42))
	reg.Register(db.KindMessage, HandlerFunc(func(context.Context, *sql.Tx, Delivery) (string, error) {
		atomic.AddInt32(&calls, 1)
		return "", nil
	}))

	c := newCounter()
	r := NewReceiver(store, reg, c, "test-token", Options{BaseURL: srv.URL, PollTimeout: 1})
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if err := r.pollOnce(ctx); err != nil {
			t.Fatalf("pollOnce %d: %v", i, err)
		}
	}

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("handler called %d times for one update_id, want 1", got)
	}
	if got := c.get("message/duplicate"); got != 1 {
		t.Errorf("duplicate counter = %d, want 1", got)
	}
}

// TestReceiver_OffsetOnlyAdvancesFromDurableState is the acknowledgement-
// ordering proof. The offset Telegram receives must come from the row that was
// written, so an update cannot be confirmed before the platform owns it.
func TestReceiver_OffsetOnlyAdvancesFromDurableState(t *testing.T) {
	store := newBotTestStore(t)
	fake := &fakeTelegram{batches: [][]byte{batch(msgUpdate(500, 42, "x"))}}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	reg := NewRegistry(knownChats(42))
	reg.Register(db.KindMessage, HandlerFunc(func(context.Context, *sql.Tx, Delivery) (string, error) {
		return "", nil
	}))
	r := NewReceiver(store, reg, newCounter(), "test-token", Options{BaseURL: srv.URL, PollTimeout: 1})
	ctx := context.Background()

	if err := r.pollOnce(ctx); err != nil {
		t.Fatalf("poll 1: %v", err)
	}
	if err := r.pollOnce(ctx); err != nil {
		t.Fatalf("poll 2: %v", err)
	}

	offsets := fake.seenOffsets()
	if len(offsets) != 2 {
		t.Fatalf("offsets = %v, want two polls", offsets)
	}
	if offsets[0] != "" {
		t.Errorf("first poll sent offset %q, want none -- the table was empty", offsets[0])
	}
	if offsets[1] != "501" {
		t.Errorf("second poll sent offset %q, want 501 (max update_id + 1, read from the DB)", offsets[1])
	}

	// And the offset really is derived from the table, not from memory.
	next, err := store.NextOffset(ctx)
	if err != nil {
		t.Fatalf("NextOffset: %v", err)
	}
	if next != 501 {
		t.Errorf("NextOffset = %d, want 501", next)
	}
}

// TestReceiver_UnknownChatIsDroppedAndCounted: anyone can message a public bot,
// so an unknown chat is an ordinary event -- dropped, counted, never dispatched.
func TestReceiver_UnknownChatIsDroppedAndCounted(t *testing.T) {
	store := newBotTestStore(t)
	fake := &fakeTelegram{batches: [][]byte{batch(msgUpdate(1, 999, "spam"))}}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	var calls int32
	reg := NewRegistry(knownChats(42)) // 999 is not known
	reg.Register(db.KindMessage, HandlerFunc(func(context.Context, *sql.Tx, Delivery) (string, error) {
		atomic.AddInt32(&calls, 1)
		return "", nil
	}))

	c := newCounter()
	r := NewReceiver(store, reg, c, "test-token", Options{BaseURL: srv.URL, PollTimeout: 1})
	if err := r.pollOnce(context.Background()); err != nil {
		t.Fatalf("pollOnce: %v", err)
	}

	if got := atomic.LoadInt32(&calls); got != 0 {
		t.Errorf("handler ran %d times for an unknown chat, want 0", got)
	}
	if got := c.get("message/unknown_chat"); got != 1 {
		t.Errorf("unknown_chat counter = %d, want 1", got)
	}
	// Still accepted, so the offset advances and Telegram stops resending it.
	next, err := store.NextOffset(context.Background())
	if err != nil {
		t.Fatalf("NextOffset: %v", err)
	}
	if next != 2 {
		t.Errorf("NextOffset = %d, want 2 -- an unknown chat must still be acknowledged", next)
	}
}

// TestReceiver_CallbackQueryRouting covers both halves of the callback
// requirement: a known callback reaches its handler, and one with no registered
// handler is dropped and counted rather than erroring.
func TestReceiver_CallbackQueryRouting(t *testing.T) {
	t.Run("routed to handler", func(t *testing.T) {
		store := newBotTestStore(t)
		fake := &fakeTelegram{batches: [][]byte{batch(cbUpdate(10, 42, "approve:123"))}}
		srv := httptest.NewServer(fake.handler())
		defer srv.Close()

		var got Delivery
		var calls int32
		reg := NewRegistry(knownChats(42))
		reg.Register(db.KindCallbackQuery, HandlerFunc(func(_ context.Context, _ *sql.Tx, d Delivery) (string, error) {
			atomic.AddInt32(&calls, 1)
			got = d
			return "", nil
		}))

		c := newCounter()
		r := NewReceiver(store, reg, c, "test-token", Options{BaseURL: srv.URL, PollTimeout: 1})
		if err := r.pollOnce(context.Background()); err != nil {
			t.Fatalf("pollOnce: %v", err)
		}
		if atomic.LoadInt32(&calls) != 1 {
			t.Fatalf("callback handler called %d times, want 1", calls)
		}
		if got.Kind != db.KindCallbackQuery {
			t.Errorf("kind = %q, want %q", got.Kind, db.KindCallbackQuery)
		}
		if !got.ChatID.Valid || got.ChatID.Int64 != 42 {
			t.Errorf("chat_id = %+v, want 42 from the callback's originating message", got.ChatID)
		}
	})

	t.Run("unknown callback dropped and counted", func(t *testing.T) {
		store := newBotTestStore(t)
		fake := &fakeTelegram{batches: [][]byte{batch(cbUpdate(11, 42, "whatever"))}}
		srv := httptest.NewServer(fake.handler())
		defer srv.Close()

		// No callback handler registered -- the state before #571.
		reg := NewRegistry(knownChats(42))
		c := newCounter()
		r := NewReceiver(store, reg, c, "test-token", Options{BaseURL: srv.URL, PollTimeout: 1})
		if err := r.pollOnce(context.Background()); err != nil {
			t.Fatalf("pollOnce: %v", err)
		}
		if got := c.get("callback_query/no_handler"); got != 1 {
			t.Errorf("no_handler counter = %d, want 1", got)
		}
		next, _ := store.NextOffset(context.Background())
		if next != 12 {
			t.Errorf("NextOffset = %d, want 12 -- an unroutable callback must still be acknowledged", next)
		}
	})
}

// TestReceiver_RestartRedispatchesAcceptedButUnprocessed is the crash case that
// matters most. An update acknowledged to Telegram but not dispatched will
// never be redelivered -- its update_id is below the offset -- so the startup
// sweep is the only thing standing between that and silent loss.
func TestReceiver_RestartRedispatchesAcceptedButUnprocessed(t *testing.T) {
	store := newBotTestStore(t)
	ctx := context.Background()

	// Exactly the state a crash between acceptance and dispatch leaves behind.
	accepted, err := store.AcceptUpdate(ctx, 900, db.KindMessage, sql.NullInt64{Int64: 42, Valid: true})
	if err != nil || !accepted {
		t.Fatalf("seed accepted update: accepted=%v err=%v", accepted, err)
	}
	// It is already acknowledged: Telegram will never send it again.
	next, err := store.NextOffset(ctx)
	if err != nil {
		t.Fatalf("NextOffset: %v", err)
	}
	if next != 901 {
		t.Fatalf("NextOffset = %d, want 901 -- the update is already past the offset", next)
	}

	var calls int32
	var seen Delivery
	reg := NewRegistry(knownChats(42))
	reg.Register(db.KindMessage, HandlerFunc(func(_ context.Context, _ *sql.Tx, d Delivery) (string, error) {
		atomic.AddInt32(&calls, 1)
		seen = d
		return "", nil
	}))

	c := newCounter()
	r := NewReceiver(store, reg, c, "test-token", Options{BaseURL: "http://127.0.0.1:1", PollTimeout: 1})
	r.sweepPending(ctx)

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("sweep dispatched %d times, want 1 -- accepted work was lost across the restart", got)
	}
	if seen.UpdateID != 900 || !seen.ChatID.Valid || seen.ChatID.Int64 != 42 {
		t.Errorf("recovered delivery = %+v, want update 900 on chat 42", seen)
	}

	// And a second sweep must not dispatch it again.
	r.sweepPending(ctx)
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("second sweep re-dispatched (total %d); the processed mark did not hold", got)
	}
}

// TestReceiver_HandlerErrorLeavesUpdatePendingForRetry: a failing handler must
// roll back with its claim, so the work is retried rather than marked done.
func TestReceiver_HandlerErrorLeavesUpdatePendingForRetry(t *testing.T) {
	store := newBotTestStore(t)
	ctx := context.Background()
	fake := &fakeTelegram{batches: [][]byte{batch(msgUpdate(300, 42, "x"))}}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	var calls int32
	reg := NewRegistry(knownChats(42))
	reg.Register(db.KindMessage, HandlerFunc(func(context.Context, *sql.Tx, Delivery) (string, error) {
		if atomic.AddInt32(&calls, 1) == 1 {
			return "", fmt.Errorf("transient handler failure")
		}
		return "", nil
	}))

	c := newCounter()
	r := NewReceiver(store, reg, c, "test-token", Options{BaseURL: srv.URL, PollTimeout: 1})
	if err := r.pollOnce(ctx); err != nil {
		t.Fatalf("pollOnce: %v", err)
	}
	if got := c.get("message/handler_error"); got != 1 {
		t.Errorf("handler_error counter = %d, want 1", got)
	}

	pending, err := store.ListPendingUpdates(ctx, 0, 10)
	if err != nil {
		t.Fatalf("ListPendingUpdates: %v", err)
	}
	if len(pending) != 1 || pending[0].UpdateID != 300 {
		t.Fatalf("pending = %+v, want update 300 still awaiting retry", pending)
	}

	// The retry succeeds and clears it.
	r.sweepPending(ctx)
	pending, err = store.ListPendingUpdates(ctx, 0, 10)
	if err != nil {
		t.Fatalf("ListPendingUpdates after retry: %v", err)
	}
	if len(pending) != 0 {
		t.Errorf("pending after successful retry = %+v, want empty", pending)
	}
}

// TestReceiver_TransportAuthFailureIsReportedNotSwallowed: the long-poll
// equivalent of "invalid secret". A 409 Conflict means another consumer holds
// the token, and a 401 means the token is wrong; either must surface as an
// error and must not advance the offset.
func TestReceiver_TransportAuthFailureIsReportedNotSwallowed(t *testing.T) {
	store := newBotTestStore(t)
	fake := &fakeTelegram{failWith: http.StatusConflict}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	r := NewReceiver(store, NewRegistry(knownChats(42)), newCounter(), "test-token",
		Options{BaseURL: srv.URL, PollTimeout: 1})
	err := r.pollOnce(context.Background())
	if err == nil {
		t.Fatal("a 409 Conflict was swallowed; a second consumer would go unnoticed")
	}
	if !strings.Contains(err.Error(), "Conflict") {
		t.Errorf("error = %v, want it to carry the API's own description", err)
	}
	next, _ := store.NextOffset(context.Background())
	if next != 0 {
		t.Errorf("NextOffset = %d after a failed poll, want 0 -- a failure must not acknowledge anything", next)
	}
}

// TestReceiver_NoSensitiveInputIsRetainedOrLogged is the privacy invariant.
// The receiver never decodes message text or callback data, so none of it can
// reach a log line, the database, or a handler.
func TestReceiver_NoSensitiveInputIsRetainedOrLogged(t *testing.T) {
	const (
		secretText = "my passport number is 1234567890"
		phone      = "+447700900123"
		payload    = "approve:secret-token-abc"
		token      = "123456:AAHsuperSecretBotToken"
	)
	store := newBotTestStore(t)
	ctx := context.Background()

	fake := &fakeTelegram{batches: [][]byte{batch(
		msgUpdate(1, 42, secretText+" "+phone),
		cbUpdate(2, 42, payload),
	)}}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	// Capture everything the receiver logs during the poll.
	var logs strings.Builder
	restore := captureSlog(t, &logs)

	reg := NewRegistry(knownChats(42))
	reg.Register(db.KindMessage, HandlerFunc(func(_ context.Context, _ *sql.Tx, d Delivery) (string, error) {
		// A handler cannot see content, because Delivery has no field for it.
		blob, _ := json.Marshal(d)
		for _, bad := range []string{secretText, phone, payload} {
			if strings.Contains(string(blob), bad) {
				t.Errorf("Delivery carried sensitive content: %s", blob)
			}
		}
		return "", nil
	}))
	r := NewReceiver(store, reg, newCounter(), token, Options{BaseURL: srv.URL, PollTimeout: 1})
	if err := r.pollOnce(ctx); err != nil {
		t.Fatalf("pollOnce: %v", err)
	}
	restore()

	for _, bad := range []string{secretText, phone, payload, token} {
		if strings.Contains(logs.String(), bad) {
			t.Errorf("log output contains %q:\n%s", bad, logs.String())
		}
	}

	// Nothing sensitive reached the database either.
	rows, err := store.DB.QueryContext(ctx, `SELECT update_id, kind, chat_id, outcome FROM bot_updates`)
	if err != nil {
		t.Fatalf("read rows: %v", err)
	}
	defer rows.Close()
	var n int
	for rows.Next() {
		var (
			id      int64
			kind    string
			chatID  sql.NullInt64
			outcome string
		)
		if err := rows.Scan(&id, &kind, &chatID, &outcome); err != nil {
			t.Fatalf("scan: %v", err)
		}
		n++
		joined := fmt.Sprintf("%d %s %v %s", id, kind, chatID, outcome)
		for _, bad := range []string{secretText, phone, payload, token} {
			if strings.Contains(joined, bad) {
				t.Errorf("row %d carries sensitive content: %s", id, joined)
			}
		}
	}
	if n != 2 {
		t.Errorf("stored %d rows, want 2", n)
	}
}

// TestReceiver_TokenNeverAppearsInAnError: net/http embeds the full request URL
// in transport errors, and the URL contains the bot token. Anything that can
// reach a log line has to be scrubbed.
func TestReceiver_TokenNeverAppearsInAnError(t *testing.T) {
	const token = "987654:AAGanotherSecretToken"
	store := newBotTestStore(t)
	// Port 1 refuses instantly, producing a transport error that carries the URL.
	r := NewReceiver(store, NewRegistry(nil), newCounter(), token,
		Options{BaseURL: "http://127.0.0.1:1", PollTimeout: 1})

	err := r.pollOnce(context.Background())
	if err == nil {
		t.Fatal("expected a transport error")
	}
	if strings.Contains(err.Error(), token) {
		t.Errorf("bot token leaked into the error: %v", err)
	}
	if !strings.Contains(err.Error(), "[redacted]") {
		t.Errorf("error = %v, want the token replaced with [redacted]", err)
	}
}

// TestReceiver_DisabledWithoutToken mirrors the digest: an unset token disables
// the feature rather than failing startup.
func TestReceiver_DisabledWithoutToken(t *testing.T) {
	store := newBotTestStore(t)
	r := NewReceiver(store, NewRegistry(nil), newCounter(), "", Options{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.Start(ctx) // must return without starting a loop
	time.Sleep(20 * time.Millisecond)
	next, err := store.NextOffset(ctx)
	if err != nil {
		t.Fatalf("NextOffset: %v", err)
	}
	if next != 0 {
		t.Errorf("NextOffset = %d, want 0 -- a tokenless receiver must not poll", next)
	}
}

// TestRegistry_DuplicateRegistrationPanics: two owners for one kind means one
// of them silently never runs, which is far worse to discover at runtime.
func TestRegistry_DuplicateRegistrationPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("registering a second handler for one kind did not panic")
		}
	}()
	reg := NewRegistry(nil)
	h := HandlerFunc(func(context.Context, *sql.Tx, Delivery) (string, error) { return "", nil })
	reg.Register(db.KindMessage, h)
	reg.Register(db.KindMessage, h)
}

// captureSlog redirects the default slog logger into w and returns a function
// that restores it. Used to assert on what the receiver actually logs rather
// than trusting that it logs nothing sensitive.
func captureSlog(t *testing.T, w io.Writer) func() {
	t.Helper()
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug})))
	return func() { slog.SetDefault(prev) }
}

// failingAcceptStore fails AcceptUpdate for one specific update_id and
// delegates everything else to a real store.
type failingAcceptStore struct {
	*db.Store
	failOn int64
}

func (f *failingAcceptStore) AcceptUpdate(ctx context.Context, updateID int64, kind string, chatID sql.NullInt64) (bool, error) {
	if updateID == f.failOn {
		return false, fmt.Errorf("simulated durable-write failure")
	}
	return f.Store.AcceptUpdate(ctx, updateID, kind, chatID)
}

// TestReceiver_AcceptFailureStopsTheBatch is a regression test for silent data
// loss. Telegram sends a batch in ascending update_id order, so if update N
// fails to become durable and the loop carries on to N+1, the DB-derived offset
// jumps past N and Telegram will never send it again -- the update is gone, and
// nothing reports that it was.
func TestReceiver_AcceptFailureStopsTheBatch(t *testing.T) {
	real := newBotTestStore(t)
	store := &failingAcceptStore{Store: real, failOn: 50}
	fake := &fakeTelegram{batches: [][]byte{batch(
		msgUpdate(50, 42, "the one that fails"),
		msgUpdate(51, 42, "the one after it"),
	)}}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	reg := NewRegistry(knownChats(42))
	reg.Register(db.KindMessage, HandlerFunc(func(context.Context, *sql.Tx, Delivery) (string, error) {
		return "", nil
	}))
	r := NewReceiver(store, reg, newCounter(), "test-token", Options{BaseURL: srv.URL, PollTimeout: 1})

	err := r.pollOnce(context.Background())
	if err == nil {
		t.Fatal("a failed durable write was swallowed")
	}

	// The critical assertion: the offset must NOT have moved past 50.
	next, oerr := real.NextOffset(context.Background())
	if oerr != nil {
		t.Fatalf("NextOffset: %v", oerr)
	}
	if next > 50 {
		t.Fatalf("NextOffset = %d: update 50 was acknowledged despite never being stored, and Telegram will not resend it", next)
	}
	if next != 0 {
		t.Errorf("NextOffset = %d, want 0 -- nothing in this batch should have been acknowledged", next)
	}
}

// TestReceiver_SweepDrainsABacklogLargerThanOneBatch pins the second P2: the
// sweep used to recover at most batchLimit rows in one pass. Those rows are
// past the Telegram offset and will never be redelivered, so a truncated sweep
// is silent loss for everything beyond the first page.
func TestReceiver_SweepDrainsABacklogLargerThanOneBatch(t *testing.T) {
	store := newBotTestStore(t)
	ctx := context.Background()

	const backlog = 25
	for i := int64(1); i <= backlog; i++ {
		if _, err := store.AcceptUpdate(ctx, i, db.KindMessage, sql.NullInt64{Int64: 42, Valid: true}); err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
	}

	var calls int32
	reg := NewRegistry(knownChats(42))
	reg.Register(db.KindMessage, HandlerFunc(func(context.Context, *sql.Tx, Delivery) (string, error) {
		atomic.AddInt32(&calls, 1)
		return "", nil
	}))

	// batchLimit deliberately smaller than the backlog.
	r := NewReceiver(store, reg, newCounter(), "test-token",
		Options{BaseURL: "http://127.0.0.1:1", PollTimeout: 1, BatchLimit: 5})
	r.sweepPending(ctx)

	if got := atomic.LoadInt32(&calls); got != backlog {
		t.Errorf("recovered %d of %d updates; the rest are past the offset and lost", got, backlog)
	}
	pending, err := store.ListPendingUpdates(ctx, 0, 100)
	if err != nil {
		t.Fatalf("list pending: %v", err)
	}
	if len(pending) != 0 {
		t.Errorf("%d updates still pending after the sweep", len(pending))
	}
}

// TestReceiver_SweepTerminatesOnAPersistentlyFailingHandler: draining must not
// become an infinite loop when nothing can be processed. The cursor advances
// even for rows that fail, so the pass ends and the retry happens on the next
// loop iteration instead.
func TestReceiver_SweepTerminatesOnAPersistentlyFailingHandler(t *testing.T) {
	store := newBotTestStore(t)
	ctx := context.Background()
	for i := int64(1); i <= 9; i++ {
		if _, err := store.AcceptUpdate(ctx, i, db.KindMessage, sql.NullInt64{Int64: 42, Valid: true}); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	var calls int32
	reg := NewRegistry(knownChats(42))
	reg.Register(db.KindMessage, HandlerFunc(func(context.Context, *sql.Tx, Delivery) (string, error) {
		atomic.AddInt32(&calls, 1)
		return "", fmt.Errorf("always fails")
	}))
	r := NewReceiver(store, reg, newCounter(), "test-token",
		Options{BaseURL: "http://127.0.0.1:1", PollTimeout: 1, BatchLimit: 3})

	done := make(chan struct{})
	go func() { r.sweepPending(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("sweepPending did not terminate with a persistently failing handler")
	}
	// Each row tried exactly once in the pass -- not retried within it.
	if got := atomic.LoadInt32(&calls); got != 9 {
		t.Errorf("handler called %d times in one sweep, want 9 (once per pending row)", got)
	}
}

// TestReceiver_InLoopSweepRetriesAFailedDispatch pins the first P2, which both
// reviewers found and which contradicted the runbook: a transient dispatch
// failure left the row pending for the rest of the process lifetime, because
// the sweep only ran before the loop. Its update_id is past the offset, so
// Telegram never redelivers it.
func TestReceiver_InLoopSweepRetriesAFailedDispatch(t *testing.T) {
	store := newBotTestStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fake := &fakeTelegram{batches: [][]byte{batch(msgUpdate(70, 42, "x"))}}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	var calls int32
	handled := make(chan struct{})
	reg := NewRegistry(knownChats(42))
	reg.Register(db.KindMessage, HandlerFunc(func(context.Context, *sql.Tx, Delivery) (string, error) {
		if atomic.AddInt32(&calls, 1) == 1 {
			return "", fmt.Errorf("transient failure")
		}
		select {
		case <-handled:
		default:
			close(handled)
		}
		return "", nil
	}))

	r := NewReceiver(store, reg, newCounter(), "test-token",
		Options{BaseURL: srv.URL, PollTimeout: 1, IdleBackoff: 10 * time.Millisecond})
	r.Start(ctx)

	select {
	case <-handled:
		// The retry happened while the process kept running, which is the point.
	case <-time.After(15 * time.Second):
		t.Fatal("a failed dispatch was never retried while running; it would sit stranded until restart")
	}
}

// TestReceiver_TokenNeverLeaksThroughARequestBuildError is the third P2. A bot
// token with a stray control character makes url.Parse fail, and *url.Error
// carries the raw URL -- which contains the token. Start logs whatever
// pollOnce returns. The existing token test only covered the client.Do path.
func TestReceiver_TokenNeverLeaksThroughARequestBuildError(t *testing.T) {
	const token = "123456:AAHsecretToken\n" // trailing newline, e.g. from a file
	store := newBotTestStore(t)
	r := NewReceiver(store, NewRegistry(nil), newCounter(), token,
		Options{BaseURL: "https://api.telegram.org", PollTimeout: 1})

	err := r.pollOnce(context.Background())
	if err == nil {
		t.Fatal("expected the malformed URL to fail")
	}
	if strings.Contains(err.Error(), "AAHsecretToken") {
		t.Errorf("bot token leaked through the request-build error: %v", err)
	}
	if !strings.Contains(err.Error(), "[redacted]") {
		t.Errorf("error = %v, want the token replaced with [redacted]", err)
	}
}

// TestReceiver_InfrastructureFailureIsNotCountedAsAHandlerError: an unknown-chat
// lookup that fails is a database problem, not a broken handler, and reading
// one as the other sends an operator to the wrong place.
func TestReceiver_InfrastructureFailureIsNotCountedAsAHandlerError(t *testing.T) {
	store := newBotTestStore(t)
	fake := &fakeTelegram{batches: [][]byte{batch(msgUpdate(80, 42, "x"))}}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	reg := NewRegistry(func(context.Context, int64) (bool, error) {
		return false, fmt.Errorf("database is down")
	})
	reg.Register(db.KindMessage, HandlerFunc(func(context.Context, *sql.Tx, Delivery) (string, error) {
		t.Error("handler ran despite the chat lookup failing")
		return "", nil
	}))

	c := newCounter()
	r := NewReceiver(store, reg, c, "test-token", Options{BaseURL: srv.URL, PollTimeout: 1})
	if err := r.pollOnce(context.Background()); err != nil {
		t.Fatalf("pollOnce: %v", err)
	}
	if got := c.get("message/" + OutcomeDispatchError); got != 1 {
		t.Errorf("dispatch_error counter = %d, want 1", got)
	}
	if got := c.get("message/" + db.OutcomeHandlerError); got != 0 {
		t.Errorf("handler_error counter = %d, want 0 -- no handler was involved", got)
	}
}

// TestReceiver_HandlerErrorTextIsScrubbedBeforeLogging closes the one path by
// which message content could still reach a log. This package never decodes
// content, but a HANDLER does, and slog attribute redaction keys off the
// attribute NAME -- so an "err" value carrying a @handle or a phone number
// would pass through untouched. Handlers come from #439 and #571; the
// transport has to hold the line regardless of what they do.
func TestReceiver_HandlerErrorTextIsScrubbedBeforeLogging(t *testing.T) {
	store := newBotTestStore(t)
	fake := &fakeTelegram{batches: [][]byte{batch(msgUpdate(90, 42, "x"))}}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	reg := NewRegistry(knownChats(42))
	reg.Register(db.KindMessage, HandlerFunc(func(context.Context, *sql.Tx, Delivery) (string, error) {
		// A handler that leaks content into its error, which is exactly what a
		// wrapped parse error over message text looks like.
		return "", fmt.Errorf(`cannot parse command from @victimhandle (+447700900123)`)
	}))

	var logs strings.Builder
	restore := captureSlog(t, &logs)
	r := NewReceiver(store, reg, newCounter(), "test-token", Options{BaseURL: srv.URL, PollTimeout: 1})
	if err := r.pollOnce(context.Background()); err != nil {
		t.Fatalf("pollOnce: %v", err)
	}
	restore()

	for _, bad := range []string{"@victimhandle", "+447700900123"} {
		if strings.Contains(logs.String(), bad) {
			t.Errorf("handler error leaked %q into the log:\n%s", bad, logs.String())
		}
	}
	if !strings.Contains(logs.String(), "[redacted]") {
		t.Errorf("expected the scrubbed marker in the log:\n%s", logs.String())
	}
}

// TestReceiver_StartSweepsBeforeItsFirstPoll: the pre-loop sweep was removed as
// redundant, so this pins that startup recovery still happens -- the first loop
// iteration must sweep before it polls.
func TestReceiver_StartSweepsBeforeItsFirstPoll(t *testing.T) {
	store := newBotTestStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Work accepted by a previous process and never dispatched.
	if _, err := store.AcceptUpdate(ctx, 950, db.KindMessage, sql.NullInt64{Int64: 42, Valid: true}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	handled := make(chan int64, 1)
	reg := NewRegistry(knownChats(42))
	reg.Register(db.KindMessage, HandlerFunc(func(_ context.Context, _ *sql.Tx, d Delivery) (string, error) {
		select {
		case handled <- d.UpdateID:
		default:
		}
		return "", nil
	}))

	// No reachable Telegram: if recovery depended on a successful poll, this
	// would hang and the test would fail.
	r := NewReceiver(store, reg, newCounter(), "test-token",
		Options{BaseURL: "http://127.0.0.1:1", PollTimeout: 1, IdleBackoff: 10 * time.Millisecond})
	r.Start(ctx)

	select {
	case id := <-handled:
		if id != 950 {
			t.Errorf("recovered update %d, want 950", id)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("startup recovery did not happen; accepted work is stranded until a successful poll")
	}
}
