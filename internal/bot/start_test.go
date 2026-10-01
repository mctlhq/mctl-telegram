package bot

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/metrics"
	"github.com/mctlhq/mctl-telegram/internal/notify"
)

func entUpdate(updateID, chatID int64, text, entType string, offset, length int) string {
	return fmt.Sprintf(`{"update_id":%d,"message":{"chat":{"id":%d},"text":%q,"entities":[{"type":%q,"offset":%d,"length":%d}]}}`,
		updateID, chatID, text, entType, offset, length)
}

func TestMessageClassification(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"bare", entUpdate(1, 5, "/start", "bot_command", 0, 6), db.KindStartCommand},
		{"suffix", entUpdate(1, 5, "/start@SomeBot", "bot_command", 0, 14), db.KindStartCommand},
		{"payload", entUpdate(1, 5, "/start onboarding", "bot_command", 0, 6), db.KindStartCommand},
		// Telegram bot commands are case-insensitive; mobile keyboards send /Start.
		{"capitalized", entUpdate(1, 5, "/Start", "bot_command", 0, 6), db.KindStartCommand},
		{"uppercase", entUpdate(1, 5, "/START", "bot_command", 0, 6), db.KindStartCommand},
		{"uppercase suffix", entUpdate(1, 5, "/START@SomeBot", "bot_command", 0, 14), db.KindStartCommand},
		{"uppercase startx", entUpdate(1, 5, "/STARTX", "bot_command", 0, 7), db.KindMessage},
		{"plain", msgUpdate(1, 5, "hello"), db.KindMessage},
		{"settings", entUpdate(1, 5, "/settings", "bot_command", 0, 9), db.KindMessage},
		{"startx", entUpdate(1, 5, "/startx", "bot_command", 0, 7), db.KindMessage},
		{"offset", entUpdate(1, 5, "hi /start", "bot_command", 3, 6), db.KindMessage},
		{"not first entity", `{"update_id":1,"message":{"chat":{"id":5},"text":"/start","entities":[{"type":"mention","offset":0,"length":3},{"type":"bot_command","offset":0,"length":6}]}}`, db.KindMessage},
		{"no entities", msgUpdate(1, 5, "/start"), db.KindMessage},
		{"edited", `{"update_id":1,"edited_message":{"chat":{"id":5},"text":"/start","entities":[{"type":"bot_command","offset":0,"length":6}]}}`, db.KindUnsupported},
		{"channel post", `{"update_id":1,"channel_post":{"chat":{"id":-5},"text":"/start","entities":[{"type":"bot_command","offset":0,"length":6}]}}`, db.KindUnsupported},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var u Update
			if err := json.Unmarshal([]byte(c.body), &u); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if got := u.Kind(); got != c.want {
				t.Errorf("Kind = %q, want %q", got, c.want)
			}
			// No text or payload may be held anywhere in the value.
			dump := fmt.Sprintf("%+v", u)
			if u.Message != nil {
				dump += fmt.Sprintf("%+v", *u.Message)
			}
			for _, leak := range []string{"onboarding", "SomeBot", "hello", "settings"} {
				if strings.Contains(dump, leak) {
					t.Errorf("update holds content %q: %s", leak, dump)
				}
			}
			if u.Message != nil {
				rt := reflect.TypeOf(*u.Message)
				for i := 0; i < rt.NumField(); i++ {
					if rt.Field(i).Type.Kind() == reflect.String {
						t.Errorf("Message has string field %s", rt.Field(i).Name)
					}
				}
			}
		})
	}
}

func seedStartUser(t *testing.T, store *db.Store, tgID int64) int64 {
	t.Helper()
	uid, err := store.EnsureUserByTelegramID(context.Background(), tgID, "alice", "Alice")
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	return uid
}

func runPoll(t *testing.T, store *db.Store, reg *Registry, updates ...string) *countingCounter {
	t.Helper()
	fake := &fakeTelegram{batches: [][]byte{batch(updates...)}}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()
	c := newCounter()
	r := NewReceiver(store, reg, c, "test-token", Options{BaseURL: srv.URL, PollTimeout: 1})
	if err := r.pollOnce(context.Background()); err != nil {
		t.Fatalf("pollOnce: %v", err)
	}
	return c
}

func TestStartHandler_RecordsReachabilityNotConsent(t *testing.T) {
	ctx := context.Background()
	store := newBotTestStore(t)
	uid := seedStartUser(t, store, 4242)
	if _, err := store.DB.ExecContext(ctx, `INSERT INTO client_bot_reachability(user_id,state,reason_code,observed_at,source,updated_at) VALUES($1,'blocked','blocked',$2,'digest',$2)`, uid, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("seed reachability: %v", err)
	}
	before, err := store.ResolveNotificationPrefs(ctx, uid)
	if err != nil {
		t.Fatal(err)
	}

	reg := NewRegistry(KnownChatFunc(store))
	reg.Register(db.KindStartCommand, StartHandler(store))
	c := runPoll(t, store, reg, entUpdate(10, 4242, "/start onboarding", "bot_command", 0, 6))

	if got := c.get("start_command/reachability_recorded"); got != 1 {
		t.Errorf("reachability_recorded = %d, want 1", got)
	}
	r, err := store.GetBotReachability(ctx, uid)
	if err != nil || r == nil {
		t.Fatalf("reachability = %v, %v", r, err)
	}
	if r.State != notify.StateReachable || r.ReasonCode != "bot_start" || r.Source != "bot_start" {
		t.Errorf("reachability = %+v", r)
	}
	after, _ := store.ResolveNotificationPrefs(ctx, uid)
	if !reflect.DeepEqual(before, after) {
		t.Errorf("prefs changed by /start: %+v -> %+v", before, after)
	}
	var n int
	_ = store.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM client_notification_prefs`).Scan(&n)
	if n != 0 {
		t.Errorf("client_notification_prefs rows = %d, want 0", n)
	}
}

func TestStartHandler_UnknownChatRecordsNothing(t *testing.T) {
	ctx := context.Background()
	store := newBotTestStore(t)
	reg := NewRegistry(KnownChatFunc(store))
	reg.Register(db.KindStartCommand, StartHandler(store))
	c := runPoll(t, store, reg,
		entUpdate(11, 777, "/start", "bot_command", 0, 6),
		entUpdate(12, -5, "/start", "bot_command", 0, 6))
	if got := c.get("start_command/unknown_chat"); got != 2 {
		t.Errorf("unknown_chat = %d, want 2", got)
	}
	var n int
	_ = store.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM client_bot_reachability`).Scan(&n)
	if n != 0 {
		t.Errorf("reachability rows = %d, want 0", n)
	}
}

func TestStartHandler_PlainMessageIsInert(t *testing.T) {
	ctx := context.Background()
	store := newBotTestStore(t)
	seedStartUser(t, store, 4242)
	reg := NewRegistry(KnownChatFunc(store))
	reg.Register(db.KindStartCommand, StartHandler(store))
	c := runPoll(t, store, reg, msgUpdate(13, 4242, "/start"))
	if got := c.get("message/no_handler"); got != 1 {
		t.Errorf("no_handler = %d, want 1", got)
	}
	for _, tbl := range []string{"client_bot_reachability", "client_notification_prefs"} {
		var n int
		_ = store.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+tbl).Scan(&n)
		if n != 0 {
			t.Errorf("%s rows = %d, want 0", tbl, n)
		}
	}
}

func TestStartHandler_ErrorRollsBackReachability(t *testing.T) {
	ctx := context.Background()
	store := newBotTestStore(t)
	uid := seedStartUser(t, store, 4242)
	inner := StartHandler(store)
	reg := NewRegistry(KnownChatFunc(store))
	reg.Register(db.KindStartCommand, HandlerFunc(func(ctx context.Context, tx *sql.Tx, d Delivery) (string, error) {
		if _, err := inner.HandleUpdate(ctx, tx, d); err != nil {
			return "", err
		}
		return "", errors.New("boom")
	}))
	runPoll(t, store, reg, entUpdate(14, 4242, "/start", "bot_command", 0, 6))
	r, err := store.GetBotReachability(ctx, uid)
	if err != nil {
		t.Fatal(err)
	}
	if r != nil {
		t.Errorf("reachability survived a handler error: %+v", r)
	}
}

func TestStartHandler_NonConclusiveOutboundKeepsReachable(t *testing.T) {
	ctx := context.Background()
	store := newBotTestStore(t)
	uid := seedStartUser(t, store, 4242)
	reg := NewRegistry(KnownChatFunc(store))
	reg.Register(db.KindStartCommand, StartHandler(store))
	runPoll(t, store, reg, entUpdate(15, 4242, "/start", "bot_command", 0, 6))
	if err := store.RecordBotReachability(ctx, uid, notify.DeliveryOutcome{State: notify.StateUnknown, ReasonCode: "rate_limited"}, "digest"); err != nil {
		t.Fatal(err)
	}
	r, _ := store.GetBotReachability(ctx, uid)
	if r == nil || r.State != notify.StateReachable {
		t.Errorf("state = %+v, want reachable", r)
	}
}

// A callback query's originating message is decoded through the same
// Message.UnmarshalJSON, so a callback on the bot's /start message derives
// StartCommand=true on CallbackQuery.Message. The update is still a callback
// (#571's kind), never a start_command: Kind checks CallbackQuery first.
func TestCallbackOnStartMessageIsNotStartCommand(t *testing.T) {
	body := `{"update_id":1,"callback_query":{"id":"cb-1","data":"x","message":{"chat":{"id":5},"text":"/start","entities":[{"type":"bot_command","offset":0,"length":6}]}}}`
	var u Update
	if err := json.Unmarshal([]byte(body), &u); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := u.Kind(); got != db.KindCallbackQuery {
		t.Errorf("Kind = %q, want %q", got, db.KindCallbackQuery)
	}
}

// A /start dispatched late by the pending sweep must not overwrite a newer
// conclusive observation recorded after it was received.
func TestStartHandler_SweptStaleStartKeepsNewerBlocked(t *testing.T) {
	ctx := context.Background()
	store := newBotTestStore(t)
	uid := seedStartUser(t, store, 4242)
	reg := NewRegistry(KnownChatFunc(store))
	reg.Register(db.KindStartCommand, StartHandler(store))
	c := newCounter()
	r := NewReceiver(store, reg, c, "test-token", Options{BaseURL: "http://127.0.0.1:1", PollTimeout: 1})

	// Accepted (durable) but not dispatched: the process died here.
	if ok, err := store.AcceptUpdate(ctx, 30, db.KindStartCommand, sql.NullInt64{Int64: 4242, Valid: true}); err != nil || !ok {
		t.Fatalf("accept: %v %v", ok, err)
	}
	time.Sleep(5 * time.Millisecond)
	// A later outbound delivery concludes the client blocked the bot.
	if err := store.RecordBotReachability(ctx, uid, notify.DeliveryOutcome{State: notify.StateBlocked, ReasonCode: "blocked", Conclusive: true}, "digest"); err != nil {
		t.Fatal(err)
	}
	r.sweepPending(ctx)

	got, err := store.GetBotReachability(ctx, uid)
	if err != nil || got == nil {
		t.Fatalf("reachability = %v, %v", got, err)
	}
	if got.State != notify.StateBlocked || got.Source != "digest" {
		t.Errorf("stale /start overwrote a newer observation: %+v", got)
	}
	if n := c.get("start_command/handled"); n != 1 {
		t.Errorf("start_command/handled = %d, want 1", n)
	}
	if n := c.get("start_command/reachability_recorded"); n != 0 {
		t.Errorf("start_command/reachability_recorded = %d, want 0", n)
	}
}

// T9: neither the receiver nor the /start handler logs a chat id, message
// text or payload, for a /start, a plain message or an unknown chat.
func TestStartPath_LogsNoChatIDOrContent(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	store := newBotTestStore(t)
	seedStartUser(t, store, 4242987)
	reg := NewRegistry(KnownChatFunc(store))
	// Update 43 runs the real handler and then fails, so the receiver logs its
	// handler-failure line on the /start path. That line proves the capture
	// sees the receiver's logs; without it, "no leak" could just mean "no log".
	inner := StartHandler(store)
	reg.Register(db.KindStartCommand, HandlerFunc(func(ctx context.Context, tx *sql.Tx, d Delivery) (string, error) {
		out, err := inner.HandleUpdate(ctx, tx, d)
		if err == nil && d.UpdateID == 43 {
			return "", errors.New("boom")
		}
		return out, err
	}))
	runPoll(t, store, reg,
		entUpdate(40, 4242987, "/start secretpayload", "bot_command", 0, 6),
		msgUpdate(41, 4242987, "secrettext"),
		entUpdate(42, 7777123, "/start otherpayload", "bot_command", 0, 6),
		entUpdate(43, 4242987, "/start failpayload", "bot_command", 0, 6))

	out := buf.String()
	if !strings.Contains(out, "bot update handler failed") || !strings.Contains(out, "kind="+db.KindStartCommand) {
		t.Fatalf("log capture did not see the receiver's handler-failure line; the leak checks below would be vacuous:\n%s", out)
	}
	for _, leak := range []string{"4242987", "7777123", "secretpayload", "secrettext", "otherpayload", "failpayload"} {
		if strings.Contains(out, leak) {
			t.Errorf("log contains %q:\n%s", leak, out)
		}
	}
}

// T11: a /start increments mctl_bot_updates_total{kind="start_command",
// outcome="reachability_recorded"}, the metric help names that outcome, and
// every kind label the classifier can produce is a db.Kind* constant.
func TestStartMetrics(t *testing.T) {
	store := newBotTestStore(t)
	seedStartUser(t, store, 4242)
	m := metrics.New()
	reg := NewRegistry(KnownChatFunc(store))
	reg.Register(db.KindStartCommand, StartHandler(store))

	fake := &fakeTelegram{batches: [][]byte{batch(entUpdate(50, 4242, "/start", "bot_command", 0, 6))}}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()
	r := NewReceiver(store, reg, NewMetricsCounter(m), "test-token", Options{BaseURL: srv.URL, PollTimeout: 1})
	if err := r.pollOnce(context.Background()); err != nil {
		t.Fatalf("pollOnce: %v", err)
	}
	if got := testutil.ToFloat64(m.BotUpdatesTotal.WithLabelValues(db.KindStartCommand, db.OutcomeReachabilityRecorded)); got != 1 {
		t.Errorf("start_command/reachability_recorded = %v, want 1", got)
	}

	ch := make(chan *prometheus.Desc, 1)
	m.BotUpdatesTotal.Describe(ch)
	if d := (<-ch).String(); !strings.Contains(d, db.OutcomeReachabilityRecorded) {
		t.Errorf("metric help does not name %q: %s", db.OutcomeReachabilityRecorded, d)
	}

	allowed := map[string]bool{db.KindMessage: true, db.KindStartCommand: true, db.KindCallbackQuery: true, db.KindUnsupported: true}
	for _, body := range []string{
		entUpdate(1, 5, "/start", "bot_command", 0, 6),
		entUpdate(1, 5, "/START@SomeBot x", "bot_command", 0, 14),
		msgUpdate(1, 5, "hi"),
		cbUpdate(1, 5, "x"),
		`{"update_id":1,"edited_message":{"chat":{"id":5},"text":"/start"}}`,
		`{"update_id":1}`,
	} {
		var u Update
		if err := json.Unmarshal([]byte(body), &u); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if k := u.Kind(); !allowed[k] {
			t.Errorf("Kind() = %q is not a db.Kind* constant", k)
		}
	}
}
