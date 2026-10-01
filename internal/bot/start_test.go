package bot

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/db"
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
	if _, err := store.DB.ExecContext(ctx, `INSERT INTO client_bot_reachability(user_id,state,reason_code,observed_at,source,updated_at) VALUES($1,'blocked','blocked','2026-01-01','digest','2026-01-01')`, uid); err != nil {
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
