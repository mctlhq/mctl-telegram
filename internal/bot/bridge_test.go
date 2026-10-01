package bot

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/notify"
)

const testBridgeToken = "bridge-token-0123456789abcdef0123456789"

func bridgeHandler(t *testing.T, store *db.Store, c Counter) http.Handler {
	t.Helper()
	auth, err := NewBearerTokenAuth(testBridgeToken)
	if err != nil {
		t.Fatal(err)
	}
	return BotStartObservationHandler(store, auth, c)
}

func postObservation(h http.Handler, auth, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, BotStartObservationPath, strings.NewReader(body))
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func obsBody(updateID, tgID int64, at time.Time) string {
	return fmt.Sprintf(`{"update_id":%d,"telegram_id":%d,"observed_at":%q}`, updateID, tgID, at.UTC().Format(time.RFC3339))
}

func reachabilityRows(t *testing.T, store *db.Store) int {
	t.Helper()
	var n int
	if err := store.DB.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM client_bot_reachability`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestBridge_RejectsMissingOrWrongAuth(t *testing.T) {
	store := newBotTestStore(t)
	seedStartUser(t, store, 4242)
	h := bridgeHandler(t, store, nil)
	body := obsBody(1, 4242, time.Now().Add(-time.Minute))
	for name, auth := range map[string]string{
		"missing":   "",
		"wrong":     "Bearer " + strings.Repeat("x", len(testBridgeToken)),
		"prefix":    "Bearer " + testBridgeToken[:len(testBridgeToken)-1],
		"no scheme": testBridgeToken,
		"basic":     "Basic " + testBridgeToken,
	} {
		if w := postObservation(h, auth, body); w.Code != http.StatusUnauthorized {
			t.Errorf("%s: status = %d, want 401", name, w.Code)
		}
	}
	if n := reachabilityRows(t, store); n != 0 {
		t.Errorf("unauthenticated calls wrote %d reachability rows", n)
	}
	var n int
	_ = store.DB.QueryRow(`SELECT COUNT(*) FROM bot_updates`).Scan(&n)
	if n != 0 {
		t.Errorf("unauthenticated calls accepted %d updates", n)
	}
}

func TestBridge_RejectsAnythingButTheThreeFields(t *testing.T) {
	store := newBotTestStore(t)
	h := bridgeHandler(t, store, nil)
	at := time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
	for name, body := range map[string]string{
		"user_id":       fmt.Sprintf(`{"update_id":1,"telegram_id":4242,"observed_at":%q,"user_id":7}`, at),
		"text":          fmt.Sprintf(`{"update_id":1,"telegram_id":4242,"observed_at":%q,"text":"/start onboarding"}`, at),
		"state":         fmt.Sprintf(`{"update_id":1,"telegram_id":4242,"observed_at":%q,"state":"blocked"}`, at),
		"no update id":  fmt.Sprintf(`{"telegram_id":4242,"observed_at":%q}`, at),
		"zero tg id":    fmt.Sprintf(`{"update_id":1,"telegram_id":0,"observed_at":%q}`, at),
		"negative chat": fmt.Sprintf(`{"update_id":1,"telegram_id":-100,"observed_at":%q}`, at),
		"no time":       `{"update_id":1,"telegram_id":4242}`,
		"future time":   obsBody(1, 4242, time.Now().Add(time.Hour)),
		"trailing":      obsBody(1, 4242, time.Now().Add(-time.Minute)) + `{}`,
		"not json":      `update_id=1`,
	} {
		if w := postObservation(h, "Bearer "+testBridgeToken, body); w.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", name, w.Code)
		}
	}
}

func TestBridge_UnknownAndAmbiguousWriteNothingAndLookIdentical(t *testing.T) {
	ctx := context.Background()
	store := newBotTestStore(t)
	known := seedStartUser(t, store, 4242)
	// 888 is ambiguous: a login identity and another user's connected account.
	a := seedStartUser(t, store, 888)
	b, err := store.EnsureUserByTelegramID(ctx, 999, "bob", "Bob")
	if err != nil {
		t.Fatal(err)
	}
	if b == a {
		t.Fatal("ambiguity setup reused a user")
	}
	if _, err := store.DB.ExecContext(ctx, `INSERT INTO telegram_accounts(user_id, telegram_user_id, session_encrypted) VALUES($1,$2,$3)`, b, 888, []byte{0}); err != nil {
		t.Fatal(err)
	}
	c := newCounter()
	h := bridgeHandler(t, store, c)
	at := time.Now().Add(-time.Minute)

	unknown := postObservation(h, "Bearer "+testBridgeToken, obsBody(1, 5555, at))
	ambiguous := postObservation(h, "Bearer "+testBridgeToken, obsBody(2, 888, at))
	valid := postObservation(h, "Bearer "+testBridgeToken, obsBody(3, 4242, at))

	for name, w := range map[string]*httptest.ResponseRecorder{"unknown": unknown, "ambiguous": ambiguous, "valid": valid} {
		if w.Code != http.StatusAccepted {
			t.Errorf("%s: status = %d, want 202", name, w.Code)
		}
		if w.Body.String() != valid.Body.String() {
			t.Errorf("%s: body %q differs from a known client's %q", name, w.Body.String(), valid.Body.String())
		}
	}
	if n := reachabilityRows(t, store); n != 1 {
		t.Errorf("reachability rows = %d, want 1 (only the known client)", n)
	}
	if r, _ := store.GetBotReachability(ctx, known); r == nil {
		t.Error("known client has no reachability row")
	}
	if got := c.get("start_command/unknown_chat"); got != 2 {
		t.Errorf("unknown_chat = %d, want 2", got)
	}
}

func TestBridge_ValidRecordsReachableNotConsent(t *testing.T) {
	ctx := context.Background()
	store := newBotTestStore(t)
	uid := seedStartUser(t, store, 4242)
	// An explicit preference exists before the /start; it must survive byte-identical.
	if err := store.SetNotificationPrefs(ctx, uid, map[string]string{"product_updates": db.PrefUnsubscribed}, "test"); err != nil {
		t.Fatalf("seed prefs: %v", err)
	}
	snapshot := func() []string {
		rows, err := store.DB.QueryContext(ctx, `SELECT user_id, category, state, source, decided_at, updated_at FROM client_notification_prefs ORDER BY category`)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = rows.Close() }()
		var out []string
		for rows.Next() {
			var u int64
			var cat, state, src string
			var dec, upd time.Time
			if err := rows.Scan(&u, &cat, &state, &src, &dec, &upd); err != nil {
				t.Fatal(err)
			}
			out = append(out, fmt.Sprintf("%d|%s|%s|%s|%s|%s", u, cat, state, src, dec.UTC().Format(time.RFC3339Nano), upd.UTC().Format(time.RFC3339Nano)))
		}
		return out
	}
	before := snapshot()
	if len(before) != 1 {
		t.Fatalf("seeded prefs rows = %d, want 1", len(before))
	}
	resolvedBefore, _ := store.ResolveNotificationPrefs(ctx, uid)

	c := newCounter()
	at := time.Now().Add(-30 * time.Second).UTC().Truncate(time.Second)
	if w := postObservation(bridgeHandler(t, store, c), "Bearer "+testBridgeToken, obsBody(10, 4242, at)); w.Code != http.StatusAccepted {
		t.Fatalf("status = %d", w.Code)
	}
	r, err := store.GetBotReachability(ctx, uid)
	if err != nil || r == nil {
		t.Fatalf("reachability = %v, %v", r, err)
	}
	if r.State != notify.StateReachable || r.ReasonCode != "bot_start" || r.Source != "bot_start" {
		t.Errorf("reachability = %+v, want reachable/bot_start/bot_start", r)
	}
	if r.ObservedAt == nil || !r.ObservedAt.Equal(at) {
		t.Errorf("observed_at = %v, want the Telegram time %v", r.ObservedAt, at)
	}
	if after := snapshot(); !reflect.DeepEqual(before, after) {
		t.Errorf("prefs rows changed: %v -> %v", before, after)
	}
	if resolvedAfter, _ := store.ResolveNotificationPrefs(ctx, uid); !reflect.DeepEqual(resolvedBefore, resolvedAfter) {
		t.Errorf("resolved prefs changed: %+v -> %+v", resolvedBefore, resolvedAfter)
	}
	if got := c.get("start_command/reachability_recorded"); got != 1 {
		t.Errorf("reachability_recorded = %d, want 1", got)
	}
}

func TestBridge_SameUpdateTwiceAppliesOnce(t *testing.T) {
	ctx := context.Background()
	store := newBotTestStore(t)
	uid := seedStartUser(t, store, 4242)
	c := newCounter()
	h := bridgeHandler(t, store, c)
	body := obsBody(20, 4242, time.Now().Add(-time.Minute))
	for i := 0; i < 2; i++ {
		if w := postObservation(h, "Bearer "+testBridgeToken, body); w.Code != http.StatusAccepted {
			t.Fatalf("call %d: status = %d", i, w.Code)
		}
	}
	if got := c.get("start_command/reachability_recorded"); got != 1 {
		t.Errorf("reachability_recorded = %d, want 1", got)
	}
	if got := c.get("start_command/duplicate"); got != 1 {
		t.Errorf("duplicate = %d, want 1", got)
	}
	var processed int
	_ = store.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM bot_updates WHERE update_id = 20 AND processed_at IS NOT NULL`).Scan(&processed)
	if processed != 1 {
		t.Errorf("processed rows = %d, want 1", processed)
	}
	if r, _ := store.GetBotReachability(ctx, uid); r == nil || r.State != notify.StateReachable {
		t.Errorf("reachability = %+v", r)
	}
}

func TestBridge_RetryAfterFailedDispatchProcessesTheRow(t *testing.T) {
	ctx := context.Background()
	store := newBotTestStore(t)
	uid := seedStartUser(t, store, 4242)
	at := time.Now().Add(-time.Minute)
	// A first attempt that got the row accepted but whose dispatch failed: the
	// row is present and unprocessed.
	if _, err := store.AcceptUpdateAt(ctx, 30, db.KindStartCommand, sql.NullInt64{Int64: 4242, Valid: true}, at); err != nil {
		t.Fatal(err)
	}
	c := newCounter()
	if w := postObservation(bridgeHandler(t, store, c), "Bearer "+testBridgeToken, obsBody(30, 4242, at)); w.Code != http.StatusAccepted {
		t.Fatalf("status = %d", w.Code)
	}
	if r, _ := store.GetBotReachability(ctx, uid); r == nil || r.State != notify.StateReachable {
		t.Errorf("retry did not record reachability: %+v", r)
	}
	if got := c.get("start_command/reachability_recorded"); got != 1 {
		t.Errorf("reachability_recorded = %d, want 1", got)
	}
}

func TestBridge_StaleStartKeepsNewerBlocked(t *testing.T) {
	ctx := context.Background()
	store := newBotTestStore(t)
	uid := seedStartUser(t, store, 4242)
	newer := time.Now().Add(-time.Minute).UTC()
	if _, err := store.DB.ExecContext(ctx, `INSERT INTO client_bot_reachability(user_id,state,reason_code,observed_at,source,updated_at) VALUES($1,'blocked','blocked',$2,'broadcast',$2)`, uid, newer); err != nil {
		t.Fatal(err)
	}
	c := newCounter()
	// The /start happened an hour before the blocked delivery outcome.
	if w := postObservation(bridgeHandler(t, store, c), "Bearer "+testBridgeToken, obsBody(40, 4242, newer.Add(-time.Hour))); w.Code != http.StatusAccepted {
		t.Fatalf("status = %d", w.Code)
	}
	r, _ := store.GetBotReachability(ctx, uid)
	if r == nil || r.State != notify.StateBlocked {
		t.Errorf("stale /start overwrote blocked: %+v", r)
	}
	if got := c.get("start_command/handled"); got != 1 {
		t.Errorf("handled = %d, want 1", got)
	}
}

func TestBridge_UpdateIDOfAnotherChatIsNotDispatched(t *testing.T) {
	ctx := context.Background()
	store := newBotTestStore(t)
	victim := seedStartUser(t, store, 4242)
	seedStartUser(t, store, 7777)
	at := time.Now().Add(-time.Minute)
	// update 50 was accepted for chat 7777 but not yet processed.
	if _, err := store.AcceptUpdateAt(ctx, 50, db.KindStartCommand, sql.NullInt64{Int64: 7777, Valid: true}, at); err != nil {
		t.Fatal(err)
	}
	if w := postObservation(bridgeHandler(t, store, nil), "Bearer "+testBridgeToken, obsBody(50, 4242, at)); w.Code != http.StatusAccepted {
		t.Fatalf("status = %d", w.Code)
	}
	if r, _ := store.GetBotReachability(ctx, victim); r != nil {
		t.Errorf("an update_id accepted for another chat recorded reachability for this one: %+v", r)
	}
}

func TestBridge_LogsNoIdentifiers(t *testing.T) {
	store := newBotTestStore(t)
	seedStartUser(t, store, 4242)
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	h := bridgeHandler(t, store, nil)
	postObservation(h, "Bearer "+testBridgeToken, obsBody(60, 4242, time.Now().Add(-time.Minute)))
	// Force the logged failure path: a closed database.
	_ = store.DB.Close()
	if w := postObservation(h, "Bearer "+testBridgeToken, obsBody(61, 4242, time.Now().Add(-time.Minute))); w.Code != http.StatusServiceUnavailable {
		t.Errorf("store failure status = %d, want 503", w.Code)
	}
	out := buf.String()
	if !strings.Contains(out, "bot-start bridge") {
		t.Fatalf("captured no bridge log line, so absence proves nothing: %q", out)
	}
	for _, leak := range []string{"4242", testBridgeToken, "\"60\"", "update_id=6"} {
		if strings.Contains(out, leak) {
			t.Errorf("log leaks %q: %s", leak, out)
		}
	}
}

func TestNewBearerTokenAuth_RejectsShortTokens(t *testing.T) {
	if _, err := NewBearerTokenAuth(strings.Repeat("a", MinBridgeTokenLen-1)); err == nil {
		t.Error("short token accepted")
	}
	if _, err := NewBearerTokenAuth(strings.Repeat("a", MinBridgeTokenLen)); err != nil {
		t.Errorf("minimum-length token rejected: %v", err)
	}
}
