package pa

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

const testSecret = "pa_webhook_secret_for_tests_only_0123456789"

type countRecorder struct {
	mu   sync.Mutex
	seen map[string]int
}

func (c *countRecorder) CountPAUpdate(o string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seen == nil {
		c.seen = map[string]int{}
	}
	c.seen[o]++
}

type runRecorder struct {
	mu   sync.Mutex
	runs []VerifiedUpdate
	err  error
}

func (r *runRecorder) HandleUpdate(_ context.Context, _ *sql.Tx, u VerifiedUpdate) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return r.err
	}
	r.runs = append(r.runs, u)
	return nil
}

func (r *runRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.runs)
}

func newStore(t *testing.T) *db.Store {
	t.Helper()
	ctx := context.Background()
	conn, err := db.Open(ctx, "file:"+t.Name()+"?mode=memory&cache=shared", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := db.Migrate(ctx, conn); err != nil {
		t.Fatal(err)
	}
	return db.NewStore(conn, nil)
}

func newWebhook(t *testing.T, dedup Deduper, h Handler, c Counter) http.Handler {
	t.Helper()
	wh, err := NewWebhookHandler(WebhookConfig{Secret: testSecret, Dedup: dedup, Handler: h, Counter: c})
	if err != nil {
		t.Fatal(err)
	}
	return wh
}

func deliver(h http.Handler, secret, body string) int {
	req := httptest.NewRequest(http.MethodPost, WebhookPath, strings.NewReader(body))
	if secret != "" {
		req.Header.Set(SecretHeader, secret)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w.Code
}

// TestWebhook_S1B3 is S1-B3: a wrong webhook secret is refused, and nothing
// past the secret check runs.
func TestWebhook_S1B3(t *testing.T) {
	runs := &runRecorder{}
	counts := &countRecorder{}
	wh := newWebhook(t, newStore(t), runs, counts)
	body := privateMessage(20, aliceID, "")

	for _, tc := range []struct{ name, secret string }{
		{"missing", ""},
		{"wrong", "pa_webhook_secret_for_tests_only_0123456788"},
		{"prefix", testSecret[:len(testSecret)-1]},
		{"longer", testSecret + "x"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if code := deliver(wh, tc.secret, body); code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", code)
			}
		})
	}
	if runs.count() != 0 {
		t.Fatalf("a run happened with a wrong secret")
	}
	if counts.seen[OutcomeBadSecret] != 4 {
		t.Fatalf("bad_secret count = %d, want 4", counts.seen[OutcomeBadSecret])
	}
	// The right secret on the same body is accepted: the refusal above is
	// the secret, not something else about the request.
	if code := deliver(wh, testSecret, body); code != http.StatusOK || runs.count() != 1 {
		t.Fatalf("right secret: status=%d runs=%d, want 200 and 1 run", code, runs.count())
	}
}

// TestWebhook_S1B2 is S1-B2: a duplicate update_id causes no second run,
// against the real dedup table.
func TestWebhook_S1B2(t *testing.T) {
	runs := &runRecorder{}
	counts := &countRecorder{}
	wh := newWebhook(t, newStore(t), runs, counts)
	body := privateMessage(30, aliceID, "")

	for i := range 3 {
		if code := deliver(wh, testSecret, body); code != http.StatusOK {
			t.Fatalf("delivery %d: status = %d, want 200", i, code)
		}
	}
	if runs.count() != 1 {
		t.Fatalf("runs = %d, want 1 for three deliveries of one update_id", runs.count())
	}
	if counts.seen[OutcomeDuplicate] != 2 {
		t.Fatalf("duplicate count = %d, want 2", counts.seen[OutcomeDuplicate])
	}
}

// A handler failure rolls the dedup row back, so Telegram's retry runs it
// instead of being swallowed as a duplicate.
func TestWebhook_HandlerFailureIsRetryable(t *testing.T) {
	runs := &runRecorder{err: errors.New("enqueue failed")}
	wh := newWebhook(t, newStore(t), runs, nil)
	body := privateMessage(40, aliceID, "")

	if code := deliver(wh, testSecret, body); code != http.StatusInternalServerError {
		t.Fatalf("failing handler: status = %d, want 500 so Telegram retries", code)
	}
	runs.err = nil
	if code := deliver(wh, testSecret, body); code != http.StatusOK || runs.count() != 1 {
		t.Fatalf("retry: status=%d runs=%d, want 200 and 1 run", code, runs.count())
	}
}

type failingDedup struct{}

func (failingDedup) AcceptPAUpdate(context.Context, int64, func(context.Context, *sql.Tx) error) (bool, error) {
	return false, errors.New("database unavailable")
}

// An unreadable dedup store is not "duplicate" and not "new": no run, and a
// 5xx so Telegram delivers again later (I9).
func TestWebhook_DedupFailureFailsClosed(t *testing.T) {
	runs := &runRecorder{}
	counts := &countRecorder{}
	wh := newWebhook(t, failingDedup{}, runs, counts)
	if code := deliver(wh, testSecret, privateMessage(50, aliceID, "")); code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", code)
	}
	if runs.count() != 0 || counts.seen[OutcomeDedupError] != 1 {
		t.Fatalf("runs=%d dedup_error=%d, want 0 and 1", runs.count(), counts.seen[OutcomeDedupError])
	}
}

// Dropped updates are acknowledged (200, so Telegram does not retry them) and
// never reach the handler or the dedup table.
func TestWebhook_DroppedUpdatesNeverRun(t *testing.T) {
	runs := &runRecorder{}
	wh := newWebhook(t, newStore(t), runs, nil)
	body := privateMessage(60, aliceID, `,"via_bot":{"id":1,"is_bot":true}`)
	if code := deliver(wh, testSecret, body); code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if runs.count() != 0 {
		t.Fatal("a dropped update reached the handler")
	}
}

func TestWebhook_MethodAndSize(t *testing.T) {
	wh := newWebhook(t, newStore(t), &runRecorder{}, nil)
	req := httptest.NewRequest(http.MethodGet, WebhookPath, nil)
	req.Header.Set(SecretHeader, testSecret)
	w := httptest.NewRecorder()
	wh.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET: status = %d, want 405", w.Code)
	}
	big := `{"update_id":1,"message":{"text":"` + strings.Repeat("a", maxUpdateBody) + `"}}`
	if code := deliver(wh, testSecret, big); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize: status = %d, want 413", code)
	}
}

func TestNewWebhookHandler_RequiresEverything(t *testing.T) {
	store := newStore(t)
	for _, cfg := range []WebhookConfig{
		{Dedup: store, Handler: InertHandler},
		{Secret: testSecret, Handler: InertHandler},
		{Secret: testSecret, Dedup: store},
	} {
		if _, err := NewWebhookHandler(cfg); !errors.Is(err, ErrWebhookConfig) {
			t.Errorf("NewWebhookHandler(%+v) error = %v, want ErrWebhookConfig", cfg.Secret != "", err)
		}
	}
}

// TestWebhook_S1X_IngressIsolation covers the ingress part of S1-X1/S1-X2:
// each run's principal is the sender of its own update, and Bob's updates
// can neither produce a run for Alice nor be deduplicated against hers.
func TestWebhook_S1X_IngressIsolation(t *testing.T) {
	runs := &runRecorder{}
	wh := newWebhook(t, newStore(t), runs, nil)

	deliver(wh, testSecret, privateMessage(70, aliceID, ""))
	deliver(wh, testSecret, privateMessage(71, bobID, ""))
	// Bob claiming Alice's chat id is dropped, not attributed to either.
	deliver(wh, testSecret, `{"update_id":72,"message":{"message_id":1,"from":{"id":556,"is_bot":false},"chat":{"id":555,"type":"private"}}}`)

	if runs.count() != 2 {
		t.Fatalf("runs = %d, want 2", runs.count())
	}
	if got := runs.runs[0].Principal().TelegramID(); got != aliceID {
		t.Fatalf("run 0 principal = %d, want Alice", got)
	}
	if got := runs.runs[1].Principal().TelegramID(); got != bobID {
		t.Fatalf("run 1 principal = %d, want Bob", got)
	}
}
