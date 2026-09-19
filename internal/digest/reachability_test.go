package digest

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/notify"
)

// stubRoundTripper intercepts every request and returns a canned response,
// so sendTelegramMessage's real net/http path is exercised without any
// network access. status/body describe the Telegram Bot API response;
// transportErr, when set, makes RoundTrip fail instead (simulating a network
// blip) so the *url.Error unwrap path is exercised too.
type stubRoundTripper struct {
	status       int
	body         string
	transportErr error
}

func (s *stubRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if s.transportErr != nil {
		return nil, s.transportErr
	}
	return &http.Response{
		StatusCode: s.status,
		Body:       io.NopCloser(strings.NewReader(s.body)),
		Header:     make(http.Header),
	}, nil
}

// withStubTransport swaps http.DefaultClient's Transport for the duration of
// the test and restores it on cleanup. sendTelegramMessage always uses
// http.DefaultClient, so this is the seam available without changing its
// signature.
func withStubTransport(t *testing.T, rt http.RoundTripper) {
	t.Helper()
	orig := http.DefaultClient.Transport
	http.DefaultClient.Transport = rt
	t.Cleanup(func() { http.DefaultClient.Transport = orig })
}

func newDigestTestStore(t *testing.T) *db.Store {
	t.Helper()
	ctx := context.Background()
	conn, err := db.Open(ctx, "file::memory:?cache=shared", 0, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := db.Migrate(ctx, conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db.NewStore(conn, nil)
}

// TestSendTelegramMessage_ReturnsTypedAPIError asserts sendTelegramMessage's
// new return type: a non-2xx response comes back as *notify.APIError
// carrying the parsed description, never a bare formatted string, and the
// bot token never appears in the error text.
func TestSendTelegramMessage_ReturnsTypedAPIError(t *testing.T) {
	withStubTransport(t, &stubRoundTripper{
		status: http.StatusForbidden,
		body:   `{"ok":false,"error_code":403,"description":"Forbidden: bot was blocked by the user"}`,
	})
	err := sendTelegramMessage("shh-secret-token", 111, "hello")
	if err == nil {
		t.Fatal("expected an error for a 403 response")
	}
	var apiErr *notify.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error is not *notify.APIError: %T: %v", err, err)
	}
	if apiErr.StatusCode != 403 {
		t.Errorf("StatusCode = %d, want 403", apiErr.StatusCode)
	}
	if apiErr.Description != "Forbidden: bot was blocked by the user" {
		t.Errorf("Description = %q, want the parsed Telegram description", apiErr.Description)
	}
	if strings.Contains(err.Error(), "shh-secret-token") {
		t.Fatalf("bot token leaked into the error: %v", err)
	}
}

// TestRecordReachability_BlockedWritesRow is T6: a stubbed 403 "bot was
// blocked by the user" results in a client_bot_reachability row with
// state=blocked and a normalised reason_code, resolved through runDigest's
// real recipient-resolution path (UserIDByTelegramID).
func TestRecordReachability_BlockedWritesRow(t *testing.T) {
	ctx := context.Background()
	store := newDigestTestStore(t)
	uid, err := store.EnsureUserByTelegramID(ctx, 111, "alice", "Alice")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}

	sendErr := &notify.APIError{StatusCode: 403, Description: "Forbidden: bot was blocked by the user"}
	recordReachability(ctx, store, 111, sendErr)

	prefs, err := store.ResolveNotificationPrefs(ctx, uid) // sanity: store is usable
	if err != nil || prefs == nil {
		t.Fatalf("store sanity check failed: %v", err)
	}
	var state, reasonCode string
	if err := store.DB.QueryRowContext(ctx,
		`SELECT state, reason_code FROM client_bot_reachability WHERE user_id = $1`, uid,
	).Scan(&state, &reasonCode); err != nil {
		t.Fatalf("read reachability row: %v", err)
	}
	if state != notify.StateBlocked {
		t.Errorf("state = %q, want %q", state, notify.StateBlocked)
	}
	if reasonCode == "" {
		t.Error("reason_code is empty, want a normalised code")
	}
}

// TestRecordReachability_TransientFailureWritesNoRow is T6's other half: a
// 500 must not write any reachability row at all.
func TestRecordReachability_TransientFailureWritesNoRow(t *testing.T) {
	ctx := context.Background()
	store := newDigestTestStore(t)
	uid, err := store.EnsureUserByTelegramID(ctx, 222, "bob", "Bob")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}

	sendErr := &notify.APIError{StatusCode: 500, Description: "Internal Server Error"}
	recordReachability(ctx, store, 222, sendErr)

	var count int
	if err := store.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM client_bot_reachability WHERE user_id = $1`, uid,
	).Scan(&count); err != nil {
		t.Fatalf("count reachability rows: %v", err)
	}
	if count != 0 {
		t.Errorf("got %d reachability rows after a 500, want 0", count)
	}
}

// TestRecordReachability_TransportErrorWritesNoRow: a network-level failure
// (no HTTP response at all) must not be treated as a classifiable outcome.
func TestRecordReachability_TransportErrorWritesNoRow(t *testing.T) {
	ctx := context.Background()
	store := newDigestTestStore(t)
	if _, err := store.EnsureUserByTelegramID(ctx, 333, "carol", "Carol"); err != nil {
		t.Fatalf("ensure user: %v", err)
	}

	recordReachability(ctx, store, 333, errors.New("dial tcp: connection refused"))

	var count int
	if err := store.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM client_bot_reachability`,
	).Scan(&count); err != nil {
		t.Fatalf("count reachability rows: %v", err)
	}
	if count != 0 {
		t.Errorf("got %d reachability rows after a transport error, want 0", count)
	}
}

// TestRunDigest_NoLogLineContainsBotToken is the log-safety half of T6: even
// on a blocked-bot send, no code path in this package formats the bot token
// into an error or log line. sendTelegramMessage's *url.Error unwrap
// pre-dates this change; this test pins that the new APIError path does not
// regress it by feeding a transport-level failure (which DOES embed the
// token in the raw *url.Error) and confirming the returned error omits it.
func TestRunDigest_NoLogLineContainsBotToken(t *testing.T) {
	withStubTransport(t, &stubRoundTripper{transportErr: &fakeTransportError{}})
	err := sendTelegramMessage("shh-secret-token", 111, "hello")
	if err == nil {
		t.Fatal("expected a transport error")
	}
	if strings.Contains(err.Error(), "shh-secret-token") {
		t.Fatalf("bot token leaked into the transport error: %v", err)
	}
}

// fakeTransportError is an arbitrary error type standing in for a transport
// failure; it only needs to satisfy the error interface.
type fakeTransportError struct{}

func (*fakeTransportError) Error() string { return "connection reset by peer" }
