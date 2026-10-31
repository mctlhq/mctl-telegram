package telegram

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/gotd/td/bin"
	"github.com/gotd/td/telegram"
	"github.com/gotd/td/tg"
	"github.com/gotd/td/tgerr"

	"github.com/mctlhq/mctl-telegram/internal/metrics"
)

// Dana is the synthetic persona these tests run as.
const floodTestUserID int64 = 500100303

// captureSlog routes the default logger into a buffer for the test.
func captureSlog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

// floodWaitObservations returns the sample count and sum of
// mctl_telegram_flood_wait_seconds for method.
func floodWaitObservations(t *testing.T, reg *metrics.Registry, method string) (uint64, float64) {
	t.Helper()
	mfs, err := reg.Prometheus.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != "mctl_telegram_flood_wait_seconds" {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "method" && l.GetValue() == method {
					return m.GetHistogram().GetSampleCount(), m.GetHistogram().GetSampleSum()
				}
			}
		}
	}
	return 0, 0
}

// invokeThrough runs one request through mws, outermost first as gotd
// applies them, ending in an invoker that returns rpcErr.
func invokeThrough(mws []telegram.Middleware, input bin.Encoder, rpcErr error) error {
	var inv tg.Invoker = telegram.InvokeFunc(func(context.Context, bin.Encoder, bin.Decoder) error {
		return rpcErr
	})
	for i := len(mws) - 1; i >= 0; i-- {
		inv = mws[i].Handle(inv)
	}
	return inv.Invoke(context.Background(), input, nil)
}

func TestFloodWaitObserver_RecordsMethodPeerKindAndWait(t *testing.T) {
	buf := captureSlog(t)
	reg := metrics.New()
	rpcErr := tgerr.New(420, "FLOOD_WAIT_15")
	req := &tg.MessagesGetHistoryRequest{Peer: &tg.InputPeerChannel{ChannelID: 1, AccessHash: 2}}

	err := invokeThrough([]telegram.Middleware{floodWaitObserver(floodTestUserID, reg)}, req, rpcErr)
	if !errors.Is(err, rpcErr) {
		t.Fatalf("observer must return the RPC error unchanged, got %v", err)
	}

	if n, sum := floodWaitObservations(t, reg, "messages.getHistory"); n != 1 || sum != 15 {
		t.Errorf("flood_wait_seconds{method=messages.getHistory}: count=%d sum=%v, want 1 and 15", n, sum)
	}
	var line map[string]any
	if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
		t.Fatalf("want exactly one JSON log line, got %q: %v", buf.String(), err)
	}
	want := map[string]any{
		"level":        "WARN",
		"msg":          "telegram flood wait",
		"method":       "messages.getHistory",
		"peer_kind":    "channel",
		"wait_seconds": float64(15),
		"user_id":      float64(floodTestUserID),
	}
	for k, v := range want {
		if line[k] != v {
			t.Errorf("log %s = %v, want %v", k, line[k], v)
		}
	}
}

// FLOOD_WAIT_0 is still a flood wait and must be recorded.
func TestFloodWaitObserver_ZeroWaitIsStillRecorded(t *testing.T) {
	captureSlog(t)
	reg := metrics.New()
	req := &tg.ContactsResolveUsernameRequest{Username: "alice_example"}
	_ = invokeThrough([]telegram.Middleware{floodWaitObserver(floodTestUserID, reg)}, req, tgerr.New(420, "FLOOD_WAIT_0"))
	if n, _ := floodWaitObservations(t, reg, "contacts.resolveUsername"); n != 1 {
		t.Errorf("FLOOD_WAIT_0 observations = %d, want 1", n)
	}
}

func TestFloodWaitObserver_IgnoresOtherOutcomes(t *testing.T) {
	buf := captureSlog(t)
	reg := metrics.New()
	req := &tg.MessagesGetHistoryRequest{Peer: &tg.InputPeerUser{UserID: 1}}
	mws := []telegram.Middleware{floodWaitObserver(floodTestUserID, reg)}
	for _, rpcErr := range []error{nil, tgerr.New(400, "PEER_ID_INVALID"), tgerr.New(420, "PEER_FLOOD"), context.DeadlineExceeded} {
		_ = invokeThrough(mws, req, rpcErr)
	}
	if n, _ := floodWaitObservations(t, reg, "messages.getHistory"); n != 0 {
		t.Errorf("non-flood outcomes recorded %d observations, want 0", n)
	}
	if buf.Len() != 0 {
		t.Errorf("non-flood outcomes logged %q, want nothing", buf.String())
	}
}

func TestPeerKind(t *testing.T) {
	tests := []struct {
		input bin.Encoder
		want  string
	}{
		{&tg.MessagesGetHistoryRequest{Peer: &tg.InputPeerUser{}}, "user"},
		{&tg.MessagesGetHistoryRequest{Peer: &tg.InputPeerChat{}}, "chat"},
		{&tg.MessagesGetHistoryRequest{Peer: &tg.InputPeerChannel{}}, "channel"},
		{&tg.MessagesGetHistoryRequest{Peer: &tg.InputPeerSelf{}}, "self"},
		{&tg.MessagesGetHistoryRequest{Peer: &tg.InputPeerEmpty{}}, "other"},
		{&tg.ContactsResolveUsernameRequest{}, "none"},
	}
	for _, tt := range tests {
		if got := peerKind(tt.input); got != tt.want {
			t.Errorf("peerKind(%T with %T) = %q, want %q", tt.input, tt.input, got, tt.want)
		}
	}
}

// The observer must be on every pooled client, after the global limiter, and
// must see the user the client serves; a helper that is never wired proves
// nothing.
func TestClientOptionsCarryFloodWaitObserver(t *testing.T) {
	buf := captureSlog(t)
	reg := metrics.New()
	limiter := telegram.MiddlewareFunc(func(next tg.Invoker) telegram.InvokeFunc { return next.Invoke })
	pool := NewClientPool(1, "hash", time.Minute, nil).WithMetrics(reg).WithGlobalMiddleware(limiter)

	mws := pool.clientOptions(&SessionStore{UserID: floodTestUserID}).Middlewares
	if len(mws) != 2 {
		t.Fatalf("pooled client middlewares = %d, want global limiter + flood-wait observer", len(mws))
	}
	_ = invokeThrough(mws, &tg.MessagesGetDialogsRequest{OffsetPeer: &tg.InputPeerEmpty{}}, tgerr.New(420, "FLOOD_WAIT_7"))
	if n, _ := floodWaitObservations(t, reg, "messages.getDialogs"); n != 1 {
		t.Errorf("pooled client did not record the flood wait (observations = %d)", n)
	}
	var line map[string]any
	if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
		t.Fatalf("want one JSON log line, got %q: %v", buf.String(), err)
	}
	if line["user_id"] != float64(floodTestUserID) {
		t.Errorf("log user_id = %v, want the client's user %d", line["user_id"], floodTestUserID)
	}
}
