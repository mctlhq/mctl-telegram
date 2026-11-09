//go:build l2finance

package telegram

// Finance Assistant L2 slice C (#1250), T1 wire layer. Application-security
// evidence only: FINANCE_SECURITY_GATE=BLOCKED regardless of the exit status
// of this test binary. Slice C only; not L2 completion; no aggregation across
// slices.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gotd/td/bin"
	"github.com/gotd/td/session"
	"github.com/gotd/td/telegram"
	"github.com/gotd/td/telegram/dcs"
	"github.com/gotd/td/tg"
)

const (
	l2Pass          = "PASS"
	l2CannotObserve = "CANNOT-OBSERVE"
	l2Fail          = "FAIL"
)

const (
	l2AliceTG int64 = 91001
	l2Marker        = "L2SYNTH-TXN-7f3a"
)

var errL2ExternalDial = errors.New("l2finance: external dial refused")

var (
	l2SourceRev string
	l2RevRe     = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

func l2GuardDial(_ context.Context, network, addr string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || strings.HasPrefix(network, "unix") {
		return nil, fmt.Errorf("%w: %s", errL2ExternalDial, addr)
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return nil, fmt.Errorf("%w: %s", errL2ExternalDial, addr)
	}
	var d net.Dialer
	return d.DialContext(context.Background(), network, addr)
}

func TestMain(m *testing.M) {
	l2SourceRev = os.Getenv("L2FINANCE_SOURCE_REV")
	if !l2RevRe.MatchString(l2SourceRev) {
		fmt.Fprintln(os.Stderr, "l2finance: L2FINANCE_SOURCE_REV must be a 40-hex commit sha")
		os.Exit(2)
	}
	_ = os.Unsetenv("TG_API_ID")
	_ = os.Unsetenv("TG_API_HASH")
	_ = os.Unsetenv("DATABASE_URL")
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, errL2ExternalDial
		},
	}
	if tr, ok := http.DefaultTransport.(*http.Transport); ok {
		tr.DialContext = l2GuardDial
	}
	os.Exit(m.Run())
}

func l2Record(t testing.TB, id, outcome, evidence string) {
	t.Helper()
	t.Logf("L2RESULT id=%s outcome=%s rev=%s evidence=%s", id, outcome, l2SourceRev, evidence)
}

func TestL2Finance_T1WireInputPeerSelf(t *testing.T) {
	var dials atomic.Int64
	var captured atomic.Value // tg.InputPeerClass
	capture := telegram.MiddlewareFunc(func(next tg.Invoker) telegram.InvokeFunc {
		return func(ctx context.Context, input bin.Encoder, output bin.Decoder) error {
			req, ok := input.(*tg.MessagesSendMessageRequest)
			if !ok {
				return fmt.Errorf("l2finance: unexpected request %T", input)
			}
			captured.Store(&req.Peer)
			// Terminating: next is never called, so nothing reaches a connection.
			if u, ok := output.(*tg.UpdatesBox); ok {
				u.Updates = &tg.Updates{Updates: []tg.UpdateClass{&tg.UpdateMessageID{ID: 1, RandomID: req.RandomID}}}
			}
			return nil
		}
	})
	client := telegram.NewClient(1, "l2-synthetic-hash", telegram.Options{
		SessionStorage: &session.StorageMemory{},
		NoUpdates:      true,
		Resolver: dcs.Plain(dcs.PlainOptions{Dial: func(context.Context, string, string) (net.Conn, error) {
			dials.Add(1)
			return nil, errL2ExternalDial
		}}),
		Middlewares: []telegram.Middleware{capture},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	type res struct {
		id  int
		err error
	}
	done := make(chan res, 1)
	go func() {
		id, err := SendToSelfWithRandomID(ctx, client, l2AliceTG, 1, l2Marker)
		done <- res{id, err}
	}()
	var r res
	select {
	case r = <-done:
	case <-ctx.Done():
		r = res{err: ctx.Err()}
	}
	peer, _ := captured.Load().(*tg.InputPeerClass)
	if peer == nil {
		l2Record(t, "T1.wire_input_peer_self", l2CannotObserve, fmt.Sprintf(
			"captured=false resolver_dials=%d call_err=%v; middleware did not capture before connection; see T1.source_pin", dials.Load(), r.err))
		return
	}
	_, self := (*peer).(*tg.InputPeerSelf)
	if !self || dials.Load() != 0 || r.err != nil {
		l2Record(t, "T1.wire_input_peer_self", l2Fail, fmt.Sprintf(
			"captured_peer=%T self=%t resolver_dials=%d call_err=%v", *peer, self, dials.Load(), r.err))
		t.Errorf("T1.wire_input_peer_self: peer=%T self=%t dials=%d err=%v", *peer, self, dials.Load(), r.err)
		return
	}
	l2Record(t, "T1.wire_input_peer_self", l2Pass, fmt.Sprintf("captured_peer=%T resolver_dials=%d call_err=%v", *peer, dials.Load(), r.err))
}

func TestL2Finance_T1SourcePin(t *testing.T) {
	b, err := os.ReadFile("sendself.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	for _, fn := range []string{"func SendToSelf(", "func SendToSelfWithRandomID("} {
		i := strings.Index(src, fn)
		if i < 0 {
			t.Fatalf("%s not found", fn)
		}
		body := src[i:]
		if j := strings.Index(body, "\n}\n"); j >= 0 {
			body = body[:j]
		}
		if !strings.Contains(body, "&tg.InputPeerSelf{}") {
			t.Fatalf("%s does not pass &tg.InputPeerSelf{}", fn)
		}
	}
	l2Record(t, "T1.source_pin", l2Pass, "source evidence only (not wire): SendToSelf and SendToSelfWithRandomID pass &tg.InputPeerSelf{} in sendself.go")
}
