package output

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/pa/output/safetext"
)

// Only a failure before the request was written, or an explicit ok:false,
// says the message was not delivered. Everything else may have delivered
// it and wraps ErrOutcomeUnknown (S1-O4).
func TestSendOutcomeClassification(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name    string
		reply   func(w http.ResponseWriter, r *http.Request)
		unknown bool
		api     bool
	}{
		{"ok false", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = io.WriteString(w, `{"ok":false,"error_code":429,"parameters":{"retry_after":3}}`)
		}, false, true},
		{"malformed 200", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `<html>`) }, true, false},
		{"no ok field", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{"result":{}}`) }, true, false},
		{"ok true on a 502", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = io.WriteString(w, `{"ok":true}`)
		}, true, false},
		{"connection dropped after the request", func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.ReadAll(r.Body)
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = conn.Close()
			}
		}, true, false},
		{"body cut short", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", "100")
			_, _ = io.WriteString(w, `{"ok":`)
			if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
				_ = conn.Close()
			}
		}, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(tc.reply))
			defer srv.Close()
			s := &Sender{hc: srv.Client(), base: srv.URL, token: testToken}
			err := s.Send(ctx, aliceChat, anyText, nil)
			var ae *APIError
			if err == nil || errors.Is(err, ErrOutcomeUnknown) != tc.unknown || errors.As(err, &ae) != tc.api {
				t.Fatalf("err = %v: unknown %v api %v, want %v %v", err, errors.Is(err, ErrOutcomeUnknown), errors.As(err, &ae), tc.unknown, tc.api)
			}
			if strings.Contains(err.Error(), testToken) {
				t.Fatalf("token leaked: %v", err)
			}
		})
	}
}

// A context that ends while the request is out is unknown; one that ended
// before anything was written, or a refused dial, is not.
func TestSendOutcomeContextAndDial(t *testing.T) {
	hold := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		<-hold
	}))
	defer srv.Close()
	defer close(hold)
	s := &Sender{hc: srv.Client(), base: srv.URL, token: testToken}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if err := s.Send(ctx, aliceChat, anyText, nil); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("deadline mid-request: %v, want ErrOutcomeUnknown", err)
	}
	done, cancelDone := context.WithCancel(context.Background())
	cancelDone()
	if err := s.Send(done, aliceChat, anyText, nil); err == nil || errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("context ended before the write: %v, want a known failure", err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	s.base = "http://" + addr
	if err := s.Send(context.Background(), aliceChat, anyText, nil); err == nil || errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("refused dial: %v, want a known failure", err)
	}
}

// SendFrom resumes after the delivered parts and reports each one.
func TestSendFromResumes(t *testing.T) {
	f, s := newFake(t)
	text, err := safetext.Render(strings.TrimSpace(strings.Repeat("word ", 2000)), safetext.UserText{})
	if err != nil || text.Parts() != 3 {
		t.Fatalf("render: %d parts, %v", text.Parts(), err)
	}
	var reported []int
	if err := s.SendFrom(context.Background(), aliceChat, text, nil, 1, func(n int) error {
		reported = append(reported, n)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	calls := len(f.calls)
	first := f.calls[0].body["text"]
	f.mu.Unlock()
	if calls != 2 || first != text.Part(1) || len(reported) != 2 || reported[0] != 2 || reported[1] != 3 {
		t.Fatalf("calls %d, reported %v: want parts 2 and 3 only", calls, reported)
	}
	stop := errors.New("not recorded")
	if err := s.SendFrom(context.Background(), aliceChat, text, nil, 0, func(int) error { return stop }); !errors.Is(err, stop) {
		t.Fatalf("callback error: %v", err)
	}
	f.mu.Lock()
	calls = len(f.calls)
	f.mu.Unlock()
	if calls != 3 {
		t.Fatalf("calls %d: a failed record must stop the send after that part", calls)
	}
	for _, from := range []int{-1, 4} {
		if err := s.SendFrom(context.Background(), aliceChat, text, nil, from, nil); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("from %d: %v", from, err)
		}
	}
}
