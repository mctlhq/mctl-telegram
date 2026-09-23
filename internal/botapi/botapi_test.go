package botapi

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/notify"
)

const token = "123456:AAH-secret-token"

func TestSendMessage_PostsPlainTextForm(t *testing.T) {
	var gotPath, gotChat, gotText, gotParse string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotPath, gotChat, gotText, gotParse = r.URL.Path, r.PostForm.Get("chat_id"), r.PostForm.Get("text"), r.PostForm.Get("parse_mode")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	c := &Client{Token: token, BaseURL: srv.URL}
	if err := c.SendMessage(context.Background(), 4242, "hi <b>there</b>"); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/bot"+token+"/sendMessage" || gotChat != "4242" || gotText != "hi <b>there</b>" || gotParse != "" {
		t.Fatalf("path=%q chat=%q text=%q parse_mode=%q", gotPath, gotChat, gotText, gotParse)
	}
}

func TestSendMessage_TypedErrorWithRetryAfter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"ok":false,"error_code":429,"description":"Too Many Requests: retry after 7","parameters":{"retry_after":7}}`))
	}))
	defer srv.Close()
	err := (&Client{Token: token, BaseURL: srv.URL}).SendMessage(context.Background(), 1, "x")
	var apiErr *notify.APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != 429 || apiErr.RetryAfter != 7*time.Second ||
		apiErr.Description != "Too Many Requests: retry after 7" {
		t.Fatalf("err = %#v", err)
	}
}

func TestSendMessage_NonJSONBodyFallsBackToText(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("  upstream down \n"))
	}))
	defer srv.Close()
	err := (&Client{Token: token, BaseURL: srv.URL}).SendMessage(context.Background(), 1, "x")
	var apiErr *notify.APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != 502 || apiErr.Description != "upstream down" || apiErr.RetryAfter != 0 {
		t.Fatalf("err = %#v", err)
	}
}

func TestSendMessage_TransportErrorNeverCarriesToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close() // connection refused
	err := (&Client{Token: token, BaseURL: url}).SendMessage(context.Background(), 1, "x")
	if err == nil || strings.Contains(err.Error(), "AAH-secret-token") {
		t.Fatalf("err = %v", err)
	}
	// The broadcast worker retries only failures that provably never
	// reached Telegram; a refused connection must stay recognisable as a
	// dial error through the token-stripping wrap.
	var opErr *net.OpError
	if !errors.As(err, &opErr) || opErr.Op != "dial" {
		t.Fatalf("connection refused is not a dial *net.OpError: %#v", err)
	}
}

func TestSendMessage_RequiresToken(t *testing.T) {
	if err := (&Client{}).SendMessage(context.Background(), 1, "x"); err == nil {
		t.Fatal("empty token must be refused")
	}
}
