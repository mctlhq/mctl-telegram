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

func TestSendHTMLMessage_SetsParseModeAndKeepsTextVerbatim(t *testing.T) {
	var gotPath, gotText, gotParse, gotPreview string
	var requests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		_ = r.ParseForm()
		gotPath, gotText, gotParse = r.URL.Path, r.PostForm.Get("text"), r.PostForm.Get("parse_mode")
		gotPreview = r.PostForm.Get("link_preview_options")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	const body = `<b>hi</b> <a href="https://example.com/?a=1&amp;b=2">x</a>`
	if err := (&Client{Token: token, BaseURL: srv.URL}).SendHTMLMessage(context.Background(), 4242, body); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/bot"+token+"/sendMessage" || gotParse != "HTML" || gotText != body || requests != 1 {
		t.Fatalf("path=%q parse_mode=%q text=%q requests=%d", gotPath, gotParse, gotText, requests)
	}
	if gotPreview != `{"is_disabled":true}` {
		t.Fatalf("link_preview_options = %q, want the link preview disabled", gotPreview)
	}
}

// A markup rejection comes back as the typed error and the client does not
// try the same text again without a parse mode.
func TestSendHTMLMessage_RejectionIsTypedAndNotRetriedAsPlain(t *testing.T) {
	var parseModes []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		parseModes = append(parseModes, r.PostForm.Get("parse_mode"))
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"ok":false,"error_code":400,"description":"Bad Request: can't parse entities: Unsupported start tag"}`))
	}))
	defer srv.Close()
	err := (&Client{Token: token, BaseURL: srv.URL}).SendHTMLMessage(context.Background(), 1, "<x>")
	var apiErr *notify.APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != 400 || !strings.Contains(apiErr.Description, "can't parse entities") {
		t.Fatalf("err = %#v", err)
	}
	if len(parseModes) != 1 || parseModes[0] != "HTML" {
		t.Fatalf("requests with parse modes %v, want exactly one HTML request", parseModes)
	}
	if strings.Contains(err.Error(), token) {
		t.Fatal("error leaks the bot token")
	}
}
