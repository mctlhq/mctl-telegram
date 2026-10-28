package botapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/notify"
)

func TestGetChat_ReadsChatAndSendsNoText(t *testing.T) {
	var gotPath, gotChat, gotText string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotPath, gotChat, gotText = r.URL.Path, r.PostForm.Get("chat_id"), r.PostForm.Get("text")
		_, _ = w.Write([]byte(`{"ok":true,"result":{"id":4242,"type":"private"}}`))
	}))
	defer srv.Close()
	if err := (&Client{Token: token, BaseURL: srv.URL}).GetChat(context.Background(), 4242); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/bot"+token+"/getChat" || gotChat != "4242" || gotText != "" {
		t.Fatalf("path=%q chat=%q text=%q", gotPath, gotChat, gotText)
	}
}

func TestGetChat_ChatNotFoundIsTypedError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"ok":false,"error_code":400,"description":"Bad Request: chat not found"}`))
	}))
	defer srv.Close()
	err := (&Client{Token: token, BaseURL: srv.URL}).GetChat(context.Background(), 1)
	var apiErr *notify.APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != 400 || apiErr.Description != "Bad Request: chat not found" {
		t.Fatalf("err = %v", err)
	}
}
