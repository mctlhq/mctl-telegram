// Copyright 2025 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package output

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

const testToken = "123456:test-token-alice"

// Alice's synthetic private chat id.
const aliceChat int64 = 100001

type recorded struct {
	path string
	body map[string]any
}

type fakeBotAPI struct {
	mu    sync.Mutex
	calls []recorded
	reply func(w http.ResponseWriter)
}

func newFake(t *testing.T) (*fakeBotAPI, *Sender) {
	t.Helper()
	f := &fakeBotAPI{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Errorf("request body is not JSON: %v", err)
		}
		f.mu.Lock()
		f.calls = append(f.calls, recorded{path: r.URL.Path, body: m})
		reply := f.reply
		f.mu.Unlock()
		if reply != nil {
			reply(w)
			return
		}
		_, _ = io.WriteString(w, `{"ok":true,"result":{}}`)
	}))
	t.Cleanup(srv.Close)
	return f, &Sender{hc: srv.Client(), base: srv.URL, token: testToken}
}

// S1-O1: every sendMessage carries link_preview_options.is_disabled = true:
// model text, server text, with a keyboard, and every part of a split
// message. No other preview switch is ever set to enable previews.
func TestS1O1_EverySendDisablesPreviews(t *testing.T) {
	f, s := newFake(t)
	ctx := context.Background()
	allow := AllowFromUserText("https://docs.example.org/a")
	sends := []struct {
		text Text
		kb   Keyboard
	}{
		{mustRender(t, "see https://docs.example.org/a", allow), nil},
		{ServerText(tpl("Consent required.")), Keyboard{{{Label: tpl("Agree"), Data: "c:1"}}}},
		{mustRender(t, strings.Repeat("Bob wrote a long message. ", 400), UserText{}), nil},
	}
	for _, sd := range sends {
		if err := s.Send(ctx, aliceChat, sd.text, sd.kb); err != nil {
			t.Fatalf("send: %v", err)
		}
	}
	if len(f.calls) < 4 {
		t.Fatalf("want the long text split into several sends, got %d calls", len(f.calls))
	}
	for i, c := range f.calls {
		if !strings.HasSuffix(c.path, "/sendMessage") {
			t.Errorf("call %d: unexpected method %s", i, c.path)
		}
		lpo, ok := c.body["link_preview_options"].(map[string]any)
		if !ok || lpo["is_disabled"] != true {
			t.Errorf("call %d: link previews not disabled: %v", i, c.body)
		}
		if _, ok := c.body["disable_web_page_preview"]; ok {
			t.Errorf("call %d: legacy preview flag set", i)
		}
		if n := utf16Len(c.body["text"].(string)); n > maxTextUTF16 || n == 0 {
			t.Errorf("call %d: text length %d", i, n)
		}
	}
}

// S1-O3: no send ever carries parse_mode or entities, a keyboard holds only
// text + callback_data buttons, and model-rendered text never carries
// reply markup.
func TestS1O3_PlainTextAndNoURLButtons(t *testing.T) {
	f, s := newFake(t)
	ctx := context.Background()
	model := mustRender(t, `<a href="https://attacker.example">x</a> **y** [z](tg://resolve?domain=EvilBot)`, UserText{})
	if err := s.Send(ctx, aliceChat, model, nil); err != nil {
		t.Fatal(err)
	}
	kb := Keyboard{{{Label: tpl("Yes"), Data: "a:1"}, {Label: tpl("No"), Data: "a:2"}}, {{Label: tpl("Cancel"), Data: "a:3"}}}
	if err := s.Send(ctx, aliceChat, ServerText(tpl("Confirm?")), kb); err != nil {
		t.Fatal(err)
	}
	allowedTop := map[string]bool{"chat_id": true, "text": true, "link_preview_options": true, "reply_markup": true}
	for i, c := range f.calls {
		for k := range c.body {
			if !allowedTop[k] {
				t.Errorf("call %d: unexpected field %q", i, k)
			}
		}
		if text := c.body["text"].(string); strings.ContainsAny(text, "<>*") || strings.Contains(text, "://") {
			t.Errorf("call %d: markup or live link in %q", i, text)
		}
	}
	if _, ok := f.calls[0].body["reply_markup"]; ok {
		t.Errorf("model text carried reply_markup")
	}
	rm, ok := f.calls[1].body["reply_markup"].(map[string]any)
	if !ok || len(rm) != 1 {
		t.Fatalf("keyboard markup: %v", f.calls[1].body["reply_markup"])
	}
	rows := rm["inline_keyboard"].([]any)
	for _, row := range rows {
		for _, b := range row.([]any) {
			btn := b.(map[string]any)
			if len(btn) != 2 || btn["text"] == nil || btn["callback_data"] == nil {
				t.Errorf("button has fields other than text and callback_data: %v", btn)
			}
		}
	}
}

func TestSendRefusesBadInput(t *testing.T) {
	f, s := newFake(t)
	ctx := context.Background()
	if err := s.Send(ctx, aliceChat, Text{}, nil); !errors.Is(err, ErrEmptyText) {
		t.Errorf("zero Text: %v", err)
	}
	if err := s.Send(ctx, aliceChat, mustRender(t, " \n ", UserText{}), nil); !errors.Is(err, ErrEmptyText) {
		t.Errorf("blank Text: %v", err)
	}
	if err := s.Send(ctx, -100200, ServerText(tpl("x")), nil); !errors.Is(err, ErrInvalidChat) {
		t.Errorf("group chat id: %v", err)
	}
	if err := s.Send(ctx, aliceChat, Text{parts: []string{strings.Repeat("z", maxTextUTF16+1)}}, nil); !errors.Is(err, ErrPartTooLong) {
		t.Errorf("oversize part: %v", err)
	}
	for _, kb := range []Keyboard{
		{{}},
		{{{Label: tpl(""), Data: "a"}}},
		{{{Label: tpl("x"), Data: ""}}},
		{{{Label: tpl("x"), Data: strings.Repeat("d", maxCallbackData+1)}}},
	} {
		if err := s.Send(ctx, aliceChat, ServerText(tpl("x")), kb); !errors.Is(err, ErrInvalidKeyboard) {
			t.Errorf("keyboard %v: %v", kb, err)
		}
	}
	if len(f.calls) != 0 {
		t.Fatalf("refused input still reached the Bot API: %d calls", len(f.calls))
	}
}

// A refusal, a non-200 or a malformed body is an error, never a silent
// success (I9), and the token never appears in it.
func TestSendFailuresAreErrors(t *testing.T) {
	f, s := newFake(t)
	ctx := context.Background()
	replies := map[string]func(w http.ResponseWriter){
		"ok false": func(w http.ResponseWriter) {
			_, _ = io.WriteString(w, `{"ok":false,"error_code":400,"description":"bad `+testToken+`"}`)
		},
		"429": func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = io.WriteString(w, `{"ok":false,"error_code":429,"description":"Too Many Requests","parameters":{"retry_after":7}}`)
		},
		"500 with ok true": func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, `{"ok":true}`)
		},
		"malformed": func(w http.ResponseWriter) { _, _ = io.WriteString(w, `not json`) },
	}
	for name, r := range replies {
		f.mu.Lock()
		f.reply = r
		f.mu.Unlock()
		err := s.Send(ctx, aliceChat, ServerText(tpl("x")), nil)
		if err == nil {
			t.Errorf("%s: want error", name)
			continue
		}
		if strings.Contains(err.Error(), testToken) {
			t.Errorf("%s: token leaked in %q", name, err)
		}
		var ae *APIError
		if name == "429" && (!errors.As(err, &ae) || ae.RetryAfter != 7) {
			t.Errorf("429: want APIError with RetryAfter 7, got %v", err)
		}
	}
	s.base = "http://127.0.0.1:1"
	if err := s.Send(ctx, aliceChat, ServerText(tpl("x")), nil); err == nil || strings.Contains(err.Error(), testToken) {
		t.Errorf("transport failure: %v", err)
	}
}

func TestAnswerCallbackHasNoURL(t *testing.T) {
	f, s := newFake(t)
	if err := s.AnswerCallback(context.Background(), "cbq-1", tpl("Saved.")); err != nil {
		t.Fatal(err)
	}
	c := f.calls[0]
	if !strings.HasSuffix(c.path, "/answerCallbackQuery") {
		t.Fatalf("path %s", c.path)
	}
	for k := range c.body {
		if k != "callback_query_id" && k != "text" {
			t.Errorf("unexpected field %q", k)
		}
	}
	if err := s.AnswerCallback(context.Background(), "", Template{}); err == nil {
		t.Error("empty callback id accepted")
	}
}

func TestNewSenderUsesEgress(t *testing.T) {
	if _, err := NewSender(Config{}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("no token: %v", err)
	}
	s, err := NewSender(Config{Token: testToken})
	if err != nil {
		t.Fatal(err)
	}
	if s.base != "https://api.telegram.org" || s.hc == nil || s.hc.Timeout <= 0 {
		t.Fatalf("unexpected sender %+v", s)
	}
	// The egress client refuses any host but the Bot API host.
	s.base = "https://attacker.example"
	err = s.Send(context.Background(), aliceChat, ServerText(tpl("x")), nil)
	if err == nil || !strings.Contains(err.Error(), "allowlist") {
		t.Fatalf("egress client must refuse a non-Bot-API host, got %v", err)
	}
}

func TestSplit(t *testing.T) {
	s := strings.Repeat("a", 10) + "\n" + strings.Repeat("b", 10)
	got := split(s, 15)
	if len(got) != 2 || got[0] != strings.Repeat("a", 10)+"\n" || got[1] != strings.Repeat("b", 10) {
		t.Fatalf("got %q", got)
	}
	// A rune outside the BMP counts as two UTF-16 units and is never cut.
	emoji := strings.Repeat("\U0001F600", 5)
	for _, p := range split(emoji, 3) {
		if utf16Len(p) > 3 || !strings.HasPrefix(p, "\U0001F600") {
			t.Fatalf("bad part %q", p)
		}
	}
}
