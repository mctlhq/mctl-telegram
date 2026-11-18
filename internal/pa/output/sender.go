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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/mctlhq/mctl-telegram/internal/pa/egress"
)

// This file is the only place under internal/pa that names a Bot API send
// method or builds a Bot API URL (TestS1O1_SenderIsTheOnlyBotAPICallSite).

const (
	botAPIHost    = "api.telegram.org"
	botAPIBaseURL = "https://" + botAPIHost

	methodSendMessage         = "sendMessage"
	methodAnswerCallbackQuery = "answerCallbackQuery"

	// maxTextUTF16 is the Bot API limit on message text, in UTF-16 units.
	maxTextUTF16 = 4096
	// maxCallbackData is the Bot API limit on callback_data, in bytes.
	maxCallbackData = 64
	// maxCallbackAnswerUTF16 is the limit on answerCallbackQuery text.
	maxCallbackAnswerUTF16 = 200
)

// Errors returned by Sender.
var (
	ErrEmptyText       = errors.New("pa output: empty text")
	ErrInvalidChat     = errors.New("pa output: invalid chat id")
	ErrInvalidKeyboard = errors.New("pa output: invalid keyboard")
	ErrInvalidConfig   = errors.New("pa output: invalid config")
)

// Button is one inline keyboard button. It can only carry callback data:
// the type has no field for a URL, login URL, web app, inline query or
// game, so a URL button cannot be expressed (S1-O3). The label is a server
// Template; Data is a server-generated opaque id.
type Button struct {
	Label Template
	Data  string
}

// Keyboard is an inline keyboard: rows of callback buttons.
type Keyboard [][]Button

// Config configures a production Sender.
type Config struct {
	// Token is the PA bot's token. Required.
	Token string
	// DeniedPrefixes are passed to the egress client (egress.Config).
	DeniedPrefixes []netip.Prefix
}

// Sender sends bot messages. It is safe for concurrent use.
type Sender struct {
	hc    *http.Client
	base  string
	token string
}

// NewSender builds a Sender whose requests go through the PA egress client
// (internal/pa/egress, PurposeBotAPI), allowed to reach only the Bot API
// host over HTTPS, with no redirects.
func NewSender(cfg Config) (*Sender, error) {
	if cfg.Token == "" {
		return nil, fmt.Errorf("%w: no bot token", ErrInvalidConfig)
	}
	hc, err := egress.New(egress.Config{
		Purpose:        egress.PurposeBotAPI,
		AllowedHosts:   []string{botAPIHost},
		DeniedPrefixes: cfg.DeniedPrefixes,
	})
	if err != nil {
		return nil, fmt.Errorf("pa output: egress client: %w", err)
	}
	return &Sender{hc: hc, base: botAPIBaseURL, token: cfg.Token}, nil
}

// linkPreviewOptions is sent on every message (S1-O1).
type linkPreviewOptions struct {
	IsDisabled bool `json:"is_disabled"`
}

type wireButton struct {
	Text         string `json:"text"`
	CallbackData string `json:"callback_data"`
}

type wireMarkup struct {
	InlineKeyboard [][]wireButton `json:"inline_keyboard"`
}

// sendMessageRequest is the full sendMessage body. It has no parse_mode and
// no entities field, so the text is always plain (S1-O3).
type sendMessageRequest struct {
	ChatID             int64              `json:"chat_id"`
	Text               string             `json:"text"`
	LinkPreviewOptions linkPreviewOptions `json:"link_preview_options"`
	ReplyMarkup        *wireMarkup        `json:"reply_markup,omitempty"`
}

// answerCallbackRequest has no url field: a callback answer never opens a
// link or a game.
type answerCallbackRequest struct {
	CallbackQueryID string `json:"callback_query_id"`
	Text            string `json:"text,omitempty"`
}

// Send sends text to a private chat, one message per part of text (Render
// and ServerText cut it to the Bot API limit); the keyboard, if any, goes on
// the last one. Every message has link previews disabled. It stops at the
// first failure.
func (s *Sender) Send(ctx context.Context, chatID int64, text Text, kb Keyboard) error {
	if chatID <= 0 {
		// The PA serves private chats only, whose id is the user id.
		return ErrInvalidChat
	}
	if len(text.parts) == 0 {
		return ErrEmptyText
	}
	markup, err := kb.wire()
	if err != nil {
		return err
	}
	for i, p := range text.parts {
		if strings.TrimSpace(p) == "" || utf16Len(p) > maxTextUTF16 {
			return ErrEmptyText
		}
		req := sendMessageRequest{
			ChatID:             chatID,
			Text:               p,
			LinkPreviewOptions: linkPreviewOptions{IsDisabled: true},
		}
		if i == len(text.parts)-1 {
			req.ReplyMarkup = markup
		}
		if err := s.call(ctx, methodSendMessage, req); err != nil {
			return err
		}
	}
	return nil
}

// AnswerCallback answers a callback query, with an optional short
// server-authored notice. It never carries a URL.
func (s *Sender) AnswerCallback(ctx context.Context, callbackQueryID string, notice Template) error {
	if callbackQueryID == "" {
		return fmt.Errorf("%w: empty callback query id", ErrInvalidConfig)
	}
	if utf16Len(notice.s) > maxCallbackAnswerUTF16 {
		return fmt.Errorf("%w: callback notice too long", ErrInvalidConfig)
	}
	return s.call(ctx, methodAnswerCallbackQuery, answerCallbackRequest{
		CallbackQueryID: callbackQueryID,
		Text:            notice.s,
	})
}

func (kb Keyboard) wire() (*wireMarkup, error) {
	if len(kb) == 0 {
		return nil, nil
	}
	m := &wireMarkup{InlineKeyboard: make([][]wireButton, 0, len(kb))}
	for _, row := range kb {
		if len(row) == 0 {
			return nil, fmt.Errorf("%w: empty row", ErrInvalidKeyboard)
		}
		wr := make([]wireButton, 0, len(row))
		for _, b := range row {
			if strings.TrimSpace(b.Label.s) == "" {
				return nil, fmt.Errorf("%w: empty label", ErrInvalidKeyboard)
			}
			if b.Data == "" || len(b.Data) > maxCallbackData || !utf8.ValidString(b.Data) {
				return nil, fmt.Errorf("%w: callback data must be 1..%d bytes of UTF-8", ErrInvalidKeyboard, maxCallbackData)
			}
			wr = append(wr, wireButton{Text: b.Label.s, CallbackData: b.Data})
		}
		m.InlineKeyboard = append(m.InlineKeyboard, wr)
	}
	return m, nil
}

// call posts one Bot API method. Any failure -- transport, non-200, ok:false,
// malformed body -- is an error (I9). The token never appears in an error.
func (s *Sender) call(ctx context.Context, method string, body any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("pa output %s: encode: %w", method, err)
	}
	endpoint := strings.TrimRight(s.base, "/") + "/bot" + s.token + "/" + method
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("pa output %s: build request failed", method)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.hc.Do(req)
	if err != nil {
		// *url.Error embeds the URL, which embeds the token.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("pa output %s: request failed: %s", method, s.redact(err.Error()))
	}
	defer resp.Body.Close()
	raw, err := egress.ReadBody(resp)
	if err != nil {
		return fmt.Errorf("pa output %s: read body: %s", method, s.redact(err.Error()))
	}
	var env struct {
		OK          bool   `json:"ok"`
		ErrorCode   int    `json:"error_code"`
		Description string `json:"description"`
		Parameters  *struct {
			RetryAfter int `json:"retry_after"`
		} `json:"parameters"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("pa output %s: malformed response (HTTP %d)", method, resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK || !env.OK {
		retry := 0
		if env.Parameters != nil {
			retry = env.Parameters.RetryAfter
		}
		return &APIError{Method: method, Status: resp.StatusCode, Code: env.ErrorCode, Description: s.redact(env.Description), RetryAfter: retry}
	}
	return nil
}

func (s *Sender) redact(msg string) string {
	return strings.ReplaceAll(msg, s.token, "[redacted]")
}

// APIError is a Bot API refusal.
type APIError struct {
	Method      string
	Status      int
	Code        int
	Description string
	// RetryAfter is the flood-wait in seconds on a 429, else 0. Sender does
	// not retry; the caller decides.
	RetryAfter int
}

func (e *APIError) Error() string {
	return fmt.Sprintf("pa output %s: refused (HTTP %d, code %d): %s", e.Method, e.Status, e.Code, e.Description)
}

func utf16Len(s string) int {
	n := 0
	for _, r := range s {
		n += utf16.RuneLen(r)
	}
	return n
}

// split cuts s into parts of at most max UTF-16 units, never inside a rune,
// preferring the last newline, then the last space, in the second half of a
// part. Whitespace-only parts are dropped, as the Bot API refuses them.
// A cut can turn the tail of a token into a new token (4095 x "x" followed
// by "a1.2.3.4/..." leaves "1.2.3.4/..." in the next part), so Render
// neutralises every part again after splitting.
func split(s string, max int) []string {
	var parts []string
	for utf16Len(s) > max {
		cut, n := 0, 0
		for i, r := range s {
			w := utf16.RuneLen(r)
			if n+w > max {
				break
			}
			n += w
			cut = i + utf8.RuneLen(r)
		}
		head := s[:cut]
		if i := strings.LastIndexByte(head, '\n'); i > cut/2 {
			cut = i + 1
		} else if i := strings.LastIndexByte(head, ' '); i > cut/2 {
			cut = i + 1
		}
		if strings.TrimSpace(s[:cut]) != "" {
			parts = append(parts, s[:cut])
		}
		s = s[cut:]
	}
	if strings.TrimSpace(s) != "" {
		parts = append(parts, s)
	}
	return parts
}
