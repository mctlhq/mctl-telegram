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
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"unicode/utf8"

	"github.com/mctlhq/mctl-telegram/internal/pa/egress"
	"github.com/mctlhq/mctl-telegram/internal/pa/output/safetext"
)

// This file is the only place under internal/pa that names a Bot API send
// method or builds a Bot API URL (TestS1O1_SenderIsTheOnlyBotAPICallSite).

const (
	botAPIHost    = "api.telegram.org"
	botAPIBaseURL = "https://" + botAPIHost

	methodSendMessage         = "sendMessage"
	methodAnswerCallbackQuery = "answerCallbackQuery"

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
	// ErrPartTooLong means a Text part is over the Bot API limit. Render and
	// ServerText never produce one, so it marks a bug, not bad input.
	ErrPartTooLong = errors.New("pa output: message part over the Bot API limit")
	// ErrOutcomeUnknown means the request may have reached the Bot API and
	// its answer was not read: a transport failure after the request was
	// written (including a cancelled or expired context), a body that
	// could not be read, or an answer that is not a Bot API envelope.
	// Whether the message was delivered is not known, so it must not be
	// sent again (send-once, S1-O4).
	ErrOutcomeUnknown = errors.New("pa output: Bot API outcome unknown")
)

// Button is one inline keyboard button. It can only carry callback data:
// the type has no field for a URL, login URL, web app, inline query or
// game, so a URL button cannot be expressed (S1-O3). The label is a server
// Template; Data is a server-generated opaque id.
type Button struct {
	Label safetext.Template
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
func (s *Sender) Send(ctx context.Context, chatID int64, text safetext.Text, kb Keyboard) error {
	return s.SendFrom(ctx, chatID, text, kb, 0, nil)
}

// SendFrom sends the parts of text from index from on, and calls sent with
// the number of parts delivered so far after each part the Bot API
// accepted, so that a retry can resume after the last delivered part
// instead of sending the earlier ones again. An error from sent stops the
// send and is returned as is. Every part is checked before the first one
// is sent: a part that would be refused never leaves earlier parts behind.
func (s *Sender) SendFrom(ctx context.Context, chatID int64, text safetext.Text, kb Keyboard, from int, sent func(delivered int) error) error {
	parts := make([]string, text.Parts())
	for i := range parts {
		parts[i] = text.Part(i)
	}
	return s.sendParts(ctx, chatID, parts, kb, from, sent)
}

// sendParts is SendFrom on the parts of a Text. It takes a plain slice only
// so that tests can hand it parts Render and ServerText never produce; the
// only production caller is SendFrom.
func (s *Sender) sendParts(ctx context.Context, chatID int64, parts []string, kb Keyboard, from int, sent func(delivered int) error) error {
	if chatID <= 0 {
		// The PA serves private chats only, whose id is the user id.
		return ErrInvalidChat
	}
	if len(parts) == 0 {
		return ErrEmptyText
	}
	if len(parts) > safetext.MaxParts {
		return safetext.ErrTooLong
	}
	if from < 0 || from > len(parts) {
		return fmt.Errorf("%w: resume at part %d of %d", ErrInvalidConfig, from, len(parts))
	}
	markup, err := kb.wire()
	if err != nil {
		return err
	}
	for i, p := range parts {
		if strings.TrimSpace(p) == "" {
			return ErrEmptyText
		}
		if n := safetext.UTF16Len(p); n > safetext.MaxPartUTF16 {
			return fmt.Errorf("%w: part %d is %d UTF-16 units, limit %d", ErrPartTooLong, i, n, safetext.MaxPartUTF16)
		}
	}
	for i := from; i < len(parts); i++ {
		req := sendMessageRequest{
			ChatID:             chatID,
			Text:               parts[i],
			LinkPreviewOptions: linkPreviewOptions{IsDisabled: true},
		}
		if i == len(parts)-1 {
			req.ReplyMarkup = markup
		}
		if err := s.call(ctx, methodSendMessage, req); err != nil {
			return err
		}
		if sent != nil {
			if err := sent(i + 1); err != nil {
				return err
			}
		}
	}
	return nil
}

// AnswerCallback answers a callback query, with an optional short
// server-authored notice. It never carries a URL.
func (s *Sender) AnswerCallback(ctx context.Context, callbackQueryID string, notice safetext.Template) error {
	if callbackQueryID == "" {
		return fmt.Errorf("%w: empty callback query id", ErrInvalidConfig)
	}
	if safetext.UTF16Len(notice.String()) > maxCallbackAnswerUTF16 {
		return fmt.Errorf("%w: callback notice too long", ErrInvalidConfig)
	}
	return s.call(ctx, methodAnswerCallbackQuery, answerCallbackRequest{
		CallbackQueryID: callbackQueryID,
		Text:            notice.String(),
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
			if strings.TrimSpace(b.Label.String()) == "" {
				return nil, fmt.Errorf("%w: empty label", ErrInvalidKeyboard)
			}
			if b.Data == "" || len(b.Data) > maxCallbackData || !utf8.ValidString(b.Data) {
				return nil, fmt.Errorf("%w: callback data must be 1..%d bytes of UTF-8", ErrInvalidKeyboard, maxCallbackData)
			}
			wr = append(wr, wireButton{Text: b.Label.String(), CallbackData: b.Data})
		}
		m.InlineKeyboard = append(m.InlineKeyboard, wr)
	}
	return m, nil
}

// call posts one Bot API method. Any failure -- transport, non-200, ok:false,
// malformed body -- is an error (I9). The token never appears in an error.
//
// Only two failures say the message was not delivered: one before the
// request was written, and an explicit ok:false answer (*APIError). Every
// other failure wraps ErrOutcomeUnknown.
func (s *Sender) call(ctx context.Context, method string, body any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("pa output %s: encode: %w", method, err)
	}
	endpoint := strings.TrimRight(s.base, "/") + "/bot" + s.token + "/" + method
	// wrote is set once the request headers went out: from then on the Bot
	// API may act on the request even if no answer comes back.
	var wrote atomic.Bool
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		WroteHeaders: func() { wrote.Store(true) },
	})
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
		if wrote.Load() {
			return fmt.Errorf("%w: pa output %s: request failed after it was sent: %s", ErrOutcomeUnknown, method, s.redact(err.Error()))
		}
		return fmt.Errorf("pa output %s: request failed: %s", method, s.redact(err.Error()))
	}
	defer resp.Body.Close()
	raw, err := egress.ReadBody(resp)
	if err != nil {
		return fmt.Errorf("%w: pa output %s: read body: %s", ErrOutcomeUnknown, method, s.redact(err.Error()))
	}
	var env struct {
		OK          *bool  `json:"ok"`
		ErrorCode   int    `json:"error_code"`
		Description string `json:"description"`
		Parameters  *struct {
			RetryAfter int `json:"retry_after"`
		} `json:"parameters"`
	}
	if err := json.Unmarshal(raw, &env); err != nil || env.OK == nil {
		return fmt.Errorf("%w: pa output %s: malformed response (HTTP %d)", ErrOutcomeUnknown, method, resp.StatusCode)
	}
	switch {
	case !*env.OK:
		retry := 0
		if env.Parameters != nil {
			retry = env.Parameters.RetryAfter
		}
		return &APIError{Method: method, Status: resp.StatusCode, Code: env.ErrorCode, Description: s.redact(env.Description), RetryAfter: retry}
	case resp.StatusCode != http.StatusOK:
		// ok:true on an error status is not an answer the Bot API gives.
		return fmt.Errorf("%w: pa output %s: ok:true with HTTP %d", ErrOutcomeUnknown, method, resp.StatusCode)
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
