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
	"regexp"
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
	methodSetMyCommands       = "setMyCommands"

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
// game, so a URL button cannot be expressed in a Keyboard (S1-O3). The one
// URL-bearing button the bot sends is SendWebApp's, which opens only the
// configured linking Mini App. The label is a server Template; Data is a
// server-generated opaque id.
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
	// WebAppURL is the linking Mini App URL (PA_APP_URL): an https URL
	// without query, fragment or userinfo. SendWebApp accepts this URL
	// with a link token and nothing else. Empty disables SendWebApp.
	WebAppURL string
	// Languages picks each chat's language for server texts and labels
	// (Text.In, Template.In); nil sends English.
	Languages *Languages
}

// Sender sends bot messages. It is safe for concurrent use.
type Sender struct {
	hc    *http.Client
	base  string
	token string
	// webApp is the only URL a web_app button may open (SendWebApp), nil
	// when none is configured.
	webApp *url.URL
	// langs picks the language of each chat's server texts and button
	// labels; nil sends English.
	langs *Languages
	// describe renders a menu command's description in a language; nil
	// means Command.Description.In. Tests set it to reach a description
	// no literal template has.
	describe func(Command, safetext.Lang) string
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
	s := &Sender{hc: hc, base: botAPIBaseURL, token: cfg.Token, langs: cfg.Languages}
	if cfg.WebAppURL != "" {
		u, err := parseWebAppBase(cfg.WebAppURL)
		if err != nil {
			return nil, err
		}
		s.webApp = u
	}
	return s, nil
}

// parseWebAppBase checks the configured Mini App URL.
func parseWebAppBase(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Opaque != "" || u.RawQuery != "" ||
		u.ForceQuery || u.Fragment != "" || u.RawPath != "" || strings.ContainsAny(raw, "?#") || u.String() != raw {
		return nil, fmt.Errorf("%w: web app URL must be an https URL without query, fragment or userinfo", ErrInvalidConfig)
	}
	return u, nil
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

// webAppRequest is a sendMessage with exactly one web_app button. It is a
// separate type so that the callback keyboard of sendMessageRequest keeps
// no way to carry a URL.
type webAppRequest struct {
	ChatID             int64              `json:"chat_id"`
	Text               string             `json:"text"`
	LinkPreviewOptions linkPreviewOptions `json:"link_preview_options"`
	ReplyMarkup        webAppMarkup       `json:"reply_markup"`
}

type webAppMarkup struct {
	InlineKeyboard [][]webAppButton `json:"inline_keyboard"`
}

type webAppButton struct {
	Text   string     `json:"text"`
	WebApp webAppInfo `json:"web_app"`
}

type webAppInfo struct {
	URL string `json:"url"`
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
	lang := s.langs.Of(chatID)
	text = text.In(lang)
	parts := make([]string, text.Parts())
	for i := range parts {
		parts[i] = text.Part(i)
	}
	return s.sendParts(ctx, chatID, parts, kb.in(lang), from, sent)
}

// sendParts is SendFrom on the parts of a Text. It takes a plain slice only
// so that tests can hand it parts Render and ServerText never produce; the
// only production caller is SendFrom.
func (s *Sender) sendParts(ctx context.Context, chatID int64, parts []string, kb localKeyboard, from int, sent func(delivered int) error) error {
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

// linkTokenFormat is the link token linking.StartLink appends: 256 random
// bits, base64url without padding.
var linkTokenFormat = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// SendWebApp sends one server text with a single inline web_app button
// that opens the linking Mini App (threat model T1 step 1). It is the only
// way a message can carry a URL, and the URL must be exactly the configured
// WebAppURL with one query parameter, link, holding a well-formed link
// token: any other scheme, host, port, path, parameter, fragment or
// userinfo is refused before anything is sent (S1-O3). The text must fit
// one message, and link previews are disabled (S1-O1).
func (s *Sender) SendWebApp(ctx context.Context, chatID int64, text safetext.Text, label safetext.Template, appURL string) error {
	if chatID <= 0 {
		// web_app buttons work in private chats only, and the PA serves
		// nothing else.
		return ErrInvalidChat
	}
	if err := s.checkWebAppURL(appURL); err != nil {
		return err
	}
	lang := s.langs.Of(chatID)
	text = text.In(lang)
	labelText := label.In(lang)
	if strings.TrimSpace(labelText) == "" {
		return fmt.Errorf("%w: empty label", ErrInvalidKeyboard)
	}
	if text.Parts() != 1 {
		if text.Parts() == 0 {
			return ErrEmptyText
		}
		return fmt.Errorf("%w: a web app message must be one part", ErrPartTooLong)
	}
	part := text.Part(0)
	if strings.TrimSpace(part) == "" {
		return ErrEmptyText
	}
	if n := safetext.UTF16Len(part); n > safetext.MaxPartUTF16 {
		return fmt.Errorf("%w: %d UTF-16 units, limit %d", ErrPartTooLong, n, safetext.MaxPartUTF16)
	}
	return s.call(ctx, methodSendMessage, webAppRequest{
		ChatID:             chatID,
		Text:               part,
		LinkPreviewOptions: linkPreviewOptions{IsDisabled: true},
		ReplyMarkup: webAppMarkup{InlineKeyboard: [][]webAppButton{{
			{Text: labelText, WebApp: webAppInfo{URL: appURL}},
		}}},
	})
}

// checkWebAppURL accepts exactly <WebAppURL>?link=<token>.
func (s *Sender) checkWebAppURL(raw string) error {
	if s.webApp == nil {
		return fmt.Errorf("%w: no web app URL configured", ErrInvalidKeyboard)
	}
	refuse := fmt.Errorf("%w: web app URL is not the linking Mini App", ErrInvalidKeyboard)
	base, query, ok := strings.Cut(raw, "?")
	if !ok || base != s.webApp.String() {
		return refuse
	}
	// Both halves are compared as strings, so nothing is left to a URL
	// parser: the base is byte-equal to the configured URL, which has no
	// query, fragment or userinfo, and the query is exactly one link
	// parameter whose value cannot hold '&', '#', '%' or '='.
	tok, ok := strings.CutPrefix(query, "link=")
	if !ok || !linkTokenFormat.MatchString(tok) {
		return refuse
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

// in returns kb with each label's text in lang. Labels stay registry
// templates; only which of their literals is sent changes.
func (kb Keyboard) in(lang safetext.Lang) localKeyboard {
	if len(kb) == 0 {
		return nil
	}
	out := make(localKeyboard, len(kb))
	for i, row := range kb {
		out[i] = make([]localButton, len(row))
		for j, b := range row {
			out[i][j] = localButton{label: b.Label.In(lang), data: b.Data}
		}
	}
	return out
}

// localKeyboard is a Keyboard with its labels resolved to one language.
type localKeyboard [][]localButton

type localButton struct {
	label string
	data  string
}

func (kb localKeyboard) wire() (*wireMarkup, error) {
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
			if strings.TrimSpace(b.label) == "" {
				return nil, fmt.Errorf("%w: empty label", ErrInvalidKeyboard)
			}
			if b.data == "" || len(b.data) > maxCallbackData || !utf8.ValidString(b.data) {
				return nil, fmt.Errorf("%w: callback data must be 1..%d bytes of UTF-8", ErrInvalidKeyboard, maxCallbackData)
			}
			wr = append(wr, wireButton{Text: b.label, CallbackData: b.data})
		}
		m.InlineKeyboard = append(m.InlineKeyboard, wr)
	}
	return m, nil
}

// Command is one entry of the bot's command menu: a command name without
// the slash and its description, a registry template.
type Command struct {
	Name        string
	Description safetext.Template
}

// commandName is what the Bot API accepts as a command: 1-32 lowercase
// letters, digits and underscores.
var commandName = regexp.MustCompile(`^[a-z0-9_]{1,32}$`)

type botCommand struct {
	Command     string `json:"command"`
	Description string `json:"description"`
}

type setMyCommandsRequest struct {
	Commands     []botCommand `json:"commands"`
	LanguageCode string       `json:"language_code,omitempty"`
}

// SetCommands sets the bot's command menu: the English descriptions for
// every client, and the Russian ones for clients in Russian. It replaces
// whatever menu was set before, so the menu always matches the commands
// this server answers.
func (s *Sender) SetCommands(ctx context.Context, cmds []Command) error {
	if len(cmds) == 0 || len(cmds) > 100 {
		return fmt.Errorf("%w: %d commands", ErrInvalidConfig, len(cmds))
	}
	// Every language's menu is built and checked before the first call,
	// so a bad description refuses the whole menu rather than leaving the
	// languages mismatched.
	var reqs []setMyCommandsRequest
	for _, lang := range []struct {
		code string
		l    safetext.Lang
	}{{"", safetext.LangEN}, {"ru", safetext.LangRU}} {
		req := setMyCommandsRequest{LanguageCode: lang.code}
		for _, c := range cmds {
			d := c.Description.In(lang.l)
			if s.describe != nil {
				d = s.describe(c, lang.l)
			}
			if !commandName.MatchString(c.Name) || strings.TrimSpace(d) == "" || utf8.RuneCountInString(d) > 256 {
				return fmt.Errorf("%w: command %q", ErrInvalidConfig, c.Name)
			}
			req.Commands = append(req.Commands, botCommand{Command: c.Name, Description: d})
		}
		reqs = append(reqs, req)
	}
	for _, req := range reqs {
		if err := s.call(ctx, methodSetMyCommands, req); err != nil {
			return err
		}
	}
	return nil
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
