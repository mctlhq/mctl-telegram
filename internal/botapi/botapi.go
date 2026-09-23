// Package botapi is the one Telegram Bot API sender in the repository: a
// plain-text sendMessage through the login bot. The daily digest and the
// broadcast delivery worker (issue-439) both use it, so the token-redaction
// and error-typing rules below hold for every bot send.
package botapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/notify"
)

// DefaultBaseURL is the public Bot API endpoint.
const DefaultBaseURL = "https://api.telegram.org"

// Client sends messages through one bot. The zero value is not usable: Token
// is required.
type Client struct {
	Token string
	// BaseURL overrides DefaultBaseURL (tests point it at httptest).
	BaseURL string
	// HTTP is the client used for requests. nil means http.DefaultClient,
	// resolved at call time so a test that swaps DefaultClient's transport
	// is honoured.
	HTTP *http.Client
}

// SendMessage posts text to chatID with no parse mode. A non-2xx response is
// returned as *notify.APIError carrying only the status, Telegram's
// description and any retry_after -- never the raw body. A transport failure
// is returned with the request URL (which embeds the bot token) stripped.
func (c *Client) SendMessage(ctx context.Context, chatID int64, text string) error {
	if c.Token == "" {
		return errors.New("bot api: no bot token configured")
	}
	base := c.BaseURL
	if base == "" {
		base = DefaultBaseURL
	}
	endpoint := strings.TrimRight(base, "/") + "/bot" + c.Token + "/sendMessage"
	form := url.Values{
		"chat_id": {strconv.FormatInt(chatID, 10)},
		"text":    {text},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return errors.New("bot api: build request failed")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		// *url.Error.Error() embeds the request URL, which contains the bot
		// token — unwrap to the underlying cause so the token cannot leak
		// into logs.
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			return fmt.Errorf("telegram request failed: %w", urlErr.Err)
		}
		return fmt.Errorf("telegram request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		// A typed *notify.APIError, not a formatted string: ClassifyDelivery
		// needs the status code and description separately, and the raw
		// response body must never be persisted (see RecordBotReachability) —
		// only Description travels past this point, and only into
		// ClassifyDelivery, never into a stored column or a log line.
		desc, retryAfter := parseError(body)
		return &notify.APIError{StatusCode: resp.StatusCode, Description: desc, RetryAfter: retryAfter}
	}
	return nil
}

// parseError extracts description and parameters.retry_after from a Telegram
// error body such as {"ok":false,"error_code":429,"description":"Too Many
// Requests: retry after 5","parameters":{"retry_after":5}}. It falls back to
// the raw (truncated, trimmed) body when it does not parse as JSON, so
// ClassifyDelivery still has text to match against.
func parseError(body []byte) (string, time.Duration) {
	var payload struct {
		Description string `json:"description"`
		Parameters  struct {
			RetryAfter int `json:"retry_after"`
		} `json:"parameters"`
	}
	if err := json.Unmarshal(body, &payload); err == nil && payload.Description != "" {
		var ra time.Duration
		if payload.Parameters.RetryAfter > 0 {
			ra = time.Duration(payload.Parameters.RetryAfter) * time.Second
		}
		return payload.Description, ra
	}
	return strings.TrimSpace(string(body)), 0
}
