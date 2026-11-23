package pa

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

// DefaultBotAPIBaseURL is the public Bot API endpoint.
const DefaultBotAPIBaseURL = "https://api.telegram.org"

// AllowedUpdates is the exact allowed_updates list of the PA webhook (T4).
var AllowedUpdates = []string{"message", "callback_query"}

// WebhookInfo is the subset of getWebhookInfo the health check reads.
type WebhookInfo struct {
	URL                  string `json:"url"`
	HasCustomCertificate bool   `json:"has_custom_certificate"`
	PendingUpdateCount   int    `json:"pending_update_count"`
	LastErrorDate        int64  `json:"last_error_date"`
	// LastErrorMessage is Telegram's text for the last delivery error. It
	// is classified (see CheckWebhook), never logged or exported.
	LastErrorMessage string   `json:"last_error_message"`
	MaxConnections   int      `json:"max_connections"`
	AllowedUpdates   []string `json:"allowed_updates"`
}

// Webhook problems reported by CheckWebhook.
const (
	ProblemURLChanged      = "url_changed"
	ProblemAllowedUpdates  = "allowed_updates_changed"
	ProblemLastErrorRecent = "delivery_error"
	// ProblemSecretRejected: the latest delivery error is our webhook's 401,
	// which it answers only to a missing or wrong secret token. Telegram
	// does not report the secret it sends, so a secret that differs from
	// PA_WEBHOOK_SECRET is seen only this way (and in the bad_secret count).
	ProblemSecretRejected = "secret_rejected"
)

// WebhookProblems lists every problem CheckWebhook can report: a closed
// set, so it can be a metric label.
func WebhookProblems() []string {
	return []string{ProblemURLChanged, ProblemAllowedUpdates, ProblemLastErrorRecent, ProblemSecretRejected}
}

// botAPITimeout bounds one Bot API call made by this package. A variable
// only so a test can shorten it.
var botAPITimeout = 10 * time.Second

// errRedirect refuses every redirect: the Bot API never redirects, and a
// redirect would carry the token-bearing request to another host.
var errRedirect = errors.New("bot api redirect refused")

// boundedClient returns a copy of hc (or of a fresh client when hc is nil)
// that never follows a redirect and always has a timeout. http.DefaultClient
// has neither, so it is never used as is.
func boundedClient(hc *http.Client) *http.Client {
	var c http.Client
	if hc != nil {
		c = *hc
	}
	if c.Timeout <= 0 || c.Timeout > botAPITimeout {
		c.Timeout = botAPITimeout
	}
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return errRedirect }
	return &c
}

// GetWebhookInfo reads the bot's webhook state. Any failure -- transport,
// non-200, ok:false, malformed body -- is an error, never a zero WebhookInfo
// that would read as "no webhook" (I9). The token never appears in an error.
func GetWebhookInfo(ctx context.Context, hc *http.Client, baseURL, token string) (WebhookInfo, error) {
	if token == "" {
		return WebhookInfo{}, errors.New("pa getWebhookInfo: no bot token")
	}
	if baseURL == "" {
		baseURL = DefaultBotAPIBaseURL
	}
	hc = boundedClient(hc)
	endpoint := strings.TrimRight(baseURL, "/") + "/bot" + token + "/getWebhookInfo"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return WebhookInfo{}, errors.New("pa getWebhookInfo: build request failed")
	}
	resp, err := hc.Do(req)
	if err != nil {
		// *url.Error embeds the URL, which embeds the token.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return WebhookInfo{}, fmt.Errorf("pa getWebhookInfo: request failed: %s", strings.ReplaceAll(err.Error(), token, "[redacted]"))
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return WebhookInfo{}, errors.New("pa getWebhookInfo: read body failed")
	}
	var env struct {
		OK     bool         `json:"ok"`
		Result *WebhookInfo `json:"result"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return WebhookInfo{}, fmt.Errorf("pa getWebhookInfo: malformed response (HTTP %d)", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK || !env.OK || env.Result == nil {
		return WebhookInfo{}, fmt.Errorf("pa getWebhookInfo: refused (HTTP %d)", resp.StatusCode)
	}
	return *env.Result, nil
}

// CheckWebhook compares info with the expected state and returns the
// problems found; an empty result means healthy. Telegram keeps
// last_error_date until the next error, so only an error at or after
// errorsSince (typically the previous check) counts. An unreadable info is
// the caller's GetWebhookInfo error and must be alerted on as well, never
// treated as healthy.
func CheckWebhook(info WebhookInfo, expectedURL string, errorsSince time.Time) []string {
	var problems []string
	if info.URL != expectedURL {
		problems = append(problems, ProblemURLChanged)
	}
	// An empty list from Telegram means "the default set", which is wider
	// than ours, so it is a problem too.
	got := slices.Clone(info.AllowedUpdates)
	want := slices.Clone(AllowedUpdates)
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		problems = append(problems, ProblemAllowedUpdates)
	}
	if info.LastErrorDate != 0 && !time.Unix(info.LastErrorDate, 0).Before(errorsSince) {
		problems = append(problems, ProblemLastErrorRecent)
		if secretRejected(info.LastErrorMessage) {
			problems = append(problems, ProblemSecretRejected)
		}
	}
	return problems
}

// secretRejected reports a delivery error that is our 401 (Telegram words
// it "Wrong response from the webhook: 401 Unauthorized").
func secretRejected(msg string) bool {
	return strings.Contains(msg, " 401") || strings.HasPrefix(msg, "401")
}
