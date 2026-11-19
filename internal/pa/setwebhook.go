package pa

// setwebhook.go registers the PA webhook with Telegram (issue #1313 slice
// d2). It is an operator action (#1318): nothing in the server calls it,
// at boot or later, and a guard test (TestSetWebhookNotCalledByServer)
// keeps it that way. Registering a webhook moves the bot's traffic, so it
// is done deliberately, once, by a person.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/mctlhq/mctl-telegram/internal/config"
)

// SetWebhookRequest is what SetWebhook registers.
type SetWebhookRequest struct {
	// URL is PA_WEBHOOK_URL: https, with no userinfo, query or fragment.
	URL string
	// Secret is PA_WEBHOOK_SECRET; Telegram sends it back in
	// X-Telegram-Bot-Api-Secret-Token on every delivery.
	Secret string
	// DropPendingUpdates discards updates queued for an earlier webhook.
	DropPendingUpdates bool
}

// ValidateWebhookURL checks a PA webhook URL: absolute https with a host,
// no userinfo, query or fragment, and the PA webhook path.
func ValidateWebhookURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("pa webhook url: not a url")
	}
	switch {
	case u.Scheme != "https":
		return errors.New("pa webhook url: must be https")
	case u.Host == "" || u.Hostname() == "":
		return errors.New("pa webhook url: no host")
	case u.User != nil:
		return errors.New("pa webhook url: userinfo is not allowed")
	case u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.ContainsAny(raw, "?#"):
		return errors.New("pa webhook url: query and fragment are not allowed")
	case u.Path != WebhookPath:
		return fmt.Errorf("pa webhook url: path must be %s", WebhookPath)
	}
	return nil
}

// SetWebhook calls setWebhook with url, secret_token and exactly
// AllowedUpdates (T4). Any failure is an error; the token and the secret
// never appear in one.
func SetWebhook(ctx context.Context, hc *http.Client, baseURL, token string, req SetWebhookRequest) error {
	if token == "" {
		return errors.New("pa setWebhook: no bot token")
	}
	if err := ValidateWebhookURL(req.URL); err != nil {
		return err
	}
	if !config.ValidPAWebhookSecret(req.Secret) {
		return fmt.Errorf("pa setWebhook: secret must be %d-256 characters from [A-Za-z0-9_-]", config.MinPAWebhookSecretLen)
	}
	if baseURL == "" {
		baseURL = DefaultBotAPIBaseURL
	}
	allowed, err := json.Marshal(AllowedUpdates)
	if err != nil {
		return errors.New("pa setWebhook: encode allowed_updates")
	}
	form := url.Values{
		"url":                  {req.URL},
		"secret_token":         {req.Secret},
		"allowed_updates":      {string(allowed)},
		"drop_pending_updates": {fmt.Sprint(req.DropPendingUpdates)},
	}
	endpoint := strings.TrimRight(baseURL, "/") + "/bot" + token + "/setWebhook"
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return errors.New("pa setWebhook: build request failed")
	}
	hreq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := boundedClient(hc).Do(hreq)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		msg := strings.ReplaceAll(err.Error(), token, "[redacted]")
		return fmt.Errorf("pa setWebhook: request failed: %s", strings.ReplaceAll(msg, req.Secret, "[redacted]"))
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return errors.New("pa setWebhook: read body failed")
	}
	var env struct {
		OK     bool `json:"ok"`
		Result bool `json:"result"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return fmt.Errorf("pa setWebhook: malformed response (HTTP %d)", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK || !env.OK || !env.Result {
		return fmt.Errorf("pa setWebhook: refused (HTTP %d)", resp.StatusCode)
	}
	return nil
}
