// Package digest sends the operator a once-a-day Telegram summary of clients
// that signed in over the last 24 hours. It exists so onboarding stays fully
// hands-off (open auto-approve) while the operator still has daily visibility
// of who connected.
package digest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

const (
	lookback    = 24 * time.Hour
	httpTimeout = 15 * time.Second
)

// StartDailyDigest launches a goroutine that, once per day at hourUTC:00 UTC,
// sends the new-client digest to every recipient via the bot. It is a no-op
// when botToken is empty or there are no recipients. The goroutine exits when
// ctx is cancelled. Single-replica only — there is no leader election.
func StartDailyDigest(ctx context.Context, store *db.Store, botToken string, recipients []int64, hourUTC int, autoApprove bool) {
	if botToken == "" || len(recipients) == 0 {
		slog.Info("daily digest disabled", "reason", "no bot token or recipients")
		return
	}
	if hourUTC < 0 || hourUTC > 23 {
		hourUTC = 9
	}
	go func() {
		for {
			wait := untilNextHour(time.Now().UTC(), hourUTC)
			t := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				t.Stop()
				return
			case <-t.C:
				runDigest(ctx, store, botToken, recipients, autoApprove)
			}
		}
	}()
	slog.Info("daily digest enabled", "hour_utc", hourUTC, "recipients", len(recipients))
}

// untilNextHour returns the duration from now to the next occurrence of
// hour:00:00 UTC.
func untilNextHour(now time.Time, hour int) time.Duration {
	now = now.UTC()
	next := time.Date(now.Year(), now.Month(), now.Day(), hour, 0, 0, 0, time.UTC)
	if !next.After(now) {
		next = next.Add(24 * time.Hour)
	}
	return next.Sub(now)
}

// runDigest collects the last-24h clients with a single ListIdentities scan
// and sends the digest. Errors are logged, never fatal — a digest is
// best-effort.
func runDigest(ctx context.Context, store *db.Store, botToken string, recipients []int64, autoApprove bool) {
	qctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	all, err := store.ListIdentities(qctx)
	if err != nil {
		slog.Error("digest: list identities", "err", err)
		return
	}
	since := time.Now().UTC().Add(-lookback)
	var newRows []db.IdentityRow
	for _, r := range all {
		if r.CreatedAt.After(since) {
			newRows = append(newRows, r)
		}
	}
	msg := buildDigestMessage(newRows, len(all), autoApprove)
	if msg == "" {
		slog.Info("digest: no new clients in the last 24h, skipping send")
		return
	}
	sent := 0
	for _, chatID := range recipients {
		if err := sendTelegramMessage(botToken, chatID, msg); err != nil {
			slog.Warn("digest: send failed", "chat_id", chatID, "err", err)
			continue
		}
		sent++
	}
	slog.Info("digest sent", "new_clients", len(newRows), "delivered", sent, "recipients", len(recipients))
}

// effectiveTier maps the raw users.access_tier value ("" = unset) to the tier
// a user effectively has, taking AUTO_APPROVE_CLIENTS into account — so the
// digest never shows an auto-approved client as "none".
func effectiveTier(raw string, autoApprove bool) string {
	switch raw {
	case db.TierClient:
		return "client"
	case db.TierNone:
		return "none (banned)"
	default: // unset
		if autoApprove {
			return "client (auto)"
		}
		return "none"
	}
}

// buildDigestMessage formats the digest text. It returns "" when there are no
// new clients so the caller can skip an empty send.
func buildDigestMessage(rows []db.IdentityRow, total int, autoApprove bool) string {
	if len(rows) == 0 {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "mctl-telegram — %d new client(s) in the last 24h (%d total):\n", len(rows), total)
	for _, r := range rows {
		name := r.Username
		if name == "" {
			name = r.DisplayName
		}
		if name == "" {
			name = "(no username)"
		}
		session := "no session"
		if r.HasSession {
			session = "session active"
		}
		fmt.Fprintf(&b, "• %s — id %d — tier=%s — %s\n",
			name, r.TelegramID, effectiveTier(r.AccessTier, autoApprove), session)
	}
	return b.String()
}

// sendTelegramMessage posts one message via the Telegram Bot API. A non-2xx
// response (e.g. an operator who never opened a chat with the bot) is returned
// as an error for the caller to log.
func sendTelegramMessage(botToken string, chatID int64, text string) error {
	endpoint := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", botToken)
	form := url.Values{
		"chat_id": {strconv.FormatInt(chatID, 10)},
		"text":    {text},
	}
	ctx, cancel := context.WithTimeout(context.Background(), httpTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
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
		return fmt.Errorf("telegram sendMessage HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}
