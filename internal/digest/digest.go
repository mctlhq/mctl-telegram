// Package digest sends the operator a once-a-day Telegram summary of clients
// that signed in over the last 24 hours. It exists so onboarding stays fully
// hands-off (open auto-approve) while the operator still has daily visibility
// of who connected.
package digest

import (
	"context"
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
// when botToken is empty or there are no recipients. The goroutine stops when
// stop is closed. Single-replica only — there is no leader election.
func StartDailyDigest(stop <-chan struct{}, store *db.Store, botToken string, recipients []int64, hourUTC int) {
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
			select {
			case <-stop:
				return
			case <-time.After(wait):
				runDigest(store, botToken, recipients)
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

// runDigest collects the last-24h clients and sends the digest. Errors are
// logged, never fatal — a digest is best-effort.
func runDigest(store *db.Store, botToken string, recipients []int64) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	since := time.Now().UTC().Add(-lookback)
	newRows, err := store.ListIdentities(ctx, since)
	if err != nil {
		slog.Error("digest: list new identities", "err", err)
		return
	}
	allRows, err := store.ListIdentities(ctx, time.Time{})
	if err != nil {
		slog.Error("digest: list all identities", "err", err)
		return
	}
	msg := buildDigestMessage(newRows, len(allRows))
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

// buildDigestMessage formats the digest text. It returns "" when there are no
// new clients so the caller can skip an empty send.
func buildDigestMessage(rows []db.IdentityRow, total int) string {
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
		fmt.Fprintf(&b, "• %s — id %d — tier=%s — %s\n", name, r.TelegramID, r.AccessTier, session)
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
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("telegram sendMessage HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}
