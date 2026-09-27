// Package digest sends the operator a once-a-day Telegram summary of clients
// that signed in over the last 24 hours. It exists so onboarding stays fully
// hands-off (open auto-approve) while the operator still has daily visibility
// of who connected.
package digest

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/botapi"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/notify"
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
	// One additional query, keyed by the Telegram ids of the rows actually
	// being rendered (bounded by the 24h window newRows already is) — never
	// the unbounded ListIdentities scan. A query error degrades to the
	// pre-existing plain "no session" text (steps stays nil) rather than
	// skipping the send.
	var steps map[int64]db.ConnectStep
	if len(newRows) > 0 {
		tgIDs := make([]int64, len(newRows))
		for i, r := range newRows {
			tgIDs[i] = r.TelegramID
		}
		s, stepsErr := store.LastConnectStepFor(qctx, tgIDs)
		if stepsErr != nil {
			slog.Warn("digest: last connect step", "err", stepsErr)
		} else {
			steps = s
		}
	}
	msg := buildDigestMessage(newRows, len(all), autoApprove, steps)
	if msg == "" {
		slog.Info("digest: no new clients in the last 24h, skipping send")
		return
	}
	sent := 0
	for _, chatID := range recipients {
		sendErr := sendTelegramMessage(botToken, chatID, msg)
		recordReachability(qctx, store, chatID, sendErr)
		if sendErr != nil {
			slog.Warn("digest: send failed", "chat_id", chatID, "err", sendErr)
			continue
		}
		sent++
	}
	slog.Info("digest sent", "new_clients", len(newRows), "delivered", sent, "recipients", len(recipients))
}

// recordReachability classifies the outcome of one sendTelegramMessage call
// and, when conclusive, records it against the recipient's users.id. This is
// the one wired sender in the repository -- see internal/notify's package
// doc for why reachability is never learned by a dedicated probe. Best
// effort: a failure to resolve the user id or to write the row is logged and
// never turns a digest send failure/success into a harder error.
func recordReachability(ctx context.Context, store *db.Store, chatID int64, sendErr error) {
	if store == nil {
		return
	}
	httpStatus := http.StatusOK
	description := ""
	var apiErr *notify.APIError
	if sendErr != nil {
		if !errors.As(sendErr, &apiErr) {
			// Transport-level failure (already unwrapped of the bot token by
			// sendTelegramMessage) — not a classifiable HTTP response at
			// all, so it is never conclusive. Nothing to record.
			return
		}
		httpStatus = apiErr.StatusCode
		description = apiErr.Description
	}
	outcome := notify.ClassifyDelivery(httpStatus, description)
	if !outcome.Conclusive {
		return
	}
	userID, err := store.UserIDByTelegramID(ctx, chatID)
	if err != nil {
		slog.Warn("digest: resolve recipient user id for reachability", "chat_id", chatID, "err", err)
		return
	}
	if err := store.RecordBotReachability(ctx, userID, outcome, "digest_delivery"); err != nil {
		slog.Warn("digest: record bot reachability", "chat_id", chatID, "err", err)
	}
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
// new clients so the caller can skip an empty send. steps is the result of
// LastConnectStepFor keyed by Telegram id; nil when that lookup failed or
// was skipped, in which case every row falls back to the plain pre-existing
// "no session" text.
func buildDigestMessage(rows []db.IdentityRow, total int, autoApprove bool, steps map[int64]db.ConnectStep) string {
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
		fmt.Fprintf(&b, "• %s — id %d — tier=%s — %s%s\n",
			name, r.TelegramID, effectiveTier(r.AccessTier, autoApprove), sessionSuffix(r, steps), reachabilitySuffix(r))
	}
	return b.String()
}

// sessionSuffix renders the session column. Rows WITH a session are
// unchanged ("session active"). Rows without one gain the last connect
// step, which is what separates "never started" from "stuck at the code
// prompt" from "FLOOD_WAIT" — three stories that were identical in the
// pre-issue-668 output. steps == nil (LastConnectStepFor failed or was
// skipped) degrades to the plain pre-existing "no session" text so a
// failing lookup never turns into a missing digest.
func sessionSuffix(r db.IdentityRow, steps map[int64]db.ConnectStep) string {
	if r.HasSession {
		return "session active"
	}
	if steps == nil {
		return "no session"
	}
	st, ok := steps[r.TelegramID]
	if !ok {
		return "no session — last: never started"
	}
	// An entry can come from the revoked-reason lookup alone: the latest
	// telegram_accounts row carries a reason but the user has no connect:*
	// audit row (rows aged out, or a session created by a path that writes
	// no connect:* step). LastConnectStepFor materialises such an entry with
	// an empty Step and a zero At, so render only the revoke clause rather
	// than an empty step and a fabricated "00:00".
	out := "no session"
	if st.Step != "" {
		out += " — last: " + st.Step + " " + st.At.UTC().Format("15:04")
	}
	if st.RevokedReason != "" {
		out += " — session revoked (" + st.RevokedReason + ")"
	}
	if st.Step == "" && st.RevokedReason == "" {
		// Defensive: a zero-valued entry with nothing to say reads like
		// the no-entry case, never like a half-rendered line.
		return "no session — last: never started"
	}
	return out
}

// reachabilitySuffix returns " — bot: <state>" for a row whose reachability
// is recorded and not "unknown", so the operator sees e.g. "bot: blocked"
// for exactly the signal this digest send itself produced. Rows with no
// recorded reachability (the common case — see design.md's Risks section)
// get no suffix at all, since "unknown" means "no delivery attempt
// observed", never "reachable", and printing it on every line would bury the
// signal that does exist.
func reachabilitySuffix(r db.IdentityRow) string {
	if r.BotReachability == nil || r.BotReachability.State == "" || r.BotReachability.State == "unknown" {
		return ""
	}
	return " — bot: " + r.BotReachability.State
}

// sendTelegramMessage posts one message via the Telegram Bot API. A non-2xx
// response (e.g. an operator who never opened a chat with the bot) is returned
// as a typed *notify.APIError for the caller to log and classify. The HTTP
// work, token redaction and error typing live in internal/botapi, shared with
// the broadcast delivery worker.
func sendTelegramMessage(botToken string, chatID int64, text string) error {
	ctx, cancel := context.WithTimeout(context.Background(), httpTimeout)
	defer cancel()
	return (&botapi.Client{Token: botToken}).SendMessage(ctx, chatID, text)
}
