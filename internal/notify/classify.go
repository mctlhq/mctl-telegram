// Package notify models bot reachability: whether the login bot may
// currently initiate a chat with a client, derived only from the outcome of
// a real Telegram Bot API delivery -- never from a probe sent solely to
// classify reachability (see design.md's "Probe-based classification"
// alternative, which is dropped and forbidden by the issue).
package notify

import (
	"strings"
	"time"
)

// Reachability states. Mirrors the four-state model in design.md: a plain
// boolean cannot express "never observed" (the state almost every client is
// in) separately from "the user never started the bot" (a different remedy
// than "the user blocked the bot").
const (
	StateUnknown        = "unknown"
	StateReachable      = "reachable"
	StateBlocked        = "blocked"
	StateCannotInitiate = "cannot_initiate"
)

// DeliveryOutcome is the result of classifying one Bot API sendMessage
// response. Conclusive distinguishes an outcome that licenses a state write
// from one that does not: a 429 or a 5xx is not evidence the user blocked
// the bot, so Store.RecordBotReachability must leave the stored state
// unchanged when Conclusive is false.
type DeliveryOutcome struct {
	State      string
	ReasonCode string
	Conclusive bool
}

// APIError is a typed, non-2xx Telegram Bot API response. digest.sendTelegramMessage
// returns this instead of a formatted string error so ClassifyDelivery can
// inspect the status code and description without re-parsing an error
// string. Description is Telegram's own human-readable text (already
// truncated to 512 bytes by the caller) -- attacker-influenced but never the
// bot token, which sendTelegramMessage's *url.Error unwrap keeps out of any
// error value in the first place.
type APIError struct {
	StatusCode  int
	Description string
	// RetryAfter is Telegram's parameters.retry_after on a 429 (flood
	// control), zero when absent. It is advice for the caller's backoff,
	// never a reachability signal.
	RetryAfter time.Duration
}

func (e *APIError) Error() string {
	return "telegram bot api: HTTP " + itoa(e.StatusCode) + ": " + e.Description
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// ClassifyDelivery is pure and offline-testable, mirroring the style of
// telegramoidc.parseIdentity: no network or DB access, so every mapping row
// is a table-driven test.
//
// Mapping (from what digest.sendTelegramMessage can actually observe):
//
//	200                                                    -> reachable, conclusive
//	403 "bot was blocked by the user"                      -> blocked, conclusive
//	403 "user is deactivated"                              -> blocked, conclusive
//	403 "bot can't initiate conversation with a user"      -> cannot_initiate, conclusive
//	400 "chat not found"                                   -> cannot_initiate, conclusive
//	429, any 5xx, anything unrecognised                    -> unchanged, NOT conclusive
//
// description matching is case-insensitive substring, since Telegram's
// human-readable text carries a "Forbidden: "/"Bad Request: " prefix that
// varies by endpoint and API version.
func ClassifyDelivery(httpStatus int, description string) DeliveryOutcome {
	if httpStatus == 200 {
		return DeliveryOutcome{State: StateReachable, ReasonCode: "delivered", Conclusive: true}
	}
	desc := strings.ToLower(description)
	if httpStatus == 403 {
		switch {
		case strings.Contains(desc, "bot was blocked by the user"):
			return DeliveryOutcome{State: StateBlocked, ReasonCode: "bot_blocked", Conclusive: true}
		case strings.Contains(desc, "user is deactivated"):
			return DeliveryOutcome{State: StateBlocked, ReasonCode: "user_deactivated", Conclusive: true}
		case strings.Contains(desc, "bot can't initiate conversation"):
			return DeliveryOutcome{State: StateCannotInitiate, ReasonCode: "cannot_initiate_conversation", Conclusive: true}
		}
		return DeliveryOutcome{Conclusive: false}
	}
	if httpStatus == 400 {
		if strings.Contains(desc, "chat not found") {
			return DeliveryOutcome{State: StateCannotInitiate, ReasonCode: "chat_not_found", Conclusive: true}
		}
		return DeliveryOutcome{Conclusive: false}
	}
	// 429, any 5xx, transport-level failures fed in as a non-2xx/4xx status,
	// and any other unrecognised status/description: not conclusive. A
	// transient failure must never downgrade a previously-observed
	// reachable/blocked/cannot_initiate state.
	return DeliveryOutcome{Conclusive: false}
}
