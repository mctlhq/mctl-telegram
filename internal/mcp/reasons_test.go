package mcp

import (
	"strings"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"
)

// errText builds the *mcplib.CallToolResult classifyToolResultReason
// inspects, mirroring how every handler in this package constructs one via
// mcplib.NewToolResultError.
func errText(text string) *mcplib.CallToolResult {
	return mcplib.NewToolResultError(text)
}

// TestClassifyToolResultReason_MatchesHandlerLiterals is T13/task 4's table
// test: every literal here is copied verbatim from the handler that
// produces it (see the corresponding line in tools.go / media_tools.go /
// apps.go), and each must classify to the reason the design's taxonomy
// assigns it.
func TestClassifyToolResultReason_MatchesHandlerLiterals(t *testing.T) {
	cases := []struct {
		name string
		text string
		want string
	}{
		// requireScope / requireAnyScope (tools.go).
		{"nil identity", "authentication required", ReasonAuthRequired},
		{"missing single scope", "identity missing scope telegram:messages:read", ReasonScopeDenied},
		{"missing any-of scopes", "identity missing scope admin:users or admin:users:read", ReasonScopeDenied},

		// jsonResult / inline encode failures (tools.go).
		{"jsonResult marshal failure", "encode: json: unsupported value: +Inf", ReasonEncodeFailed},
		{"search_messages inline encode failure", "encode: json: unsupported value: +Inf", ReasonEncodeFailed},

		// Local-Bridge mode refusals (tools.go, search_messages / edit_message
		// / delete_messages / forward_messages / set_reaction all share this
		// suffix).
		{"search_messages local-bridge refusal", "search_messages is not yet supported for local-bridge accounts", ReasonModeUnsupported},
		{"edit_message local-bridge refusal", "edit_message is not yet supported for local-bridge accounts", ReasonModeUnsupported},

		// Media admission gate refusal (issue #705, media_gate.go).
		{"media gate capacity refusal", "media downloads are at capacity - retry shortly", ReasonMediaCapacity},

		// Argument validation (tools.go / media_tools.go / apps.go).
		{"single required field", "peer is required", ReasonInvalidArgument},
		{"two required fields", "peer and text are required", ReasonInvalidArgument},
		{"three required fields", "peer, message_id, and text are required", ReasonInvalidArgument},
		{"positive-integer requirement", "telegram_id is required and must be a positive integer", ReasonInvalidArgument},
		{"enum requirement", `tier must be "client" or "none"`, ReasonInvalidArgument},
		{"media_type enum", `media_type must be one of "photo", "video", "document", "animation", "voice"`, ReasonInvalidArgument},
		{"mutually exclusive", "jti and telegram_id are mutually exclusive", ReasonInvalidArgument},
		{"exactly one of", "exactly one of jti or telegram_id is required", ReasonInvalidArgument},
		{"rfc3339 requirement", "before must be RFC3339 (e.g. 2026-05-14T00:00:00Z)", ReasonInvalidArgument},

		// Confirmation-flow mismatches (confirm.go / tools.go / media_tools.go).
		{"confirmation wrong pair", "confirmation_id was issued for a different (peer, text) — re-run prepare_send_message", ReasonConfirmationRejected},
		{"confirmation wrong user", "confirmation_id belongs to another identity", ReasonConfirmationRejected},
		{"confirmation not found", "confirmation_id not found, expired, or already used", ReasonNotFound},
		{"confirmation required pin", "confirmation_id required — call prepare_pin_message first", ReasonInvalidArgument},
		{"confirmation required media", "confirmation_id required — call prepare_get_media first", ReasonInvalidArgument},
		{"confirmation required send", "confirmation_id required — call prepare_send_message first", ReasonInvalidArgument},

		// Rate limiting (audit.RateLimiter).
		{"per-peer rate limit", "per-peer send rate limit reached (20/hour to one peer) — wait, pick a different recipient, or send fewer messages per call", ReasonRateLimited},

		// Policy refusals.
		{"dry-run blocked preview", "pin blocked: demo mode", ReasonRefused},
		{"demo reviewer account guard", demoReviewerAccountMgmtRefusal, ReasonRefused},

		// Telegram-side failures (sessionErrText / borrowErrResult).
		{"2fa incomplete", "Telegram setup is incomplete — the two-step-verification (2FA) step was not finished. Reconnect the connector and complete phone number → SMS code → 2FA password without closing the page.", ReasonTelegramError},
		{"session revoked", "Your Telegram session is no longer valid — it was signed out from another device, or the account is unavailable. Reconnect the connector to sign in again.", ReasonTelegramError},
		{"session expired", "Your Telegram session has expired. Reconnect the connector to sign in again.", ReasonTelegramError},
		{"no active session", "No Telegram account is connected. Reconnect the connector and complete the in-browser setup (phone → SMS → 2FA).", ReasonTelegramError},
		{"pool full", "server at session capacity — try again later", ReasonTelegramError},
		{"flood wait envelope", `{"error":"flood_wait","message":"Telegram rate limit reached. Wait 5 seconds before retrying.","retry_after_seconds":5,"action":"Wait 5 seconds, then retry the same tool call."}`, ReasonTelegramError},

		// not_found lookups.
		{"no telegram identity", "get_my_identity: no Telegram identity on this session", ReasonNotFound},

		// Resolution failures (audit's own doc comment: `peer %q not found`).
		{"peer resolution failure", `peer "@nobody" not found`, ReasonNotFound},

		// Unrecognized text must be honest, not guessed.
		{"unrecognized", "the daemon fell over sideways", ReasonUnknown},
		{"empty text", "", ReasonUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyToolResultReason(errText(tc.text))
			if got != tc.want {
				t.Errorf("classifyToolResultReason(%q) = %q, want %q", tc.text, got, tc.want)
			}
		})
	}
}

func TestClassifyToolResultReason_NilResult(t *testing.T) {
	if got := classifyToolResultReason(nil); got != ReasonUnknown {
		t.Errorf("classifyToolResultReason(nil) = %q, want %q", got, ReasonUnknown)
	}
}

// TestMTProtoCatalog_NoMessageIsAPrefixOfAnother guards the catalog prefix
// loop in classifyToolResultReason against map-iteration-order dependence.
func TestMTProtoCatalog_NoMessageIsAPrefixOfAnother(t *testing.T) {
	for ka, a := range mtprotoErrCatalog {
		for kb, b := range mtprotoErrCatalog {
			if ka != kb && a.message != b.message && strings.HasPrefix(b.message, a.message) {
				t.Errorf("catalog message %q (%v) is a prefix of %q (%v)", a.message, ka, b.message, kb)
			}
		}
	}
}
