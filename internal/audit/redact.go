// Package audit provides slog-handler redaction and a per-identity token-bucket
// rate limiter. Both are concerns we want pluggable independently of the
// MCP-tool implementations.
package audit

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
)

// peerLike matches Telegram identifiers that can appear verbatim inside error
// strings: @handles and phone-like digit runs. Numeric chat IDs are left alone
// — they are less identifying and indistinguishable from ordinary numbers
// without false positives.
var peerLike = regexp.MustCompile(`@[A-Za-z0-9_]{4,}|\+?\d{7,}`)

// ScrubText masks Telegram peer identifiers (@handles, phone numbers) inside
// arbitrary free text. It is used before mirroring tool-call error strings to
// slog, where errors such as `peer "@username" not found` would otherwise leak
// a raw dialog identifier into centralized logs. MTProto error codes and other
// non-identifying text pass through unchanged.
func ScrubText(s string) string {
	return peerLike.ReplaceAllString(s, "[redacted]")
}

// sensitiveKeys is checked case-insensitively against attribute keys.
// Values for matching keys are replaced with `[redacted len=N]`.
var sensitiveKeys = map[string]struct{}{
	"text":                        {},
	"body":                        {},
	"proposed_text":               {},
	"payload":                     {},
	"password":                    {},
	"phone":                       {},
	"code":                        {},
	"approval_code_encrypted":     {},
	"session_encrypted":           {},
	"session":                     {},
	"tg_api_hash":                 {},
	"oauth_jwt_secret":            {},
	"jwt_secret":                  {},
	"client_secret":               {},
	"telegram_oidc_client_secret": {},
	"encryption_key":              {},
	"authorization":               {},
	"bearer":                      {},
	// Local Bridge owner-consent / device-credential surface (issue-483).
	// device_pubkey is DELIBERATELY absent from this list: it is a public
	// key, so logging it is not a disclosure, and redacting it would make
	// debugging device-mismatch reports (wrong key / wrong device) harder
	// for no security benefit -- see the call site that logs it.
	//
	// credential_domain_id and cost_usd (agent-worker policy-denial/job-cost
	// observability, issue-580) are likewise DELIBERATELY absent: both are
	// non-secret by construction — credential_domain_id is an
	// operator-chosen label (a Vault path or account label, never the
	// credential itself) bounded to [A-Za-z0-9._:/-]{1,128}, and cost_usd is
	// a dollar figure — and redacting either would defeat the entire
	// purpose of the metric/log line they appear on.
	"user_code":               {},
	"device_code":             {},
	"consent_token":           {},
	"nonce":                   {},
	"signature":               {},
	"device_registration_key": {},
	"worker_token":            {},
	"bridge_token":            {},
	// mctl_surface_telegram_token is the surface:telegram bearer the
	// work-context adapter (issue-443) authenticates outbound mctl-api
	// calls with — never MCTL_API_TOKEN or an mctl-agent credential, and
	// like every other credential in this list it must never reach a log
	// line.
	"mctl_surface_telegram_token": {},
	// Login-bot update receiver (issue-619). The receiver never decodes
	// message text or callback data, so these keys should never be reachable
	// from it -- they are here so that a LATER handler that does decode
	// content cannot log it by naming the field in the obvious way.
	// bot_token is the Bot API token; callback_data and callback_payload are
	// attacker-influenced content; update_json would be a whole raw update.
	"bot_token":        {},
	"callback_data":    {},
	"callback_payload": {},
	"update_json":      {},
	// send_media byte sources. file_base64 is file contents; file_path is a
	// local filesystem path. Neither may appear in slog.
	"file_base64": {},
	"file_path":   {},
	// Client identity attributes (issue-438). Captured Telegram first/last
	// name are PII the same way display_name/username already were meant to
	// be treated -- new identity-capture and admin-projection code paths must
	// log only ids, categories, states and reason codes, never these.
	"first_name": {},
	"last_name":  {},
	// Broadcast campaigns (issue-439). content is the operator-authored
	// broadcast text; it is stored for delivery and must never reach a log
	// line, whichever handler (worker, web approval, MCP tool) holds it.
	"content":          {},
	"campaign_content": {},
	"broadcast_text":   {},
	// sub, client_id, jti and exp (attributed auth failures, issue-668) are
	// DELIBERATELY absent from this list, for the same reason as
	// credential_domain_id above: none of the four is a secret. They are
	// identifiers this service itself minted into a token it signed with its
	// own HMAC key, attached to the "auth failed" log line only for claims
	// that already passed that signature check (see
	// internal/auth.AttributedError) -- the token material itself stays
	// covered by the existing "authorization"/"bearer" entries.
}

// RedactingHandler wraps a slog.Handler and rewrites attribute values for
// known-sensitive keys before the inner handler ever sees them.
type RedactingHandler struct {
	inner slog.Handler
}

func NewRedactingHandler(inner slog.Handler) *RedactingHandler {
	return &RedactingHandler{inner: inner}
}

func (h *RedactingHandler) Enabled(ctx context.Context, lvl slog.Level) bool {
	return h.inner.Enabled(ctx, lvl)
}

func (h *RedactingHandler) Handle(ctx context.Context, r slog.Record) error {
	newRec := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	r.Attrs(func(a slog.Attr) bool {
		newRec.AddAttrs(redactAttr(a))
		return true
	})
	return h.inner.Handle(ctx, newRec)
}

func (h *RedactingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	red := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		red[i] = redactAttr(a)
	}
	return &RedactingHandler{inner: h.inner.WithAttrs(red)}
}

func (h *RedactingHandler) WithGroup(name string) slog.Handler {
	return &RedactingHandler{inner: h.inner.WithGroup(name)}
}

func redactAttr(a slog.Attr) slog.Attr {
	if _, hit := sensitiveKeys[toLower(a.Key)]; hit {
		return slog.String(a.Key, fmt.Sprintf("[redacted len=%d]", lengthOf(a.Value)))
	}
	if a.Value.Kind() == slog.KindGroup {
		newAttrs := make([]slog.Attr, 0, len(a.Value.Group()))
		for _, inner := range a.Value.Group() {
			newAttrs = append(newAttrs, redactAttr(inner))
		}
		return slog.Group(a.Key, anySlice(newAttrs)...)
	}
	return a
}

func anySlice(in []slog.Attr) []any {
	out := make([]any, len(in))
	for i, a := range in {
		out[i] = a
	}
	return out
}

func lengthOf(v slog.Value) int {
	switch v.Kind() {
	case slog.KindString:
		return len(v.String())
	default:
		return len(v.String())
	}
}

func toLower(s string) string {
	out := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c = c + 32
		}
		out[i] = c
	}
	return string(out)
}
