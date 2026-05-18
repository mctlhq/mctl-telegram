// Package audit provides slog-handler redaction and a per-identity token-bucket
// rate limiter. Both are concerns we want pluggable independently of the
// MCP-tool implementations.
package audit

import (
	"context"
	"fmt"
	"log/slog"
)

// sensitiveKeys is checked case-insensitively against attribute keys.
// Values for matching keys are replaced with `[redacted len=N]`.
var sensitiveKeys = map[string]struct{}{
	"text":                        {},
	"password":                    {},
	"phone":                       {},
	"code":                        {},
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
