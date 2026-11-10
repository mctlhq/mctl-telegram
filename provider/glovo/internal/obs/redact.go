// Package obs holds the worker's redacting logger, metrics and audit events. Everything it emits is opaque ids,
// refusal codes and counters.
package obs

import (
	"context"
	"log/slog"
	"strings"
)

const redacted = "[REDACTED]"

// sensitiveFragments are matched case-insensitively as substrings of
// attribute keys.
var sensitiveFragments = []string{
	"receipt", "approval", "basket", "item", "address", "token", "session", "cookie",
	"password", "secret", "phone", "message", "body", "credential", "authorization", "api_key", "apikey", "lease", "note",
}

func sensitive(key string) bool {
	k := strings.ToLower(key)
	for _, f := range sensitiveFragments {
		if strings.Contains(k, f) {
			return true
		}
	}
	return false
}

type redactHandler struct{ inner slog.Handler }

// NewRedactingHandler wraps inner and replaces the value of every attribute
// whose key looks sensitive.
func NewRedactingHandler(inner slog.Handler) slog.Handler { return &redactHandler{inner: inner} }

func (h *redactHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.inner.Enabled(ctx, l)
}

func (h *redactHandler) Handle(ctx context.Context, r slog.Record) error {
	out := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	r.Attrs(func(a slog.Attr) bool { out.AddAttrs(scrub(a)); return true })
	return h.inner.Handle(ctx, out)
}

func (h *redactHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	s := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		s[i] = scrub(a)
	}
	return &redactHandler{inner: h.inner.WithAttrs(s)}
}

func (h *redactHandler) WithGroup(name string) slog.Handler {
	return &redactHandler{inner: h.inner.WithGroup(name)}
}

func scrub(a slog.Attr) slog.Attr {
	if sensitive(a.Key) {
		return slog.String(a.Key, redacted)
	}
	if a.Value.Kind() == slog.KindGroup {
		g := a.Value.Group()
		s := make([]slog.Attr, len(g))
		for i, c := range g {
			s[i] = scrub(c)
		}
		return slog.Attr{Key: a.Key, Value: slog.GroupValue(s...)}
	}
	return a
}
