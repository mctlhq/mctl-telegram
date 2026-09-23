package auth

import (
	"errors"
	"testing"
)

// TestClassifyAuthError_UnaffectedByAttributedErrorWrapping is task 5's DoD:
// classifyAuthError(wrapped.Error()) must return the same label as
// classifyAuthError(inner.Error()) for every existing reason, because
// AttributedError.Error() forwards the wrapped error's message unchanged.
func TestClassifyAuthError_UnaffectedByAttributedErrorWrapping(t *testing.T) {
	cases := []string{
		"JWT expired",
		"invalid JWT signature",
		`unexpected JWT issuer: "https://evil.example"`,
		"JWT missing required audience claim",
		`JWT audience [a b] does not match expected "c"`,
		"worker token revoked",
		"Authorization header must use Bearer scheme",
		"malformed JWT",
		"some entirely novel failure",
	}
	for _, msg := range cases {
		t.Run(msg, func(t *testing.T) {
			inner := errors.New(msg)
			wrapped := &AttributedError{
				Attr: TokenAttribution{Subject: "tg:1", ClientID: "c", Jti: "j", ExpiresAt: 1},
				Err:  inner,
			}
			want := classifyAuthError(inner.Error())
			got := classifyAuthError(wrapped.Error())
			if got != want {
				t.Errorf("classifyAuthError(wrapped) = %q, classifyAuthError(inner) = %q, want equal", got, want)
			}
			if wrapped.Error() != inner.Error() {
				t.Errorf("AttributedError.Error() = %q, want %q (must forward unchanged)", wrapped.Error(), inner.Error())
			}
		})
	}
}

// TestAttributionOf covers the extraction helper directly: a plain error has
// no attribution, an AttributedError's does, and Unwrap lets errors.Is see
// through the wrapper to whatever it wraps.
func TestAttributionOf(t *testing.T) {
	if _, ok := AttributionOf(errors.New("plain")); ok {
		t.Error("a plain error must not report an attribution")
	}

	sentinel := errors.New("sentinel")
	wrapped := &AttributedError{Attr: TokenAttribution{Subject: "tg:42"}, Err: sentinel}
	attr, ok := AttributionOf(wrapped)
	if !ok || attr.Subject != "tg:42" {
		t.Errorf("AttributionOf(wrapped) = %+v, %v, want Subject=tg:42, true", attr, ok)
	}
	if !errors.Is(wrapped, sentinel) {
		t.Error("errors.Is must see through AttributedError to the wrapped sentinel")
	}

	// An error wrapping an AttributedError two levels down must still surface
	// the attribution — errors.As walks the whole chain.
	doubly := errors.Join(errors.New("context"), wrapped)
	if _, ok := AttributionOf(doubly); !ok {
		t.Error("AttributionOf must find an AttributedError nested inside errors.Join")
	}
}
