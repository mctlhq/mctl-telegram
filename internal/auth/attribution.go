package auth

import "errors"

// TokenAttribution carries the identifying claims of a token that VERIFIED
// its signature but was then rejected (expired, wrong issuer, audience
// mismatch, revoked). Every field is safe to log: none is a secret, and all
// four were vouched for by this service's own HMAC key.
type TokenAttribution struct {
	Subject   string
	ClientID  string
	Jti       string
	ExpiresAt int64
}

// AttributedError wraps a post-signature verification failure with the
// claims that produced it. Providers MUST NOT construct one for a failure at
// or before the signature check: those claims are attacker-controlled input
// that this service never authenticated.
type AttributedError struct {
	Attr TokenAttribution
	Err  error
}

// Error forwards the wrapped error's message unchanged, so every existing
// classifier (classifyAuthError operates on err.Error()) and every
// errors.Is/string-match call site keeps working byte-for-byte.
func (e *AttributedError) Error() string { return e.Err.Error() }

// Unwrap exposes the wrapped error so errors.Is/errors.As continue to see
// through an AttributedError to whatever it wraps.
func (e *AttributedError) Unwrap() error { return e.Err }

// AttributionOf extracts the TokenAttribution from err, if any provider in
// its error chain wrapped one via AttributedError.
func AttributionOf(err error) (TokenAttribution, bool) {
	var ae *AttributedError
	if errors.As(err, &ae) {
		return ae.Attr, true
	}
	return TokenAttribution{}, false
}
