package oauth

import (
	"errors"
	"log/slog"
	"net/url"
)

// regReason is a closed set of registration-outcome tokens. Values are
// compile-time constants so a client-supplied error string can never become
// a Prometheus label and blow up cardinality.
type regReason string

const (
	regOK                  regReason = "ok"
	regRateLimited         regReason = "rate_limited"
	regMalformedBody       regReason = "malformed_body"
	regNoRedirectURIs      regReason = "no_redirect_uris"
	regTooManyRedirectURIs regReason = "too_many_redirect_uris"
	regRedirectTooLong     regReason = "redirect_uri_too_long"
	regSchemeNotAllowed    regReason = "redirect_scheme_not_allowed"
	regHostNotAllowed      regReason = "redirect_host_not_allowed"
	regUserinfo            regReason = "redirect_userinfo"
	regBackslash           regReason = "redirect_backslash"
	regUnparseable         regReason = "redirect_unparseable"
	regPersistFailed       regReason = "persist_failed"
)

// Typed sentinels for the redirect_uri validators in server.go
// (validateRedirectURIShape, validateImplicitRedirectURI). classifyRegistrationError
// uses errors.Is against these instead of matching the free-text message,
// which is fragile and — on the "not a valid URL" path — embeds the raw
// client-supplied URI.
var (
	errRedirectBackslash = errors.New("redirect_uri must not contain a backslash")
	errRedirectUserinfo  = errors.New("redirect_uri must not contain userinfo")
	errRedirectScheme    = errors.New("redirect_uri scheme not allowed")
	errRedirectHost      = errors.New("redirect_uri host not allowed")
)

// reasonError pairs a validator's existing free-text error with a typed
// sentinel for errors.Is classification, without changing what the wire
// sees: Error() forwards err's message exactly (so error_description stays
// byte-identical to before this change), and Unwrap exposes both err and
// sentinel so errors.Is can match either.
type reasonError struct {
	err      error
	sentinel error
}

func (e *reasonError) Error() string   { return e.err.Error() }
func (e *reasonError) Unwrap() []error { return []error{e.err, e.sentinel} }

// withReason wraps err so errors.Is(result, sentinel) succeeds while
// result.Error() stays exactly err.Error().
func withReason(err, sentinel error) error {
	return &reasonError{err: err, sentinel: sentinel}
}

// classifyRegistrationError maps an error returned by validateRedirectURIShape
// or validateImplicitRedirectURI to its regReason token via errors.Is — never
// by matching the free-text message. A redirect_uri that failed to parse at
// all (url.Parse error, wrapped but with no typed sentinel attached) falls
// into the regUnparseable default.
func classifyRegistrationError(err error) regReason {
	switch {
	case err == nil:
		return regOK
	case errors.Is(err, errRedirectBackslash):
		return regBackslash
	case errors.Is(err, errRedirectUserinfo):
		return regUserinfo
	case errors.Is(err, errRedirectScheme):
		return regSchemeNotAllowed
	case errors.Is(err, errRedirectHost):
		return regHostNotAllowed
	default:
		return regUnparseable
	}
}

// redirectOrigin parses raw and returns its scheme and hostname — never the
// path, query, fragment or port. Returns ("", "") when raw does not parse,
// rather than falling back to logging the raw string. Hostname() (not Host)
// deliberately drops the port to keep the field's cardinality low.
func redirectOrigin(raw string) (scheme, host string) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", ""
	}
	return u.Scheme, u.Hostname()
}

// auditRegistration emits the single "oauth: client_registration audit" line
// for one /oauth/register outcome and increments the paired counter, so the
// log line and the metric can never disagree about which bucket a request
// fell into. clientName and userAgent are omitted from the log line when
// empty (e.g. a request that failed before the body was decoded);
// redirect_scheme/redirect_host are included only when the refusal concerns
// a redirect URI. extra carries call-site-specific attributes appended
// as-is (e.g. redirect_uri_count on the accepted path).
func (s *Server) auditRegistration(outcome string, reason regReason, clientName, userAgent, scheme, host string, extra ...any) {
	attrs := []any{"outcome", outcome, "reason", string(reason)}
	if clientName != "" {
		attrs = append(attrs, "client_name", clientName)
	}
	if userAgent != "" {
		attrs = append(attrs, "user_agent", userAgent)
	}
	if scheme != "" || host != "" {
		attrs = append(attrs, "redirect_scheme", scheme, "redirect_host", host)
	}
	attrs = append(attrs, extra...)
	slog.Info("oauth: client_registration audit", attrs...)
	if s.metrics != nil {
		s.metrics.CountOAuthClientRegistration(outcome, string(reason))
	}
}
