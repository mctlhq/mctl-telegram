package connection

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"
)

// allowedScopes is the exact Phase 1 scope set per server (threat model T8).
// The effective scope of every token must EQUAL this set: not a superset,
// not a subset.
//
// tg: the two read scopes, matching the per-client scope ceiling of #1326
// (internal/oauth ScopeCeilingByClientID). alice: iot:view only (owner
// decision 2026-11-18 on #1314).
var allowedScopes = map[Server][]string{
	ServerTG:    {"telegram:dialogs:read", "telegram:messages:read"},
	ServerAlice: {"iot:view"},
}

// AllowedScopes returns a copy of the allowed scope set for server, sorted.
func AllowedScopes(server Server) ([]string, bool) {
	s, ok := allowedScopes[server]
	if !ok {
		return nil, false
	}
	out := slices.Clone(s)
	slices.Sort(out)
	return out, true
}

// CanonicalScope is the stored form of an allowed set: sorted, single-space
// joined.
func CanonicalScope(server Server) (string, bool) {
	s, ok := AllowedScopes(server)
	if !ok {
		return "", false
	}
	return strings.Join(s, " "), true
}

// TokenSet is the parsed part of a token response that the store keeps.
type TokenSet struct {
	AccessToken  Secret
	RefreshToken Secret
	// ExpiresIn is seconds, 0 when the server did not say.
	ExpiresIn int64
	// ExpiresAt is when the access token expires: the time its response
	// was received plus ExpiresIn (#1318 slice C2b). The zero time means
	// unknown, never "does not expire": the server did not say, said 0, or
	// the set was sealed before expiries were kept. An unknown expiry is
	// never refreshed ahead; only the server's 401 refreshes it.
	ExpiresAt time.Time
}

// receivedAt stamps the expiry of a set parsed from a response received
// at at. It is the receipt, not the time the set is sealed, that the
// server's expires_in counts from. A lifetime past MaxExpiresIn is cut
// to it: time.Duration overflows from about 9.2e9 seconds, and an
// overflowed expiry would land in the past and refresh every call.
func (t TokenSet) receivedAt(at time.Time) TokenSet {
	t.ExpiresAt = time.Time{}
	if t.ExpiresIn > 0 && !at.IsZero() {
		t.ExpiresAt = at.Add(time.Duration(min(t.ExpiresIn, MaxExpiresIn)) * time.Second).UTC()
	}
	return t
}

// MaxExpiresIn is the longest access-token lifetime taken from a server,
// in seconds: one year.
const MaxExpiresIn = 365 * 24 * 60 * 60

// tokenSetWire is the sealed form. It is only ever marshalled into a DEK
// seal and never logged. ExpiresAtMS is absent from a set sealed before
// #1318 slice C2b, which opens with an unknown expiry.
type tokenSetWire struct {
	AccessToken  string `json:"a"`
	RefreshToken string `json:"r,omitempty"`
	ExpiresIn    int64  `json:"e,omitempty"`
	ExpiresAtMS  int64  `json:"x,omitempty"`
}

func (t TokenSet) marshal() ([]byte, error) {
	w := tokenSetWire{
		AccessToken:  t.AccessToken.Reveal(),
		RefreshToken: t.RefreshToken.Reveal(),
		ExpiresIn:    t.ExpiresIn,
	}
	if !t.ExpiresAt.IsZero() {
		w.ExpiresAtMS = t.ExpiresAt.UnixMilli()
	}
	return json.Marshal(w)
}

func unmarshalTokenSet(b []byte) (TokenSet, error) {
	var w tokenSetWire
	if err := json.Unmarshal(b, &w); err != nil || w.AccessToken == "" || w.ExpiresAtMS < 0 {
		return TokenSet{}, fmt.Errorf("%w: sealed token set", ErrUnreadable)
	}
	ts := TokenSet{AccessToken: NewSecret(w.AccessToken), RefreshToken: NewSecret(w.RefreshToken), ExpiresIn: w.ExpiresIn}
	if w.ExpiresAtMS > 0 {
		ts.ExpiresAt = time.UnixMilli(w.ExpiresAtMS).UTC()
	}
	return ts, nil
}

// ScopeCheck is the outcome of VerifyTokenResponse. Tokens is set whenever
// the response carried a usable access token, even if the scope check
// failed, so the caller can revoke what the server issued.
type ScopeCheck struct {
	Tokens TokenSet
	// Granted is the canonical granted scope; set only when Err is nil.
	Granted string
	Err     error
}

// VerifyTokenResponse is VerifyTokenResponseFor for a connection that asked
// for the read scope set only.
func VerifyTokenResponse(server Server, raw []byte) ScopeCheck {
	return VerifyTokenResponseFor(server, "", raw)
}

// VerifyTokenResponseFor parses an OAuth token response (RFC 6749 section
// 5.1) and checks, fail-closed, its effective scope against what the
// connection asked for (threat model T8, S1-T9, S1-T10):
//
//   - a missing "scope" field fails: the server did not report the
//     effective scope, and "probably the requested one" is not an answer;
//   - a non-string, empty, badly delimited, duplicated or out-of-charset
//     value fails as unparseable;
//   - a connection that asked for the read set (requested is empty or the
//     read set) must be granted exactly the read set;
//   - a connection that asked for the write set (WriteRequestScope) must
//     be granted exactly the write set or exactly the read set. The second
//     is a narrowed grant: the principal, or the server, withheld the write
//     scope. It is recorded as what it is, the read set, and the
//     connection never holds a write scope it was not given;
//   - any other set fails, a wider one included: nothing the server adds
//     on its own is accepted.
//
// Granted is always the reported set, never the requested one. Every
// failure wraps ErrScopeMismatch or ErrTokenResponse.
func VerifyTokenResponseFor(server Server, requested string, raw []byte) ScopeCheck {
	allowed, ok := AllowedScopes(server)
	if !ok {
		return ScopeCheck{Err: fmt.Errorf("%w: unknown server", ErrScopeMismatch)}
	}
	read := strings.Join(allowed, " ")
	wide, _ := WriteRequestScope(server)
	if requested != "" && requested != read && requested != wide {
		// A requested set this build does not ask for: the row is not one
		// it wrote, and nothing is accepted for it.
		return ScopeCheck{Err: fmt.Errorf("%w: unknown requested scope", ErrScopeMismatch)}
	}
	var fields map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&fields); err != nil || fields == nil {
		return ScopeCheck{Err: fmt.Errorf("%w: not a JSON object", ErrTokenResponse)}
	}
	var out ScopeCheck
	access, ok := jsonString(fields["access_token"])
	if !ok || access == "" {
		return ScopeCheck{Err: fmt.Errorf("%w: no access_token", ErrTokenResponse)}
	}
	out.Tokens.AccessToken = NewSecret(access)
	if rt, present := fields["refresh_token"]; present {
		v, ok := jsonString(rt)
		if !ok {
			out.Err = fmt.Errorf("%w: refresh_token is not a string", ErrTokenResponse)
			return out
		}
		out.Tokens.RefreshToken = NewSecret(v)
	}
	if tt, present := fields["token_type"]; present {
		v, ok := jsonString(tt)
		if !ok || !strings.EqualFold(v, "bearer") {
			out.Err = fmt.Errorf("%w: token_type is not bearer", ErrTokenResponse)
			return out
		}
	}
	if ei, present := fields["expires_in"]; present {
		var n int64
		if err := json.Unmarshal(ei, &n); err != nil || n < 0 {
			out.Err = fmt.Errorf("%w: expires_in is not a non-negative integer", ErrTokenResponse)
			return out
		}
		out.Tokens.ExpiresIn = n
	}
	scopeRaw, present := fields["scope"]
	if !present {
		out.Err = fmt.Errorf("%w: no scope field", ErrScopeMismatch)
		return out
	}
	scope, ok := jsonString(scopeRaw)
	if !ok {
		out.Err = fmt.Errorf("%w: scope is not a string", ErrScopeMismatch)
		return out
	}
	got, err := parseScope(scope)
	if err != nil {
		out.Err = err
		return out
	}
	granted := strings.Join(got, " ")
	if !slices.Equal(got, allowed) && !(wide != "" && requested == wide && granted == wide) {
		out.Err = fmt.Errorf("%w: got %d scopes, want exactly the %d allowed", ErrScopeMismatch, len(got), len(allowed))
		return out
	}
	out.Granted = granted
	return out
}

// parseScope parses an RFC 6749 section 3.3 scope value strictly: tokens
// separated by exactly one space, each from the scope-token charset, no
// duplicates. It returns the tokens sorted.
func parseScope(s string) ([]string, error) {
	if s == "" {
		return nil, fmt.Errorf("%w: empty scope", ErrScopeMismatch)
	}
	parts := strings.Split(s, " ")
	for _, p := range parts {
		if p == "" {
			return nil, fmt.Errorf("%w: unparseable scope delimiter", ErrScopeMismatch)
		}
		for i := 0; i < len(p); i++ {
			c := p[i]
			// scope-token = 1*( %x21 / %x23-5B / %x5D-7E )
			if c < 0x21 || c == 0x22 || c == 0x5C || c > 0x7E {
				return nil, fmt.Errorf("%w: unparseable scope character", ErrScopeMismatch)
			}
		}
	}
	slices.Sort(parts)
	if len(slices.Compact(slices.Clone(parts))) != len(parts) {
		return nil, fmt.Errorf("%w: duplicated scope", ErrScopeMismatch)
	}
	return parts, nil
}

func jsonString(raw json.RawMessage) (string, bool) {
	if raw == nil {
		return "", false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false
	}
	return s, true
}
