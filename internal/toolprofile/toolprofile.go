// Package toolprofile defines the restricted tool profiles of
// docs/design/core-profiles.md and the binding of OAuth clients to them.
//
// A profile is a named, server-side allowlist of MCP tools with per-tool
// argument rules. The authorization server stamps the profile bound to a
// client into every access token it mints for that client (claim "prf");
// the MCP layer intersects the profile with the caller's scopes, so a
// profile can only hide tools or tighten their arguments. It never grants a
// scope and never shows a tool the scopes would hide.
//
// The package has no dependencies on the MCP or OAuth packages so both can
// import it: config validates binding tables against Lookup at startup, the
// OAuth server resolves bindings, and internal/mcp enforces the rules.
package toolprofile

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// CoreReadonly is the read-only core profile: one named chat per read, in
// bounded pages, plus the caller's own state.
const CoreReadonly = "core-readonly"

// Rule is the argument policy a profile applies to one tool. The zero Rule
// leaves the tool's arguments as they are.
type Rule struct {
	// Required lists arguments the profile makes mandatory even where the
	// tool itself treats them as optional (peer on a cross-chat read). A
	// required argument must be a non-blank string: every argument a core
	// profile requires today is a peer reference. A rule requiring a
	// numeric or boolean argument needs the check in internal/mcp widened.
	Required []string
	// Forbidden lists arguments the profile refuses when they are set to
	// anything but their zero value (fetch_media=true). They are also
	// removed from the schema the client is shown.
	Forbidden []string
	// LimitDefault, when non-zero, is the "limit" a call without one gets.
	LimitDefault int
	// LimitMax, when non-zero, is the largest "limit" the profile accepts.
	// A larger value is refused, not clamped, so the caller learns the
	// bound instead of silently receiving less than it asked for.
	LimitMax int
}

// Profile is a named allowlist of tools with their argument rules. A tool
// absent from Tools is hidden and refused.
//
// A profile must never list a tool that mints a credential
// (mint_worker_token, or anything like it): the minted token carries
// caller-chosen scopes and no profile, so it would escape the restriction.
// auth.Middleware closes the HTTP minting routes to profiled credentials
// for the same reason.
type Profile struct {
	Name  string
	Tools map[string]Rule
}

// messagePage is the bound every message-returning read shares under the
// core profiles: 20 by default, 50 at most (owner decision 2026-10-21).
var messagePage = Rule{LimitDefault: 20, LimitMax: 50}

func withPeer(r Rule) Rule {
	r.Required = append([]string{"peer"}, r.Required...)
	return r
}

func noMedia(r Rule) Rule {
	r.Forbidden = append([]string{"fetch_media"}, r.Forbidden...)
	return r
}

var profiles = map[string]Profile{
	CoreReadonly: {
		Name: CoreReadonly,
		Tools: map[string]Rule{
			"list_dialogs":        {},
			"get_messages":        noMedia(messagePage),
			"get_unread_messages": withPeer(noMedia(messagePage)),
			"search_messages":     withPeer(messagePage),
			"get_my_identity":     {},
			"get_my_send_status":  {},
			"get_my_audit_log":    {},
		},
	},
}

// Lookup returns the named profile. ok is false for an unknown name; callers
// must treat that as "nothing is allowed", never as "no profile".
func Lookup(name string) (Profile, bool) {
	p, ok := profiles[name]
	return p, ok
}

// Names returns every defined profile name, sorted.
func Names() []string {
	out := make([]string, 0, len(profiles))
	for n := range profiles {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Binding is one record of the MCP_CLIENT_PROFILES table.
type Binding struct {
	// ClientID is matched byte-for-byte against the OAuth client_id the
	// token is minted for: a CIMD client_id URL or a preregistered id.
	ClientID string `json:"client_id"`
	// RedirectURI is decoded only so that a record using it fails startup
	// with a clear message. Binding by redirect_uri is not supported: the
	// refresh path knows only the client_id, and an unregistered client's
	// redirect_uri is stored nowhere it could be re-read. Silently ignoring
	// the record would leave the client on the full surface.
	RedirectURI string `json:"redirect_uri,omitempty"`
	Profile     string `json:"profile"`
}

// ParseBindings decodes MCP_CLIENT_PROFILES, a JSON array of
// {"client_id": "...", "profile": "..."} records, into a client_id → profile
// map. An empty value yields an empty map: no client is restricted, which
// is the behaviour before profiles existed.
//
// It fails closed on everything else that is not a valid table: unknown
// keys, a redirect_uri record, a missing client_id, an unknown profile name,
// a duplicate client_id, trailing data. The operator who set the variable is
// relying on the restriction, so a typo must stop the server rather than
// leave a client unrestricted.
func ParseBindings(raw string) (map[string]string, error) {
	out := map[string]string{}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return out, nil
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	var recs []Binding
	if err := dec.Decode(&recs); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	if dec.More() {
		return nil, errors.New("trailing data after the JSON array")
	}
	for i, b := range recs {
		if b.RedirectURI != "" {
			return nil, fmt.Errorf("record %d: binding by redirect_uri is not supported; bind the exact client_id instead", i)
		}
		id := strings.TrimSpace(b.ClientID)
		if id == "" {
			return nil, fmt.Errorf("record %d: client_id is required", i)
		}
		if id != b.ClientID {
			return nil, fmt.Errorf("record %d: client_id %q has surrounding whitespace; it is matched byte-for-byte", i, b.ClientID)
		}
		if _, ok := Lookup(b.Profile); !ok {
			return nil, fmt.Errorf("record %d (%s): unknown profile %q (known: %s)", i, id, b.Profile, strings.Join(Names(), ", "))
		}
		if _, dup := out[id]; dup {
			return nil, fmt.Errorf("record %d: duplicate client_id %q", i, id)
		}
		out[id] = b.Profile
	}
	return out, nil
}
