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
	"net/url"
	"sort"
	"strings"
)

// CoreReadonly is the read-only core profile: one named chat per read, in
// bounded pages, plus the caller's own state.
const CoreReadonly = "core-readonly"

// CoreReply is core-readonly plus a two-step reply: draft_reply shows the
// exact recipient and text and issues a one-shot confirmation, send_reply
// delivers exactly that and nothing else.
const CoreReply = "core-reply"

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

func coreReadonlyTools() map[string]Rule {
	return map[string]Rule{
		"list_dialogs":        {},
		"get_messages":        noMedia(messagePage),
		"get_unread_messages": withPeer(noMedia(messagePage)),
		"search_messages":     withPeer(messagePage),
		"get_my_identity":     {},
		"get_my_send_status":  {},
		"get_my_audit_log":    {},
	}
}

func coreReplyTools() map[string]Rule {
	t := coreReadonlyTools()
	t["draft_reply"] = Rule{}
	t["send_reply"] = Rule{}
	return t
}

var profiles = map[string]Profile{
	CoreReadonly: {Name: CoreReadonly, Tools: coreReadonlyTools()},
	CoreReply:    {Name: CoreReply, Tools: coreReplyTools()},
}

// profileOnlyTools exist only inside a profile: a caller whose credential
// carries no profile is never shown them and cannot call them, so adding
// them leaves the unprofiled surface exactly as it was. draft_reply and
// send_reply duplicate what send_message already offers everyone else, in
// a stricter shape that only means something under core-reply.
var profileOnlyTools = map[string]bool{
	"draft_reply": true,
	"send_reply":  true,
}

// ProfileOnly reports whether the named tool is offered only to a caller
// whose profile lists it.
func ProfileOnly(name string) bool { return profileOnlyTools[name] }

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

// reservedClientIDs are client_ids the table must never bind. The
// self-connect client (oauth.ConnectClientID) mints the browser's
// mctl_connect_token cookie for /telegram/connect/manage; a profiled
// credential is refused outside the MCP endpoint, so binding it would lock
// every user out of their own manage page. internal/oauth pins that this
// list names its constant.
var reservedClientIDs = map[string]string{
	"mctl_self_connect": "it is the built-in self-connect client behind the manage page, which a profiled credential cannot open",
}

// Reserved reports whether id is a client_id the table refuses to bind.
func Reserved(id string) bool {
	_, ok := reservedClientIDs[id]
	return ok
}

// Binding is one record of the MCP_CLIENT_PROFILES table. A record names
// exactly one of ClientID and RedirectURI.
type Binding struct {
	// ClientID is matched byte-for-byte against the OAuth client_id the
	// token is minted for: a CIMD client_id URL or a preregistered id.
	ClientID string `json:"client_id,omitempty"`
	// RedirectURI is matched byte-for-byte against the redirect_uri of the
	// authorization the token descends from. It is how a client without a
	// stable client_id (dynamic registration, an implicit DCR host) is
	// bound: every registration of the product uses the same callback. The
	// authorization server stores the redirect_uri in the refresh-token
	// family, so the binding is re-resolved at every refresh like a
	// client_id binding.
	RedirectURI string `json:"redirect_uri,omitempty"`
	Profile     string `json:"profile"`
}

// Bindings is the decoded MCP_CLIENT_PROFILES table.
type Bindings struct {
	// ByClientID maps an exact client_id to a profile name.
	ByClientID map[string]string
	// ByRedirectURI maps an exact redirect_uri to a profile name.
	ByRedirectURI map[string]string
}

// Empty reports whether the table restricts no client at all.
func (b Bindings) Empty() bool { return len(b.ByClientID) == 0 && len(b.ByRedirectURI) == 0 }

// Resolve returns the profile bound to a token minted for clientID from an
// authorization whose redirect_uri was redirectURI, or "" when neither is
// bound. A client_id binding wins over a redirect_uri binding: it names the
// client itself, the redirect_uri only its callback. An empty redirectURI
// matches nothing; the caller decides what an unknown redirect_uri means.
//
// Because a profile only narrows a client's surface, a client that
// registers someone else's redirect_uri can only restrict itself; it can
// never reach a wider surface through this table.
func (b Bindings) Resolve(clientID, redirectURI string) string {
	if p, ok := b.ByClientID[clientID]; ok {
		return p
	}
	if redirectURI == "" {
		return ""
	}
	return b.ByRedirectURI[redirectURI]
}

// ParseBindings decodes MCP_CLIENT_PROFILES, a JSON array of
// {"client_id": "...", "profile": "..."} and
// {"redirect_uri": "...", "profile": "..."} records. An empty value yields
// an empty table: no client is restricted, which is the behaviour before
// profiles existed.
//
// It fails closed on everything else that is not a valid table: unknown
// keys, a record naming both or neither of client_id and redirect_uri, a
// reserved client_id, a redirect_uri that is not an absolute URL, an
// unknown profile name, a duplicate key, surrounding whitespace, trailing
// data. The operator who set the variable is relying on the restriction, so
// a typo must stop the server rather than leave a client unrestricted.
func ParseBindings(raw string) (*Bindings, error) {
	out := &Bindings{ByClientID: map[string]string{}, ByRedirectURI: map[string]string{}}
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
		switch {
		case b.ClientID != "" && b.RedirectURI != "":
			return nil, fmt.Errorf("record %d: names both client_id and redirect_uri; a record binds exactly one of them", i)
		case b.RedirectURI != "":
			uri := b.RedirectURI
			if strings.TrimSpace(uri) != uri {
				return nil, fmt.Errorf("record %d: redirect_uri %q has surrounding whitespace; it is matched byte-for-byte", i, uri)
			}
			if u, err := url.Parse(uri); err != nil || u.Scheme == "" || u.Host == "" || u.Fragment != "" {
				return nil, fmt.Errorf("record %d: redirect_uri %q is not an absolute URL without a fragment", i, uri)
			}
			if _, ok := Lookup(b.Profile); !ok {
				return nil, fmt.Errorf("record %d (%s): unknown profile %q (known: %s)", i, uri, b.Profile, strings.Join(Names(), ", "))
			}
			if _, dup := out.ByRedirectURI[uri]; dup {
				return nil, fmt.Errorf("record %d: duplicate redirect_uri %q", i, uri)
			}
			out.ByRedirectURI[uri] = b.Profile
		default:
			id := strings.TrimSpace(b.ClientID)
			if id == "" {
				return nil, fmt.Errorf("record %d: client_id or redirect_uri is required", i)
			}
			if id != b.ClientID {
				return nil, fmt.Errorf("record %d: client_id %q has surrounding whitespace; it is matched byte-for-byte", i, b.ClientID)
			}
			if why, reserved := reservedClientIDs[id]; reserved {
				return nil, fmt.Errorf("record %d: client_id %q cannot be bound: %s", i, id, why)
			}
			if _, ok := Lookup(b.Profile); !ok {
				return nil, fmt.Errorf("record %d (%s): unknown profile %q (known: %s)", i, id, b.Profile, strings.Join(Names(), ", "))
			}
			if _, dup := out.ByClientID[id]; dup {
				return nil, fmt.Errorf("record %d: duplicate client_id %q", i, id)
			}
			out.ByClientID[id] = b.Profile
		}
	}
	return out, nil
}
