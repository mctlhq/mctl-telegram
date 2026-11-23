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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"

	"github.com/mctlhq/mctl-telegram/internal/jsonstrict"
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

// noFolder keeps a message read to the one named chat: folder (#1155)
// reads every chat in a folder, which is the cross-chat read the core
// profiles exist to refuse, and peer is required there anyway.
func noFolder(r Rule) Rule {
	r.Forbidden = append(r.Forbidden, "folder")
	return r
}

func noMedia(r Rule) Rule {
	r.Forbidden = append([]string{"fetch_media"}, r.Forbidden...)
	return r
}

func coreReadonlyTools() map[string]Rule {
	return map[string]Rule{
		"list_dialogs":        {},
		"list_folders":        {},
		"list_topics":         {},
		"get_messages":        noMedia(messagePage),
		"get_unread_messages": withPeer(noFolder(noMedia(messagePage))),
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
// exactly one of ClientID, ClientIDPrefix and RedirectURI.
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
	// ClientIDPrefix bounds every URL client_id below it: a product that
	// registers one CIMD client per install shares neither a client_id nor
	// a callback between installs (ChatGPT's connectors use
	// https://chatgpt.com/oauth/<id>/client.json and call back to
	// https://chatgpt.com/connector/oauth/<id>), so only the part of the
	// client_id in front of the install id names the product. It is
	// "https://" + a lowercase host name + a path ending in "/", and it
	// matches a client_id on that host whose path starts with that path
	// (see matchesClientIDPrefix). A CIMD client_id is the URL its document
	// was fetched from, so only whoever serves that part of the host can
	// place a client under the prefix.
	//
	// Such a record carries a ScopeCeiling and nothing else. It cannot bind
	// a profile.
	ClientIDPrefix string `json:"client_id_prefix,omitempty"`
	// Profile is the tool profile the client is bound to. It may be omitted
	// only on a record that carries a ScopeCeiling.
	Profile string `json:"profile,omitempty"`
	// ScopeCeiling, when present, is the allowlist of OAuth scopes any
	// access token minted for this client_id may carry (mctl-telegram#1326,
	// threat model T8). The authorization server intersects every grant
	// with it, membership-granted scopes (admin:users, admin:users:read,
	// admin:broadcast) included, and mints the token with no groups. On a
	// redirect_uri record it bounds every client that authorizes with that
	// exact callback, which is how a client without a stable client_id
	// (DCR) gets a ceiling, provided every registration shares the callback.
	// On a client_id_prefix record it bounds every URL client_id below the
	// prefix. When several ceilings match, the exact client_id wins, then
	// the longest client_id_prefix, then the redirect_uri.
	//
	// It is kept raw so that three cases stay distinguishable: an absent
	// key (nil: no ceiling, today's behaviour), an explicit null (refused:
	// a null must never read as "no ceiling" on a record the operator
	// wrote a ceiling into) and a list (validated by parseScopeCeiling).
	ScopeCeiling json.RawMessage `json:"scope_ceiling,omitempty"`
}

// bindingKeys are the only member names a Binding record may carry, spelled
// exactly.
var bindingKeys = []string{"client_id", "client_id_prefix", "redirect_uri", "profile", "scope_ceiling"}

// Bindings is the decoded MCP_CLIENT_PROFILES table.
type Bindings struct {
	// ByClientID maps an exact client_id to a profile name.
	ByClientID map[string]string
	// ByRedirectURI maps an exact redirect_uri to a profile name.
	ByRedirectURI map[string]string
	// ScopeCeilingByClientID maps an exact client_id to the allowlist of
	// scopes its tokens may carry. A client_id absent from it has no
	// ceiling. A present entry is never empty (ParseBindings refuses that).
	ScopeCeilingByClientID map[string][]string
	// ScopeCeilingByRedirectURI maps an exact redirect_uri to the allowlist
	// of scopes the tokens of every client authorizing with it may carry. It
	// is consulted only when the client_id has no ceiling of its own.
	ScopeCeilingByRedirectURI map[string][]string
	// ScopeCeilingByClientIDPrefix maps a client_id prefix (see
	// Binding.ClientIDPrefix) to the allowlist of scopes the tokens of every
	// URL client_id below it may carry. It is consulted when the exact
	// client_id has no ceiling, and before the redirect_uri.
	ScopeCeilingByClientIDPrefix map[string][]string
}

// Empty reports whether the table restricts no client at all.
func (b Bindings) Empty() bool {
	return len(b.ByClientID) == 0 && len(b.ByRedirectURI) == 0 && len(b.ScopeCeilingByClientID) == 0 &&
		len(b.ScopeCeilingByRedirectURI) == 0 && len(b.ScopeCeilingByClientIDPrefix) == 0
}

// ScopeCeiling returns the scope allowlist bound to the exact clientID, and
// whether one is bound. It deliberately has no redirect_uri fallback: use
// ScopeCeilingFor where the redirect_uri is known.
func (b Bindings) ScopeCeiling(clientID string) ([]string, bool) {
	c, ok := b.ScopeCeilingByClientID[clientID]
	return c, ok
}

// ClientIDScopeCeiling returns the scope allowlist the client_id alone
// selects, and whether there is one: the exact client_id's, or failing that
// the one of the longest client_id prefix clientID is below. Unlike a
// redirect_uri ceiling it needs nothing but the client_id, so it is known
// even for a grant whose redirect_uri is not.
func (b Bindings) ClientIDScopeCeiling(clientID string) ([]string, bool) {
	if c, ok := b.ScopeCeilingByClientID[clientID]; ok {
		return c, true
	}
	var (
		best    []string
		bestLen = -1
	)
	for prefix, c := range b.ScopeCeilingByClientIDPrefix {
		// Prefixes on one host nest, so the longest match is the most
		// specific; two prefixes of equal length cannot both match.
		if len(prefix) > bestLen && matchesClientIDPrefix(prefix, clientID) {
			best, bestLen = c, len(prefix)
		}
	}
	return best, bestLen >= 0
}

// matchesClientIDPrefix reports whether clientID is an https URL on the
// prefix's host whose path starts with the prefix's path. prefix has passed
// ValidateClientIDPrefix. The comparison is on the client_id as a URL, not
// as bytes: the host is compared case-insensitively and without a port, and
// the path after percent-decoding, so "https://CHATGPT.com:443/%6Fauth/x" is
// below "https://chatgpt.com/oauth/", and so is a host with a trailing dot. Every such spelling must match: a
// ceiling only narrows, so a spelling that slipped past it would leave that
// client with the wider grant.
func matchesClientIDPrefix(prefix, clientID string) bool {
	host, path, ok := strings.Cut(strings.TrimPrefix(prefix, "https://"), "/")
	if !ok {
		return false
	}
	u, err := url.Parse(clientID)
	if err != nil || u.Scheme != "https" || u.Opaque != "" {
		return false
	}
	return strings.TrimSuffix(strings.ToLower(u.Hostname()), ".") == host && strings.HasPrefix(u.Path, "/"+path)
}

// ValidateClientIDPrefix checks a client_id_prefix: "https://", a lowercase
// host name, and a path that ends in "/". The path is "/" (every client_id
// on the host) or whole segments, so that a prefix always ends on a segment
// boundary and "https://a.example/oauth/" cannot match "/oauthx/...".
// ParseBindings applies it; it is exported for a table built in code.
func ValidateClientIDPrefix(p string) error {
	if strings.TrimSpace(p) != p {
		return errors.New("has surrounding whitespace")
	}
	rest, ok := strings.CutPrefix(p, "https://")
	if !ok {
		return errors.New("must start with https://")
	}
	host, path, ok := strings.Cut(rest, "/")
	if !ok {
		return errors.New("must end with \"/\": name the host as https://host/ or a path as https://host/path/")
	}
	if host == "" || host != strings.ToLower(host) || strings.ContainsAny(host, ":@*?#\\% \t\r\n\v\f") ||
		strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") || !strings.Contains(host, ".") {
		return fmt.Errorf("host %q is not a lowercase host name without a port", host)
	}
	if net.ParseIP(host) != nil {
		return fmt.Errorf("host %q is an IP literal", host)
	}
	if path == "" {
		return nil
	}
	if !strings.HasSuffix(path, "/") {
		return errors.New("must end with \"/\" so that it matches whole path segments")
	}
	if strings.ContainsAny(path, "%\\?#@* \t\r\n\v\f") {
		return errors.New("path contains a forbidden character")
	}
	for _, seg := range strings.Split(strings.TrimSuffix(path, "/"), "/") {
		if seg == "" || seg == "." || seg == ".." {
			return errors.New("path has an empty, \".\" or \"..\" segment")
		}
	}
	return nil
}

// ScopeCeilingFor returns the scope allowlist that bounds a token minted for
// clientID from an authorization whose redirect_uri was redirectURI, and
// whether one applies. A ceiling the client_id selects (ClientIDScopeCeiling:
// exact, then longest prefix) wins over a redirect_uri ceiling, mirroring
// Resolve. An empty redirectURI matches no redirect_uri ceiling; the caller
// decides what an unknown redirect_uri means.
func (b Bindings) ScopeCeilingFor(clientID, redirectURI string) ([]string, bool) {
	if c, ok := b.ClientIDScopeCeiling(clientID); ok {
		return c, true
	}
	if redirectURI == "" {
		return nil, false
	}
	c, ok := b.ScopeCeilingByRedirectURI[redirectURI]
	return c, ok
}

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
// {"redirect_uri": "...", "profile": "..."} records. Either kind may also
// carry "scope_ceiling": [...], with or without a profile. A third kind,
// {"client_id_prefix": "...", "scope_ceiling": [...]}, carries a ceiling
// only. An empty
// value yields an empty table: no client is restricted, which is the
// behaviour before profiles existed.
//
// A scope_ceiling is refused when it is null, not a list of strings, empty,
// or has an entry that is blank, contains whitespace or repeats.
//
// Keys are checked strictly before anything is decoded. encoding/json keeps
// the last of a repeated member and matches member names
// case-insensitively, so a repeated "scope_ceiling" ending in null, a
// repeated "client_id" or an alias such as "SCOPE_CEILING" would otherwise
// silently drop a ceiling or move it to another client. A repeated key at
// any depth, or a record key not spelled exactly as one of client_id,
// client_id_prefix, redirect_uri, profile and scope_ceiling, is refused.
// Whether each entry names a scope the server can grant is checked by the
// authorization server at construction, since this package cannot know the
// scope set.
//
// It fails closed on everything else that is not a valid table: unknown
// keys, a record naming more than one or none of client_id, client_id_prefix
// and redirect_uri, a client_id_prefix record with a profile or without a
// ceiling, a malformed client_id_prefix, a reserved client_id, a redirect_uri that is not an absolute URL, an
// unknown profile name, a duplicate key, surrounding whitespace, trailing
// data. The operator who set the variable is relying on the restriction, so
// a typo must stop the server rather than leave a client unrestricted.
func ParseBindings(raw string) (*Bindings, error) {
	out := &Bindings{ByClientID: map[string]string{}, ByRedirectURI: map[string]string{}, ScopeCeilingByClientID: map[string][]string{}, ScopeCeilingByRedirectURI: map[string][]string{}, ScopeCeilingByClientIDPrefix: map[string][]string{}}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return out, nil
	}
	if err := jsonstrict.RejectDuplicateKeys([]byte(raw)); err != nil {
		if errors.Is(err, jsonstrict.ErrTrailingData) {
			return nil, errors.New("trailing data after the JSON array")
		}
		if errors.Is(err, jsonstrict.ErrDuplicateKey) {
			return nil, err
		}
		return nil, fmt.Errorf("decode: %w", err)
	}
	var rawRecs []json.RawMessage
	if err := json.Unmarshal([]byte(raw), &rawRecs); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	recs := make([]Binding, len(rawRecs))
	for i, rec := range rawRecs {
		dec := json.NewDecoder(bytes.NewReader(rec))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&recs[i]); err != nil {
			return nil, fmt.Errorf("decode: record %d: %w", i, err)
		}
		if err := jsonstrict.ObjectKeysWithin(rec, bindingKeys...); err != nil {
			return nil, fmt.Errorf("record %d: %w; keys are matched exactly (%s)", i, err, strings.Join(bindingKeys, ", "))
		}
	}
	for i, b := range recs {
		switch {
		case b.ClientID != "" && b.RedirectURI != "":
			return nil, fmt.Errorf("record %d: names both client_id and redirect_uri; a record binds exactly one of them", i)
		case b.ClientIDPrefix != "" && (b.ClientID != "" || b.RedirectURI != ""):
			return nil, fmt.Errorf("record %d: names client_id_prefix together with client_id or redirect_uri; a record binds exactly one of them", i)
		case b.ClientIDPrefix != "":
			prefix := b.ClientIDPrefix
			if err := ValidateClientIDPrefix(prefix); err != nil {
				return nil, fmt.Errorf("record %d: client_id_prefix %q: %w", i, prefix, err)
			}
			if b.Profile != "" {
				return nil, fmt.Errorf("record %d (%s): a client_id_prefix record cannot bind a profile; it carries a scope_ceiling only", i, prefix)
			}
			if b.ScopeCeiling == nil {
				return nil, fmt.Errorf("record %d (%s): a client_id_prefix record needs a scope_ceiling", i, prefix)
			}
			if _, dup := out.ScopeCeilingByClientIDPrefix[prefix]; dup {
				return nil, fmt.Errorf("record %d: duplicate client_id_prefix %q", i, prefix)
			}
			ceiling, err := parseScopeCeiling(b.ScopeCeiling)
			if err != nil {
				return nil, fmt.Errorf("record %d (%s): scope_ceiling: %w", i, prefix, err)
			}
			out.ScopeCeilingByClientIDPrefix[prefix] = ceiling
		case b.RedirectURI != "":
			uri := b.RedirectURI
			if strings.TrimSpace(uri) != uri {
				return nil, fmt.Errorf("record %d: redirect_uri %q has surrounding whitespace; it is matched byte-for-byte", i, uri)
			}
			if u, err := url.Parse(uri); err != nil || u.Scheme == "" || u.Host == "" || u.Fragment != "" {
				return nil, fmt.Errorf("record %d: redirect_uri %q is not an absolute URL without a fragment", i, uri)
			}
			// A ceiling-only record needs no profile; every other record
			// does, with the same error as before ceilings were allowed here.
			if b.ScopeCeiling == nil || b.Profile != "" {
				if _, ok := Lookup(b.Profile); !ok {
					return nil, fmt.Errorf("record %d (%s): unknown profile %q (known: %s)", i, uri, b.Profile, strings.Join(Names(), ", "))
				}
			}
			_, dupProfile := out.ByRedirectURI[uri]
			_, dupCeiling := out.ScopeCeilingByRedirectURI[uri]
			if dupProfile || dupCeiling {
				return nil, fmt.Errorf("record %d: duplicate redirect_uri %q", i, uri)
			}
			if b.ScopeCeiling != nil {
				ceiling, err := parseScopeCeiling(b.ScopeCeiling)
				if err != nil {
					return nil, fmt.Errorf("record %d (%s): scope_ceiling: %w", i, uri, err)
				}
				out.ScopeCeilingByRedirectURI[uri] = ceiling
			}
			if b.Profile != "" {
				out.ByRedirectURI[uri] = b.Profile
			}
		default:
			id := strings.TrimSpace(b.ClientID)
			if id == "" {
				return nil, fmt.Errorf("record %d: client_id, client_id_prefix or redirect_uri is required", i)
			}
			if id != b.ClientID {
				return nil, fmt.Errorf("record %d: client_id %q has surrounding whitespace; it is matched byte-for-byte", i, b.ClientID)
			}
			if why, reserved := reservedClientIDs[id]; reserved {
				return nil, fmt.Errorf("record %d: client_id %q cannot be bound: %s", i, id, why)
			}
			// A ceiling-only record needs no profile; every other record
			// does, with the same error as before ceilings existed.
			if b.ScopeCeiling == nil || b.Profile != "" {
				if _, ok := Lookup(b.Profile); !ok {
					return nil, fmt.Errorf("record %d (%s): unknown profile %q (known: %s)", i, id, b.Profile, strings.Join(Names(), ", "))
				}
			}
			_, dupProfile := out.ByClientID[id]
			_, dupCeiling := out.ScopeCeilingByClientID[id]
			if dupProfile || dupCeiling {
				return nil, fmt.Errorf("record %d: duplicate client_id %q", i, id)
			}
			if b.ScopeCeiling != nil {
				ceiling, err := parseScopeCeiling(b.ScopeCeiling)
				if err != nil {
					return nil, fmt.Errorf("record %d (%s): scope_ceiling: %w", i, id, err)
				}
				out.ScopeCeilingByClientID[id] = ceiling
			}
			if b.Profile != "" {
				out.ByClientID[id] = b.Profile
			}
		}
	}
	return out, nil
}

// parseScopeCeiling validates one scope_ceiling list. It refuses an empty
// list rather than reading it as "no scopes": an operator who meant to
// remove the ceiling deletes the key, and one who meant "nothing" has a
// typo somewhere. Either way the server must not start on a guess.
func parseScopeCeiling(rawJSON json.RawMessage) ([]string, error) {
	if bytes.Equal(bytes.TrimSpace(rawJSON), []byte("null")) {
		return nil, errors.New("is null; name at least one scope, or remove the key to set no ceiling")
	}
	var raw []string
	if err := json.Unmarshal(rawJSON, &raw); err != nil {
		return nil, fmt.Errorf("is not a list of scope strings: %w", err)
	}
	if len(raw) == 0 {
		return nil, errors.New("is empty; name at least one scope, or remove the key to set no ceiling")
	}
	seen := make(map[string]struct{}, len(raw))
	out := make([]string, 0, len(raw))
	for _, sc := range raw {
		if f := strings.Fields(sc); len(f) != 1 || f[0] != sc {
			return nil, fmt.Errorf("entry %q is not a single scope token", sc)
		}
		if _, dup := seen[sc]; dup {
			return nil, fmt.Errorf("duplicate scope %q", sc)
		}
		seen[sc] = struct{}{}
		out = append(out, sc)
	}
	return out, nil
}
