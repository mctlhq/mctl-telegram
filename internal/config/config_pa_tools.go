package config

// config_pa_tools.go reads the settings of the Personal Assistant's tools
// runtime (#1318 slice C1): the KEK, the account-linking flow and each
// catalog server's OAuth client registration. It is separate from loadPA so
// that the tools runtime can only be configured, never half-configured:
// LoadPATools either returns a complete, validated set for every enabled
// server or an error naming the first variable that is missing or wrong.
//
// Nothing calls LoadPATools yet. Slice C2 calls it from the PA wiring,
// behind PA_ENABLED; until then no environment variable below is read by
// the running service (internal/pa.TestC1SymbolsNotWiredAtRuntime).

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
)

// PAAppPath is the path of the linking Mini App page on PUBLIC_BASE_URL. It
// equals linking.AppPath, which a test in that package keeps in step (this
// package cannot import linking: linking's dependencies import config).
const PAAppPath = "/pa/link/app"

// PAOAuthCallbackPrefix is the path prefix of the OAuth redirect URIs; the
// server name follows it. linking.New requires a redirect URI ending in
// this prefix plus the server name.
const PAOAuthCallbackPrefix = "/pa/oauth/callback/"

// PAServerEnv returns the environment variable holding one setting of one
// catalog server: PAServerEnv(connection.ServerTG, "ENABLED") is
// PA_SERVER_TG_ENABLED, the variable linking.ServerFlag reads.
func PAServerEnv(server connection.Server, setting string) string {
	return "PA_SERVER_" + strings.ToUpper(string(server)) + "_" + setting
}

// PATools is the validated configuration of the tools runtime.
type PATools struct {
	// KEK is the parsed KEK configuration. It is set, and has passed
	// connection.NewKEK, only when at least one server is enabled.
	KEK connection.KEKConfig
	// BotUsername, MiniAppName and AppURL configure the linking flow
	// (linking.Config). Set only when at least one server is enabled.
	BotUsername string
	MiniAppName string
	AppURL      string
	// Servers holds one entry per catalog server with a linking flag, enabled
	// or not. A disabled server carries only its name.
	Servers map[connection.Server]PAServer
}

// AnyEnabled reports whether at least one server is enabled.
func (t *PATools) AnyEnabled() bool {
	if t == nil {
		return false
	}
	for _, s := range t.Servers {
		if s.Enabled {
			return true
		}
	}
	return false
}

// PAServer is one catalog server's OAuth client registration.
type PAServer struct {
	Name    connection.Server
	Enabled bool
	// ClientID is the client id registered on the server's authorization
	// server (PA_SERVER_<NAME>_CLIENT_ID).
	ClientID string
	// Issuer is the one pinned issuer; the authorization server metadata is
	// fetched from it at startup and must name it.
	Issuer                string
	AuthorizationEndpoint string
	TokenEndpoint         string
	// RevocationEndpoint is the RFC 7009 endpoint. Optional: without it a
	// token cannot be revoked remotely, and the revoker says so.
	RevocationEndpoint string
	// MCPURL is the server's MCP endpoint.
	MCPURL string
	// Resource is the RFC 8707 resource indicator.
	Resource string
	// RedirectURI is PUBLIC_BASE_URL + PAOAuthCallbackPrefix + name.
	RedirectURI string
	// AllowedHosts is the egress host allowlist (egress.Config.AllowedHosts).
	// The issuer, token, revocation and MCP hosts are all on it.
	AllowedHosts []string
	// PromptConsent: the server supports prompt=consent.
	PromptConsent bool
}

// paToolServers are the servers LoadPATools reads, in a fixed order so the
// first error is deterministic. It is linking.FlagServers, which a test in
// that package keeps in step.
var paToolServers = []connection.Server{connection.ServerTG, connection.ServerAlice}

// paUsernameFormat is a Telegram bot username: 5-32 characters of
// [A-Za-z0-9_], ending in "bot" (Telegram's rule for bot usernames).
var paUsernameFormat = regexp.MustCompile(`^[A-Za-z0-9_]{2,29}[Bb][Oo][Tt]$`)

// paMiniAppNameFormat is a BotFather Mini App short name.
var paMiniAppNameFormat = regexp.MustCompile(`^[A-Za-z0-9_]{3,30}$`)

// paHostFormat is one bare host name of an allowlist: lower case letters,
// digits, dots and hyphens, no scheme, port, path or wildcard.
var paHostFormat = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

// LoadPATools reads the tools runtime settings through getenv. It reads
// nothing unless c.PAEnabled is set, and returns nil then.
//
// It fails closed:
//   - every PA_SERVER_<NAME>_ENABLED is read, and anything but empty,
//     "true" or "false" is an error;
//   - a disabled server needs nothing else, and nothing else of it is read;
//   - an enabled server needs its full registration, and each URL must be
//     https without userinfo or fragment; the hosts the service calls
//     (issuer, token, revocation, MCP) must be on its allowlist;
//   - with any server enabled, the KEK must build (connection.NewKEK) and
//     the linking settings must be complete, with PA_APP_URL exactly
//     PUBLIC_BASE_URL + PAAppPath;
//   - alice cannot be enabled: it has no account source yet, so a link
//     would be refused only after the code exchange.
//
// Errors name the variable, never its value.
func LoadPATools(c *Config, getenv func(string) string) (*PATools, error) {
	if c == nil || !c.PAEnabled {
		return nil, nil
	}
	t := &PATools{Servers: map[connection.Server]PAServer{}}
	for _, name := range paToolServers {
		on, err := paBool(getenv, PAServerEnv(name, "ENABLED"))
		if err != nil {
			return nil, err
		}
		t.Servers[name] = PAServer{Name: name, Enabled: on}
	}
	if !t.AnyEnabled() {
		return t, nil
	}
	if t.Servers[connection.ServerAlice].Enabled {
		return nil, fmt.Errorf("%s=true is not supported: alice has no account source, so its links cannot be verified", PAServerEnv(connection.ServerAlice, "ENABLED"))
	}
	base, err := paPublicBase(c.PublicBaseURL)
	if err != nil {
		return nil, err
	}
	if err := loadPAKEK(t, getenv); err != nil {
		return nil, err
	}
	if err := loadPALinking(t, getenv, base); err != nil {
		return nil, err
	}
	for _, name := range paToolServers {
		if !t.Servers[name].Enabled {
			continue
		}
		s, err := loadPAServer(name, getenv, base)
		if err != nil {
			return nil, err
		}
		t.Servers[name] = s
	}
	return t, nil
}

// paPublicBase is PUBLIC_BASE_URL as an https origin without a trailing
// slash: the redirect URIs and the app URL are built on it, and Telegram
// opens a web_app button only over https.
func paPublicBase(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery ||
		u.Fragment != "" || strings.Trim(u.Path, "/") != "" {
		return "", errors.New("PA tools require PUBLIC_BASE_URL to be an https origin")
	}
	return strings.TrimRight(raw, "/"), nil
}

func loadPAKEK(t *PATools, getenv func(string) string) error {
	kc, err := connection.LoadKEKConfig(getenv)
	if err != nil {
		// LoadKEKConfig's errors name the variable only.
		return fmt.Errorf("PA tools: %w", err)
	}
	switch kc.Mode {
	case connection.KEKModeLocal:
		if _, err := connection.NewKEK(kc); err != nil {
			return fmt.Errorf("PA tools: PA_KEK_MODE=local needs ENV=preview (or a local tier) and PA_KEK_LOCAL_KEY of 32 bytes: %w", err)
		}
	case connection.KEKModeTransit:
		// The transit KEK needs a Vault token source and an HTTP client, which
		// are not built yet; preview uses the local KEK (owner decision on
		// #1318). Refusing here is the fail-closed answer, not a default.
		return errors.New("PA tools: PA_KEK_MODE=transit is not supported yet; transit is required before production use")
	case "":
		return errors.New("PA tools: PA_KEK_MODE is required when a PA server is enabled")
	default:
		return errors.New("PA tools: PA_KEK_MODE must be local or transit")
	}
	t.KEK = kc
	return nil
}

func loadPALinking(t *PATools, getenv func(string) string, base string) error {
	t.BotUsername = strings.TrimSpace(getenv("PA_BOT_USERNAME"))
	if !paUsernameFormat.MatchString(t.BotUsername) {
		return errors.New("PA tools: PA_BOT_USERNAME must be the PA bot's username (5-32 characters of [A-Za-z0-9_], ending in bot)")
	}
	t.MiniAppName = strings.TrimSpace(getenv("PA_MINI_APP_NAME"))
	if !paMiniAppNameFormat.MatchString(t.MiniAppName) {
		return errors.New("PA tools: PA_MINI_APP_NAME must be the Mini App short name (3-30 characters of [A-Za-z0-9_])")
	}
	// Compared as a string, not as a parsed URL: the value becomes the
	// web_app button's URL, and output.Sender accepts exactly this value.
	t.AppURL = getenv("PA_APP_URL")
	if t.AppURL != base+PAAppPath {
		return fmt.Errorf("PA tools: PA_APP_URL must be PUBLIC_BASE_URL + %s", PAAppPath)
	}
	return nil
}

func loadPAServer(name connection.Server, getenv func(string) string, base string) (PAServer, error) {
	s := PAServer{Name: name, Enabled: true, RedirectURI: base + PAOAuthCallbackPrefix + string(name)}
	var err error
	if s.ClientID = strings.TrimSpace(getenv(PAServerEnv(name, "CLIENT_ID"))); s.ClientID == "" || len(s.ClientID) > 256 {
		return PAServer{}, fmt.Errorf("PA tools: %s is required (at most 256 bytes) when %s=true", PAServerEnv(name, "CLIENT_ID"), PAServerEnv(name, "ENABLED"))
	}
	hosts, err := paHosts(getenv, PAServerEnv(name, "ALLOWED_HOSTS"))
	if err != nil {
		return PAServer{}, err
	}
	s.AllowedHosts = hosts
	urls := []struct {
		setting  string
		dst      *string
		optional bool
		// called: the service sends requests to it, so its host must be on
		// the egress allowlist. The authorization endpoint is opened by the
		// user's browser, never by the service.
		called bool
		// noQuery: the value must not carry a query (an issuer, RFC 8414 2).
		noQuery bool
	}{
		{"ISSUER", &s.Issuer, false, true, true},
		{"AUTHORIZATION_ENDPOINT", &s.AuthorizationEndpoint, false, false, false},
		{"TOKEN_ENDPOINT", &s.TokenEndpoint, false, true, false},
		{"REVOCATION_ENDPOINT", &s.RevocationEndpoint, true, true, false},
		{"MCP_URL", &s.MCPURL, false, true, false},
		{"RESOURCE", &s.Resource, false, false, false},
	}
	for _, u := range urls {
		env := PAServerEnv(name, u.setting)
		v := strings.TrimSpace(getenv(env))
		if v == "" {
			if u.optional {
				continue
			}
			return PAServer{}, fmt.Errorf("PA tools: %s is required when %s=true", env, PAServerEnv(name, "ENABLED"))
		}
		host, err := paHTTPSURL(v, u.noQuery)
		if err != nil {
			return PAServer{}, fmt.Errorf("PA tools: %s %w", env, err)
		}
		if u.called && !containsHost(hosts, host) {
			return PAServer{}, fmt.Errorf("PA tools: the host of %s must be on %s", env, PAServerEnv(name, "ALLOWED_HOSTS"))
		}
		*u.dst = v
	}
	if s.PromptConsent, err = paBool(getenv, PAServerEnv(name, "PROMPT_CONSENT")); err != nil {
		return PAServer{}, err
	}
	return s, nil
}

// paHTTPSURL checks one endpoint URL and returns its lower-case host.
func paHTTPSURL(raw string, noQuery bool) (string, error) {
	u, err := url.Parse(raw)
	switch {
	case err != nil:
		return "", errors.New("must be a URL")
	case u.Scheme != "https" || u.Host == "" || u.Opaque != "":
		return "", errors.New("must be an https URL")
	case u.User != nil:
		return "", errors.New("must not carry userinfo")
	case u.Fragment != "" || strings.Contains(raw, "#"):
		return "", errors.New("must not carry a fragment")
	case noQuery && (u.RawQuery != "" || u.ForceQuery):
		return "", errors.New("must not carry a query")
	case u.Port() != "" && u.Port() != "443":
		return "", errors.New("must use port 443")
	}
	return strings.ToLower(u.Hostname()), nil
}

func paHosts(getenv func(string) string, env string) ([]string, error) {
	raw := strings.TrimSpace(getenv(env))
	if raw == "" {
		return nil, fmt.Errorf("PA tools: %s is required when the server is enabled", env)
	}
	var out []string
	for _, h := range strings.Split(raw, ",") {
		h = strings.ToLower(strings.TrimSpace(h))
		if !paHostFormat.MatchString(h) || len(h) > 253 {
			return nil, fmt.Errorf("PA tools: %s must be a comma-separated list of bare host names", env)
		}
		if !containsHost(out, h) {
			out = append(out, h)
		}
	}
	return out, nil
}

func containsHost(hosts []string, h string) bool {
	for _, x := range hosts {
		if x == h {
			return true
		}
	}
	return false
}

// paBool reads one switch as linking.ServerFlag does: missing or empty is
// false, "true" and "false" are themselves, anything else is an error.
func paBool(getenv func(string) string, env string) (bool, error) {
	switch strings.TrimSpace(getenv(env)) {
	case "", "false":
		return false, nil
	case "true":
		return true, nil
	default:
		return false, fmt.Errorf("PA tools: %s must be true or false", env)
	}
}
