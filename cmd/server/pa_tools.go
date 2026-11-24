package main

// pa_tools.go builds the Personal Assistant's tools runtime (#1318 slice
// C2): the KEK and the connection manager, the account-linking flow and its
// bot commands, the MCP endpoints, the pin and the audited executor that the
// connector dispatcher runs on, and the tool resolver that binds a run to
// the principal's active connections at claim. Nothing here is built
// unless PA_ENABLED is on and at least one PA_SERVER_<NAME>_ENABLED is true
// (config.LoadPATools): with every server off the PA runs exactly as before
// C2, without tools.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/config"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/oauth"
	"github.com/mctlhq/mctl-telegram/internal/pa"
	"github.com/mctlhq/mctl-telegram/internal/pa/catalog"
	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
	"github.com/mctlhq/mctl-telegram/internal/pa/connector"
	"github.com/mctlhq/mctl-telegram/internal/pa/egress"
	"github.com/mctlhq/mctl-telegram/internal/pa/jobs"
	"github.com/mctlhq/mctl-telegram/internal/pa/linking"
)

// paMetadataTimeout bounds the startup fetch of every enabled server's
// authorization server metadata.
const paMetadataTimeout = 15 * time.Second

// paServerNet is one enabled server's network clients, every one on an
// internal/pa/egress client allowed only the server's pinned hosts.
type paServerNet struct {
	// Metadata fetches the RFC 8414 metadata at startup.
	Metadata *http.Client
	Revoker  connection.Revoker
	Tokens   linking.TokenClient
	// Refresh is the server's refresh-token grant (#1318 slice C2b).
	Refresh  connection.RefreshFunc
	Endpoint connector.MCPEndpoint
}

// newPAServerNet builds one enabled server's clients. A variable only so
// the wiring tests can point them at httptest fakes (egress refuses
// loopback); nothing else assigns it.
var newPAServerNet = func(s config.PAServer) (paServerNet, error) {
	md, err := egress.New(egress.Config{Purpose: egress.PurposeDiscovery, AllowedHosts: s.AllowedHosts})
	if err != nil {
		return paServerNet{}, fmt.Errorf("pa tools: metadata egress for %s: %w", s.Name, err)
	}
	oc, err := linking.NewOAuthClient(map[connection.Server]linking.OAuthServer{s.Name: {
		ClientID: s.ClientID, TokenEndpoint: s.TokenEndpoint, RevocationEndpoint: s.RevocationEndpoint,
		Resource: s.Resource, AllowedHosts: s.AllowedHosts,
	}}, nil)
	if err != nil {
		return paServerNet{}, err
	}
	ep, err := connector.NewEndpoint(string(s.Name), s.MCPURL)
	if err != nil {
		return paServerNet{}, err
	}
	return paServerNet{Metadata: md, Revoker: oc, Tokens: oc.TokenClient(), Refresh: oc.Refresh, Endpoint: ep}, nil
}

// paRevokers dispatches a revocation to its server's client. A server
// without one (disabled now, connected earlier) is an error, never a
// success: Disconnect reports it as the remote failure.
type paRevokers map[connection.Server]connection.Revoker

func (r paRevokers) Revoke(ctx context.Context, server connection.Server, token connection.Secret, hint connection.TokenHint) error {
	rv, ok := r[server]
	if !ok || rv == nil {
		return fmt.Errorf("pa tools: no revocation client for %s", server)
	}
	return rv.Revoke(ctx, server, token, hint)
}

// paRefreshers dispatches a refresh-token grant to its server's client. A
// server without one is an error, which fails the call that needed the
// refresh and changes nothing (connection.ErrRefreshFailed).
type paRefreshers map[connection.Server]connection.RefreshFunc

func (r paRefreshers) Refresh(ctx context.Context, server connection.Server, refreshToken connection.Secret) ([]byte, error) {
	fn, ok := r[server]
	if !ok || fn == nil {
		return nil, fmt.Errorf("pa tools: no refresh client for %s", server)
	}
	return fn(ctx, server, refreshToken)
}

// paTokenClients dispatches a code exchange to its server's client.
type paTokenClients map[connection.Server]linking.TokenClient

func (t paTokenClients) ExchangeCode(ctx context.Context, server connection.Server, req linking.ExchangeRequest) ([]byte, error) {
	tc, ok := t[server]
	if !ok || tc == nil {
		return nil, fmt.Errorf("pa tools: no token client for %s", server)
	}
	return tc.ExchangeCode(ctx, server, req)
}

// paTools is the built tools runtime.
type paTools struct {
	// servers are the enabled servers, sorted.
	servers   []connection.Server
	manager   *connection.Manager
	links     *linking.Service
	commands  *linking.Commands
	endpoints map[string]connector.MCPEndpoint
	pin       *catalog.Pin
	executor  *connector.Executor
	flags     func() (connector.Flags, error)
	// writes is the write path, or nil (pa_writes.go). The resolver asks
	// it which write tools a connection may be offered.
	writes *paWrites
}

// buildPATools builds the tools runtime for tools, or nil when no server is
// enabled. Any error refuses startup. The metadata fetch runs under ctx,
// bounded by paMetadataTimeout.
func buildPATools(ctx context.Context, cfg *config.Config, tools *config.PATools, store *db.Store, sender paBotSender) (*paTools, error) {
	if !tools.AnyEnabled() {
		return nil, nil
	}
	// The scope tables decide what a connection asks for and which write
	// tool it may carry: a build whose tables do not hold together does
	// not start.
	if err := connection.CheckScopeConfig(); err != nil {
		return nil, fmt.Errorf("pa tools: %w", err)
	}
	kek, err := connection.NewKEK(tools.KEK)
	if err != nil {
		return nil, fmt.Errorf("pa tools: KEK: %w", err)
	}
	pin, err := catalog.LoadPin()
	if err != nil {
		return nil, fmt.Errorf("pa tools: pin: %w", err)
	}
	t := &paTools{pin: pin, endpoints: map[string]connector.MCPEndpoint{}, flags: connector.EnvFlags(os.Getenv)}
	revokers := paRevokers{}
	tokens := paTokenClients{}
	refreshers := paRefreshers{}
	identity := map[connection.Server]connector.MCPEndpoint{}
	servers := map[connection.Server]linking.ServerConfig{}
	ctx, cancel := context.WithTimeout(ctx, paMetadataTimeout)
	defer cancel()
	for name, s := range tools.Servers {
		if !s.Enabled {
			servers[name] = linking.ServerConfig{}
			continue
		}
		if _, ok := pin.Servers[string(name)]; !ok {
			return nil, fmt.Errorf("pa tools: %s is enabled but not in the pin", name)
		}
		n, err := newPAServerNet(s)
		if err != nil {
			return nil, err
		}
		md, err := paServerMetadata(ctx, n.Metadata, s, paSelfIssuer(cfg))
		if err != nil {
			return nil, err
		}
		revokers[name], tokens[name], identity[name] = n.Revoker, n.Tokens, n.Endpoint
		refreshers[name] = n.Refresh
		t.endpoints[string(name)] = n.Endpoint
		t.servers = append(t.servers, name)
		servers[name] = linking.ServerConfig{
			Enabled: true, Issuer: s.Issuer, Metadata: &md,
			AuthorizationEndpoint: s.AuthorizationEndpoint, TokenEndpoint: s.TokenEndpoint,
			ClientID: s.ClientID, RedirectURI: s.RedirectURI, Resource: s.Resource, PromptConsent: s.PromptConsent,
		}
	}
	slices.Sort(t.servers)
	sink := connector.StoreSink{Store: store}
	t.executor = &connector.Executor{Sink: sink}
	t.manager, err = connection.NewManager(connection.Config{
		Store: store, KEK: kek, Revoker: revokers, Auditor: connector.FenceAudit{Sink: sink},
		Refresh: refreshers.Refresh,
	})
	if err != nil {
		return nil, fmt.Errorf("pa tools: connection manager: %w", err)
	}
	t.links, err = linking.New(linking.Config{
		BotToken: cfg.PABotToken, LoginBotToken: cfg.TelegramLoginBotToken,
		BotUsername: tools.BotUsername, MiniAppName: tools.MiniAppName, AppURL: tools.AppURL,
		Servers: servers, Manager: t.manager, Store: store, Tokens: tokens,
		Accounts:  connector.IdentityAccounts{Endpoints: identity},
		Messenger: linking.BotMessenger{Sender: sender},
		// The same allowlist the webhook and the run loop check.
		Allowed: pa.NewAllowlist(cfg.PAAllowedPrincipals),
		// The same switch the dispatcher reads: while it is on, a new
		// link asks for the server's write scopes too. Only in a process
		// with a write path (t.writes, set once at startup, before any
		// request is served): one started with writes off cannot send a
		// write until it restarts, so it asks for the read scopes
		// whatever the flag reads later. Off is read at every use.
		Writes: func() (bool, error) {
			if t.writes == nil {
				return false, nil
			}
			return paWritesEnabled(t.flags)
		},
	})
	if err != nil {
		return nil, fmt.Errorf("pa tools: linking: %w", err)
	}
	t.commands = &linking.Commands{Links: t.links, Connections: t.manager, Sender: sender, Servers: t.servers}
	return t, nil
}

// paWritesSwitch is paWritesEnabled as the switch /consent and /connect
// read at every use: one reader of PA_WRITES_ENABLED for the startup
// decision and for them. A failed read is off, with the error.
func paWritesSwitch(flags func() (connector.Flags, error)) func() (bool, error) {
	return func() (bool, error) { return paWritesEnabled(flags) }
}

// paServerMetadata fetches s's authorization server metadata and checks it
// against the configuration: the issuer (FetchASMetadata), the
// authorization and token endpoints, and the revocation endpoint when one
// is configured. The metadata is the server's own statement of where its
// endpoints are; a configuration that disagrees with it, or metadata that
// cannot be read, refuses startup (#1338 item 2). Errors name the variable,
// never a value.
//
// When s's issuer is this process's own authorization server (self, see
// paSelfIssuer), the document is the one this process publishes
// (oauth.MetadataDocument), read in process rather than fetched: the fetch
// would go out to the public URL before this server listens, and with the
// Deployment's Recreate strategy nothing answers there at that moment, so
// every start would refuse itself (gitops#2961 crash-looped preview on
// "HTTP 503"). The document goes through the same parser and the same
// comparisons, so a configuration that disagrees with what this server
// publishes still refuses startup.
func paServerMetadata(ctx context.Context, client *http.Client, s config.PAServer, self string) (linking.ASMetadata, error) {
	var md linking.ASMetadata
	var err error
	if self != "" && s.Issuer == self {
		var body []byte
		if body, err = json.Marshal(oauth.MetadataDocument(self)); err == nil {
			md, err = linking.ParseASMetadata(body, s.Issuer)
		}
	} else {
		md, err = linking.FetchASMetadata(ctx, client, s.Issuer)
	}
	if err != nil {
		return linking.ASMetadata{}, fmt.Errorf("pa tools: %s metadata: %w", config.PAServerEnv(s.Name, "ISSUER"), err)
	}
	if md.AuthorizationEndpoint != s.AuthorizationEndpoint {
		return linking.ASMetadata{}, paMetadataMismatch(s.Name, "AUTHORIZATION_ENDPOINT")
	}
	if md.TokenEndpoint != s.TokenEndpoint {
		return linking.ASMetadata{}, paMetadataMismatch(s.Name, "TOKEN_ENDPOINT")
	}
	if s.RevocationEndpoint != "" && md.RevocationEndpoint != s.RevocationEndpoint {
		return linking.ASMetadata{}, paMetadataMismatch(s.Name, "REVOCATION_ENDPOINT")
	}
	return md, nil
}

// paSelfIssuer is the issuer of the authorization server this process
// serves, or "" when it serves none: main mounts the OAuth server, with
// PUBLIC_BASE_URL as its issuer, only in AUTH_MODE=local-jwt.
func paSelfIssuer(cfg *config.Config) string {
	if cfg == nil || !strings.EqualFold(cfg.AuthMode, "local-jwt") {
		return ""
	}
	return strings.TrimRight(cfg.PublicBaseURL, "/")
}

// errPAMetadataMismatch is a configured endpoint the server's metadata does
// not name.
var errPAMetadataMismatch = errors.New("pa tools: configured endpoint differs from the authorization server metadata")

func paMetadataMismatch(name connection.Server, setting string) error {
	return fmt.Errorf("%w: %s", errPAMetadataMismatch, config.PAServerEnv(name, setting))
}

// paConnectionLister is the store read the tool resolver makes in the claim
// transaction (*db.Store).
type paConnectionLister interface {
	ListPAConnectionsTx(ctx context.Context, tx *sql.Tx, principal int64) ([]connection.Connection, error)
}

// toolResolver binds a run, at claim, to the principal's active connections
// on servers that are enabled now, and exposes the pinned read tools of
// those servers as "server/tool". The switches are re-read on every claim:
// with PA_EXTERNAL_TOOLS_ENABLED off, or unreadable, the run gets no tool
// at all; a server whose flag is off or unreadable contributes nothing.
// A failed store read wraps jobs.ErrStoreFault (pa.ToolResolver): it is
// never an empty set.
//
// With a write path built (t.writes, pa_writes.go) a connection also
// contributes the approve-tier tools the action gate offers it
// (paWriteGate), while PA_WRITES_ENABLED reads true in the same read of
// the switches.
// Without one, or with that switch off or unreadable, the set is the
// pinned reads and nothing else.
func (t *paTools) toolResolver(store paConnectionLister) pa.ToolResolver {
	return func(ctx context.Context, tx *sql.Tx, principal int64) ([]pa.ConnectionRevision, []string, error) {
		f, err := t.flags()
		if err != nil || !f.ExternalTools {
			return nil, nil, nil
		}
		conns, err := store.ListPAConnectionsTx(ctx, tx, principal)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: pa connections: %v", jobs.ErrStoreFault, err)
		}
		var bound []pa.ConnectionRevision
		used := map[connection.Server]bool{}
		var tools []string
		var wrote bool
		var withheld string
		for _, c := range conns {
			if c.State != connection.StateActive || !slices.Contains(t.servers, c.Server) || !f.Servers[string(c.Server)] {
				continue
			}
			bound = append(bound, pa.ConnectionRevision{ConnectionID: c.ID, AuthorityRevision: c.AuthorityRevision})
			used[c.Server] = true
			// Write tools: none without a write path, none with
			// PA_WRITES_ENABLED off or unreadable in this same read of the
			// switches, and only those the action gate offers this
			// connection. A gate that could not be read fails the claim.
			wt, why, err := t.writes.offered(ctx, tx, f, principal, c)
			if err != nil {
				return nil, nil, fmt.Errorf("%w: pa action gate: %v", jobs.ErrStoreFault, err)
			}
			tools = append(tools, wt...)
			wrote = wrote || len(wt) > 0
			if withheld == "" {
				withheld = why
			}
		}
		if wrote {
			withheld = ""
		}
		t.writes.note(principal, withheld)
		for server := range used {
			for name, tool := range t.pin.Servers[string(server)].Tools {
				if tool.Class == catalog.ClassRead && tool.Tier == catalog.TierAuto {
					tools = append(tools, string(server)+"/"+name)
				}
			}
		}
		sort.Strings(tools)
		return bound, tools, nil
	}
}
