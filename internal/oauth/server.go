// Package oauth implements an RFC 6749/RFC 8414/RFC 7591 authorization server
// scoped to a single resource (the mctl-telegram MCP endpoint). It replaces
// the cross-service shared-hmac coupling with api.mctl.ai — mctl-telegram is
// now its own issuer.
//
// Identity provider is Telegram's OpenID Connect provider: /oauth/authorize
// redirects the browser to oauth.telegram.org with an Authorization Code +
// PKCE request, and /oauth/telegram/callback exchanges the returned code for a
// JWKS-validated id_token via internal/auth/telegramoidc. The service is thus
// an OIDC federation broker — an OAuth 2.1 Authorization Server to its own
// MCP clients, and an OIDC Relying Party to Telegram.
//
// Tokens are minted by internal/auth/localjwt. PKCE-S256 is mandatory — the
// only supported response_type is "code". Clients are public (no
// client_secret); dynamic registration per RFC 7591 returns an ephemeral
// client_id keyed to a redirect_uri.
//
// Storage is in-memory (codes, registrations, pending OIDC flows). Each
// store has a TTL; a background goroutine sweeps expired entries. For a
// single-replica deployment (current mctl-telegram in `labs`) this is fine;
// horizontal scale-out would need to externalise the code store to Redis or
// Postgres — out of scope for the first cut.
package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/auth/localjwt"
	"github.com/mctlhq/mctl-telegram/internal/auth/telegramoidc"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/telegram"
)

// Server wires the OAuth endpoints. Construct with New, mount handlers with
// Register.
type Server struct {
	cfg    Config
	issuer *localjwt.Issuer
	tgoidc telegramoidc.Authenticator
	store  *db.Store
	clock  func() time.Time

	mu      sync.Mutex
	pending map[string]*pendingAuth   // keyed by "state" issued at /oauth/authorize
	codes   map[string]*authCode      // keyed by the authorization_code value
	clients map[string]*clientReg     // keyed by client_id
	enables map[string]*enableSession // keyed by the "es" token of an enable_access flow

	// loginFn performs the Telegram MTProto phone -> code -> 2FA login. It is
	// a field (not a direct telegram.Login call) so tests can substitute a
	// stub without dialing real Telegram. New sets it to telegram.Login.
	loginFn LoginFunc

	// loginMu serialises enable_access login goroutines per users.id (key
	// int64 -> *sync.Mutex). Two flows for the same uid must not interleave,
	// or a cancelled-but-still-running predecessor could revoke the session a
	// newer flow just provisioned. Entries are created on demand and never
	// removed — one mutex per onboarded user is negligible.
	loginMu sync.Map
}

// LoginFunc matches the signature of telegram.Login. The enable_access flow
// drives it from a background goroutine with channel-backed askCode/askPassword
// callbacks.
type LoginFunc func(
	ctx context.Context,
	apiID int,
	apiHash string,
	store *db.Store,
	userID int64,
	phone string,
	askCode func(context.Context) (string, error),
	askPassword func(context.Context) (string, error),
) (telegramUserID int64, displayName, username string, err error)

// Config captures everything the OAuth server needs at construction time.
type Config struct {
	// Issuer is the canonical PublicBaseURL of mctl-telegram, e.g.
	// "https://tg.mctl.ai". Used for iss claims and metadata.
	Issuer string
	// JWTSecret signs+verifies access tokens. Same value as the localjwt
	// Provider on the /mcp path.
	JWTSecret []byte
	// Telegram OpenID Connect (Relying Party) configuration. New uses these to
	// build the Authenticator unless TelegramOIDC is injected directly.
	//
	// TelegramOIDCClientID is the OIDC client id — the login bot's numeric id
	// (the part of the bot token before the colon). Not secret.
	TelegramOIDCClientID string
	// TelegramOIDCClientSecret is the OIDC client secret from BotFather; a
	// credential distinct from the bot API token. Sourced from Vault.
	TelegramOIDCClientSecret string
	// TelegramOIDCIssuerURL overrides the OIDC issuer. Empty ⇒ the
	// telegramoidc default (https://oauth.telegram.org).
	TelegramOIDCIssuerURL string
	// TelegramOIDCRedirectURL is the absolute URL of this server's Telegram
	// callback. Empty ⇒ derived as Issuer + "/oauth/telegram/callback". It
	// must match a Redirect URI registered for the bot in BotFather exactly.
	TelegramOIDCRedirectURL string
	// TelegramOIDCSigningAlgs restricts accepted id_token signing algorithms.
	// Empty ⇒ telegramoidc default (RS256).
	TelegramOIDCSigningAlgs []string
	// TelegramOIDC is an injected Authenticator. When non-nil New uses it and
	// skips OIDC discovery — the seam tests use to avoid a network call.
	TelegramOIDC telegramoidc.Authenticator
	// AdminTelegramIDs is the allowlist of Telegram user ids that get
	// admin/platform-admins scopes — the full telegram:* set plus admin:users.
	AdminTelegramIDs map[int64]bool
	// ClientTelegramIDs is the allowlist of Telegram user ids that get the
	// telegram:* scopes for their OWN account (read/send/pin) but NOT the
	// admin:users platform-admin capability. An id in neither allowlist still
	// authenticates but receives an empty scope set (403 on every MCP tool).
	ClientTelegramIDs map[int64]bool
	// AutoApproveClients opens registration: when true, any Telegram-authenticated
	// user whose users.access_tier is unset resolves to the client tier without
	// an operator action. An explicit DB tier of "none" still bans them.
	AutoApproveClients bool
	// AccessTokenTTL is how long the issued access tokens live. Default 1h.
	AccessTokenTTL time.Duration
	// CodeTTL bounds how long an authorization code is valid after issuance.
	// Default 10 minutes (RFC 6749 §4.1.2 recommends "as short as possible").
	CodeTTL time.Duration
	// RefreshTokenTTL is the absolute lifetime of an issued refresh token.
	// Default 720h (30 days). Refresh tokens are long-lived on purpose — they
	// are opaque, stored hashed, and rotated on every use, so a client can
	// renew a short-lived access token across pod restarts without re-running
	// the Telegram OIDC sign-in flow.
	RefreshTokenTTL time.Duration
	// AllowImplicitClient allows /oauth/authorize without prior /oauth/register.
	// Set to true to make Claude.ai onboarding trivial; the redirect_uri is
	// still validated against AllowedImplicitHosts before being accepted.
	AllowImplicitClient bool
	// AllowedImplicitHosts is the hostname allowlist applied to redirect_uri
	// when AllowImplicitClient is true and the client_id has not been
	// registered. Empty list ⇒ a built-in default (claude.ai, claude.com,
	// localhost, 127.0.0.1) is used. The check is exact-match on the
	// URL's Host (including any port); never substring-match.
	//
	// AllowedImplicitHosts is also applied to redirect_uris supplied at
	// RFC 7591 dynamic registration, so a malicious /oauth/register call
	// cannot smuggle in a phishing destination by bypassing the implicit
	// check via prior registration.
	AllowedImplicitHosts []string
	// ClientRegistrationTTL bounds how long a dynamically-registered client
	// is kept in memory before the sweeper evicts it. Defaults to 24h.
	// Set to a negative duration to disable eviction (not recommended in
	// production — /oauth/register is unauthenticated).
	ClientRegistrationTTL time.Duration
	// MaxRegisteredClients caps how many dynamic client registrations are
	// kept simultaneously. When exceeded, the oldest entry is evicted on
	// the next /oauth/register call. Defaults to 1000.
	MaxRegisteredClients int
	// MaxPendingAuth caps the size of the in-memory pending-authorize state
	// map. /oauth/authorize is unauthenticated, so without this bound an
	// attacker could push valid-looking requests and grow process memory
	// until OOM. When exceeded, the oldest entry is evicted on the next
	// /oauth/authorize call. Defaults to 5000.
	MaxPendingAuth int
	// MaxAuthCodes caps the size of the issued-authorization-code map.
	// Each successful Telegram callback inserts an entry; without a bound
	// an attacker who replays valid callbacks can mint codes without ever
	// redeeming them and grow process memory. Defaults to 10000.
	MaxAuthCodes int
	// MaxRegisterBodyBytes caps how many bytes /oauth/register will read
	// from r.Body before bailing out. Default 64 KiB — generous for the
	// RFC 7591 metadata fields we accept, tiny next to anything an
	// attacker could send to OOM the JSON decoder.
	MaxRegisterBodyBytes int64
	// MaxRedirectURIs caps how many entries the registration endpoint
	// accepts under redirect_uris. Default 16.
	MaxRedirectURIs int
	// MaxRedirectURILength caps each individual redirect URI string.
	// Default 2048.
	MaxRedirectURILength int
	// JWTAudience overrides the aud claim emitted into newly minted access
	// tokens. When empty (default), the access token has no aud — keeping
	// token-side audience policy aligned with the localjwt verifier's
	// transitional defaults. When set, every minted token carries this
	// aud value, which lets operators run OAUTH_JWT_AUDIENCE_REQUIRED=true
	// without breaking the in-band token flow.
	JWTAudience string
	// TGAPIID / TGAPIHash are the Telegram MTProto application credentials
	// (my.telegram.org). The in-browser enable_access flow needs them to run
	// the phone -> code -> 2FA login. When unset, enable_access reports a
	// configuration error instead of dialing Telegram; the rest of the OAuth
	// flow still works for users who already have a session.
	TGAPIID   int
	TGAPIHash string
	// MaxPendingEnable caps the in-memory enable_access session map. Each
	// admin who lands on the enable_access flow without a session inserts an
	// entry; oldest-evict on insert keeps the public surface bounded.
	// Defaults to 256.
	MaxPendingEnable int
}

// pendingAuth is the state captured between /oauth/authorize and the Telegram
// OIDC callback. Survives 10 minutes by default.
//
// Two PKCE pairs are in play and must never be confused:
//   - CodeChallenge is the MCP *client's* PKCE challenge, verified later in
//     handleToken against the client-supplied code_verifier.
//   - TGCodeVerifier is the *Telegram-leg* PKCE verifier this server generated
//     for its own RP request to oauth.telegram.org; it is replayed to
//     telegramoidc.Exchange and never leaves the server.
type pendingAuth struct {
	ClientID            string
	RedirectURI         string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	Scope               string
	Nonce               string
	TGCodeVerifier      string
	CreatedAt           time.Time
}

// authCode is the redeemable authorization_code returned via the redirect.
type authCode struct {
	ClientID            string
	RedirectURI         string
	CodeChallenge       string
	CodeChallengeMethod string
	TelegramID          int64
	TelegramUsername    string
	Scope               string
	CreatedAt           time.Time
}

// clientReg is the persisted shape of a RFC 7591 dynamic client registration.
type clientReg struct {
	ClientID     string
	ClientName   string
	RedirectURIs []string
	CreatedAt    time.Time
}

// New constructs a Server. The caller is responsible for wiring the handlers
// onto a chi router via Register.
//
// Unless cfg.TelegramOIDC is injected, New performs OIDC discovery against
// Telegram — a network call. It must therefore be invoked at startup and is
// fail-closed: a discovery failure returns an error rather than booting a
// server that cannot authenticate anyone.
func New(ctx context.Context, cfg Config, store *db.Store) (*Server, error) {
	if cfg.Issuer == "" {
		return nil, errors.New("oauth: issuer required")
	}
	if len(cfg.JWTSecret) == 0 {
		return nil, errors.New("oauth: JWTSecret required")
	}
	if cfg.AccessTokenTTL <= 0 {
		cfg.AccessTokenTTL = 1 * time.Hour
	}
	if cfg.CodeTTL <= 0 {
		cfg.CodeTTL = 10 * time.Minute
	}
	if cfg.RefreshTokenTTL <= 0 {
		cfg.RefreshTokenTTL = 720 * time.Hour
	}
	if cfg.AdminTelegramIDs == nil {
		cfg.AdminTelegramIDs = map[int64]bool{}
	}
	if cfg.ClientTelegramIDs == nil {
		cfg.ClientTelegramIDs = map[int64]bool{}
	}
	if len(cfg.AllowedImplicitHosts) == 0 {
		cfg.AllowedImplicitHosts = []string{
			"claude.ai",
			"claude.com",
			"localhost",
			"127.0.0.1",
		}
	}
	if cfg.ClientRegistrationTTL == 0 {
		cfg.ClientRegistrationTTL = 24 * time.Hour
	}
	if cfg.MaxRegisteredClients == 0 {
		cfg.MaxRegisteredClients = 1000
	}
	if cfg.MaxPendingAuth == 0 {
		cfg.MaxPendingAuth = 5000
	}
	if cfg.MaxAuthCodes == 0 {
		cfg.MaxAuthCodes = 10000
	}
	if cfg.MaxRegisterBodyBytes == 0 {
		cfg.MaxRegisterBodyBytes = 64 * 1024
	}
	if cfg.MaxRedirectURIs == 0 {
		cfg.MaxRedirectURIs = 16
	}
	if cfg.MaxRedirectURILength == 0 {
		cfg.MaxRedirectURILength = 2048
	}
	if cfg.MaxPendingEnable == 0 {
		cfg.MaxPendingEnable = 256
	}
	issuer, err := localjwt.NewIssuer(cfg.JWTSecret, cfg.Issuer)
	if err != nil {
		return nil, err
	}
	// Identity provider: Telegram's OIDC. A test injects cfg.TelegramOIDC to
	// skip the network discovery New would otherwise perform at boot.
	auth := cfg.TelegramOIDC
	if auth == nil {
		if cfg.TelegramOIDCClientID == "" {
			return nil, errors.New("oauth: TelegramOIDCClientID required")
		}
		if cfg.TelegramOIDCClientSecret == "" {
			return nil, errors.New("oauth: TelegramOIDCClientSecret required")
		}
		redirectURL := cfg.TelegramOIDCRedirectURL
		if redirectURL == "" {
			redirectURL = cfg.Issuer + "/oauth/telegram/callback"
		}
		auth, err = telegramoidc.New(ctx, telegramoidc.Config{
			IssuerURL:    cfg.TelegramOIDCIssuerURL,
			ClientID:     cfg.TelegramOIDCClientID,
			ClientSecret: cfg.TelegramOIDCClientSecret,
			RedirectURL:  redirectURL,
			SigningAlgs:  cfg.TelegramOIDCSigningAlgs,
		})
		if err != nil {
			return nil, err
		}
	}
	return &Server{
		cfg:     cfg,
		issuer:  issuer,
		tgoidc:  auth,
		store:   store,
		clock:   time.Now,
		pending: map[string]*pendingAuth{},
		codes:   map[string]*authCode{},
		clients: map[string]*clientReg{},
		enables: map[string]*enableSession{},
		loginFn: telegram.Login,
	}, nil
}

// StartSweeper runs a background loop that drops expired in-memory state.
// Caller controls the lifetime via the context.
func (s *Server) StartSweeper(stop <-chan struct{}, interval time.Duration) {
	if interval <= 0 {
		interval = 1 * time.Minute
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case now := <-t.C:
				s.sweep(now)
			}
		}
	}()
}

func (s *Server) sweep(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, p := range s.pending {
		if now.Sub(p.CreatedAt) > s.cfg.CodeTTL {
			delete(s.pending, k)
		}
	}
	for k, c := range s.codes {
		if now.Sub(c.CreatedAt) > s.cfg.CodeTTL {
			delete(s.codes, k)
		}
	}
	// Dynamic client registrations are kept for ClientRegistrationTTL.
	// Without this sweep the map grows unbounded because /oauth/register is
	// unauthenticated — a trivial public-API DoS vector.
	if s.cfg.ClientRegistrationTTL > 0 {
		for k, c := range s.clients {
			if now.Sub(c.CreatedAt) > s.cfg.ClientRegistrationTTL {
				delete(s.clients, k)
			}
		}
	}
	// Abandoned enable_access flows. Drop the entry only once the goroutine
	// could be cancelled; if a handler is mid-step (holds e.lock) keep the
	// entry so the user's in-flight flow is not silently invalidated — the
	// next sweep tick retries after the handler releases the lock.
	for k, e := range s.enables {
		if now.Sub(e.createdAt) > s.cfg.CodeTTL {
			if cancelEnableFlow(e) {
				delete(s.enables, k)
			}
		}
	}
}

// cancelEnableFlow best-effort cancels the background login goroutine of an
// enable_access session that is being dropped (swept or evicted). It runs
// under s.mu; the TryLock keeps it free of a lock-ordering hazard against the
// handler path (a handler holds e.lock, then may take s.mu).
//
// Returns true when it acquired e.lock (cancel applied, nothing left to do)
// and false when a handler currently holds e.lock. A false result means the
// caller must NOT drop the entry yet — a handler is mid-step and dropping it
// would silently invalidate the user's in-flight flow.
func cancelEnableFlow(e *enableSession) bool {
	if e.lock.TryLock() {
		if e.flow != nil && e.flow.cancel != nil {
			e.flow.cancel()
		}
		e.lock.Unlock()
		return true
	}
	return false
}

// ResolveScopes maps a Telegram identity to a scope set. Three tiers:
//   - admins (TG_LOGIN_ADMINS env) → platform-admins: full telegram:* plus
//     admin:users.
//   - clients → clients: telegram:* for the user's own account (read/send/
//     pin), without admin:users. The client allowlist is the union of the
//     TG_LOGIN_CLIENTS env (bootstrap) and the runtime-managed
//     users.access_tier='client' column (set via the admin MCP tools).
//   - anyone else → no scopes; authenticates but fails the per-tool gate.
//
// telegram:messages:send is granted to clients too, but a real send stays
// gated by the per-account send_enabled flag — the scope alone does not let a
// client send. A DB error resolving the client tier is returned so the caller
// fails the token issuance rather than silently under-granting.
func (s *Server) ResolveScopes(ctx context.Context, tgID int64) (groups, scopes []string, err error) {
	if s.cfg.AdminTelegramIDs[tgID] {
		return []string{"platform-admins", "admins"}, []string{
			"telegram:dialogs:read",
			"telegram:messages:read",
			"telegram:messages:send",
			"telegram:messages:pin",
			"admin:users",
		}, nil
	}
	isClient, err := s.isClientTier(ctx, tgID)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve client tier: %w", err)
	}
	if isClient {
		return []string{"clients"}, []string{
			"telegram:dialogs:read",
			"telegram:messages:read",
			"telegram:messages:send",
			"telegram:messages:pin",
		}, nil
	}
	return nil, nil, nil
}

// isClientTier reports whether tgID is in the client tier. The DB
// users.access_tier column is authoritative when set explicitly; when it is
// unset (NULL / no row) the TG_LOGIN_CLIENTS env allowlist is the bootstrap
// fallback. This ordering lets set_telegram_access(tier="none") revoke even an
// env-listed client. Both ResolveScopes and the handleTelegramCallback
// enable_access gate use it, so the two stay consistent.
func (s *Server) isClientTier(ctx context.Context, tgID int64) (bool, error) {
	tier, err := s.store.GetAccessTier(ctx, tgID)
	if err != nil {
		return false, err
	}
	switch tier {
	case db.TierClient:
		return true, nil
	case db.TierNone:
		return false, nil
	default: // unset
		// Open registration: an un-tiered user is a client by default.
		// An explicit DB "none" (above) still bans them.
		if s.cfg.AutoApproveClients {
			return true, nil
		}
		// Otherwise fall back to the env bootstrap allowlist.
		return s.cfg.ClientTelegramIDs[tgID], nil
	}
}

// Register mounts the OAuth handlers onto the supplied router. Each route is
// idempotent — Register may be called once at server boot.
func (s *Server) Register(mux Router) {
	mux.Get("/.well-known/oauth-authorization-server", s.handleAuthorizationServerMetadata)
	mux.Get("/oauth/authorize", s.handleAuthorize)
	// /oauth/telegram/callback is GET: Telegram's OIDC provider 302-redirects
	// the browser here with ?code=&state=. The unguessable server-side `state`
	// bound to a pending entry, plus the Telegram-leg PKCE verifier replayed at
	// the token exchange, are what tie the callback to a real authorize request.
	mux.Get("/oauth/telegram/callback", s.handleTelegramCallback)
	mux.Post("/oauth/token", s.handleToken)
	mux.Post("/oauth/register", s.handleClientRegistration)
	// In-browser "enable message access" flow. Public (no auth gate): the
	// caller's identity is carried by the unguessable "es" token minted at
	// the Telegram callback, which also serves as the CSRF token.
	mux.Post("/oauth/telegram/enable_access/start", s.handleEnableStart)
	mux.Post("/oauth/telegram/enable_access/code", s.handleEnableCode)
	mux.Post("/oauth/telegram/enable_access/password", s.handleEnablePassword)
}

// Router is the minimum chi.Router surface we depend on. Lets us write
// handler tests without pulling chi into the test deps.
type Router interface {
	Get(pattern string, h http.HandlerFunc)
	Post(pattern string, h http.HandlerFunc)
}

// ----- /.well-known/oauth-authorization-server -----

func (s *Server) handleAuthorizationServerMetadata(w http.ResponseWriter, _ *http.Request) {
	body := map[string]any{
		"issuer":                                s.cfg.Issuer,
		"authorization_endpoint":                s.cfg.Issuer + "/oauth/authorize",
		"token_endpoint":                        s.cfg.Issuer + "/oauth/token",
		"registration_endpoint":                 s.cfg.Issuer + "/oauth/register",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none"},
		"scopes_supported": []string{
			"telegram:dialogs:read",
			"telegram:messages:read",
			"telegram:messages:send",
			"telegram:messages:pin",
			"admin:users",
		},
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_ = json.NewEncoder(w).Encode(body)
}

// ----- /oauth/authorize -----

// handleAuthorize validates the client params, persists pending state, and
// 302-redirects the browser to Telegram's OIDC authorization endpoint. The
// authorization code is delivered back to the MCP client only later, by
// handleTelegramCallback, once Telegram has authenticated the user.
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	state := q.Get("state")
	codeChallenge := q.Get("code_challenge")
	codeChallengeMethod := q.Get("code_challenge_method")
	responseType := q.Get("response_type")
	scope := q.Get("scope")

	if responseType != "code" {
		s.writeAuthorizeError(w, "unsupported_response_type", "only response_type=code is supported")
		return
	}
	if clientID == "" || redirectURI == "" {
		s.writeAuthorizeError(w, "invalid_request", "client_id and redirect_uri are required")
		return
	}
	if codeChallenge == "" || codeChallengeMethod != "S256" {
		s.writeAuthorizeError(w, "invalid_request", "PKCE S256 is required (code_challenge + code_challenge_method=S256)")
		return
	}
	if err := validPKCEString(codeChallenge); err != nil {
		s.writeAuthorizeError(w, "invalid_request", "code_challenge "+err.Error())
		return
	}
	// Bound client-controlled strings. /oauth/authorize is unauthenticated and
	// stores each request in the in-memory pending map; without length limits an
	// attacker can fill entries with near-header-limit strings and drive the
	// process to OOM before TTL eviction fires.
	if len(clientID) > 256 {
		s.writeAuthorizeError(w, "invalid_request", "client_id exceeds 256 bytes")
		return
	}
	if len(redirectURI) > 2048 {
		s.writeAuthorizeError(w, "invalid_request", "redirect_uri exceeds 2048 bytes")
		return
	}
	if len(state) > 512 {
		s.writeAuthorizeError(w, "invalid_request", "state exceeds 512 bytes")
		return
	}
	if len(scope) > 1024 {
		s.writeAuthorizeError(w, "invalid_request", "scope exceeds 1024 bytes")
		return
	}
	if err := s.validateClient(clientID, redirectURI); err != nil {
		s.writeAuthorizeError(w, "invalid_client", err.Error())
		return
	}

	// Persist pending state, indexed by a fresh random server-side state token.
	// We DO NOT trust the client-supplied state — that survives only as a
	// pass-through value the OIDC callback echoes back on redirect.
	//
	// nonce binds the id_token Telegram returns to this request; tgVerifier is
	// the Telegram-leg PKCE verifier (its challenge goes to Telegram, the
	// verifier is replayed at the token exchange). Both are kept server-side.
	serverState := randomToken(32)
	nonce := randomToken(16)
	tgVerifier, tgChallenge := pkceChallenge()
	now := s.clock()
	s.mu.Lock()
	// Bound the pending map. /oauth/authorize is unauthenticated; without a
	// cap an attacker could push enough authorize requests to OOM the
	// process before any individual entry hits its TTL. The eviction is a
	// linear scan but only fires when we are at the limit, and we are
	// already under the mutex.
	if s.cfg.MaxPendingAuth > 0 && len(s.pending) >= s.cfg.MaxPendingAuth {
		var oldestKey string
		var oldestAt time.Time
		for k, p := range s.pending {
			if oldestKey == "" || p.CreatedAt.Before(oldestAt) {
				oldestKey = k
				oldestAt = p.CreatedAt
			}
		}
		if oldestKey != "" {
			delete(s.pending, oldestKey)
		}
	}
	s.pending[serverState] = &pendingAuth{
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		State:               state,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		Scope:               scope,
		Nonce:               nonce,
		TGCodeVerifier:      tgVerifier,
		CreatedAt:           now,
	}
	s.mu.Unlock()

	// Hand the browser to Telegram's OIDC authorization endpoint. Telegram
	// renders its own account-selection and consent screen, then 302s back to
	// /oauth/telegram/callback with ?code=&state=serverState. tgChallenge is
	// the Telegram-leg PKCE challenge — independent of the MCP client's
	// codeChallenge held in pending and verified later at /oauth/token.
	http.Redirect(w, r, s.tgoidc.AuthCodeURL(serverState, nonce, tgChallenge), http.StatusFound)
}

func (s *Server) writeAuthorizeError(w http.ResponseWriter, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": desc,
	})
}

// ----- /oauth/telegram/callback -----

// handleTelegramCallback receives Telegram's OIDC redirect: ?code=&state= on
// success, or ?error=&state= when the user cancelled or Telegram refused. It
// consumes the pending entry, exchanges the code for a JWKS-verified id_token,
// resolves the Telegram identity, issues an authorization_code, and redirects
// the browser to the MCP client's redirect_uri.
func (s *Server) handleTelegramCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	serverState := q.Get("state")
	if serverState == "" {
		http.Error(w, "missing state", http.StatusBadRequest)
		return
	}
	// Consume the pending entry up front — state is single-use whatever the
	// outcome, so an error redirect cannot be replayed against a fresh code.
	s.mu.Lock()
	pending, ok := s.pending[serverState]
	delete(s.pending, serverState)
	s.mu.Unlock()
	if !ok {
		http.Error(w, "unknown or expired state", http.StatusBadRequest)
		return
	}
	// Defensive TTL check: the background sweeper drops stale entries on a
	// timer, but a callback arriving in the gap between expiry and the next
	// sweep tick would still be served if we only relied on map presence.
	// CodeTTL bounds how long we trust serverState; reject if exceeded.
	if s.clock().Sub(pending.CreatedAt) > s.cfg.CodeTTL {
		http.Error(w, "state expired", http.StatusBadRequest)
		return
	}

	// The user cancelled at oauth.telegram.org, or Telegram refused the
	// request. The pending entry is already consumed above; show a friendly
	// page rather than a 500 or a blank screen.
	if oidcErr := q.Get("error"); oidcErr != "" {
		renderEnableError(w, "Telegram sign-in was not completed ("+sanitizeOIDCError(oidcErr)+"). Close this page and try connecting again from your MCP client.")
		return
	}
	code := q.Get("code")
	if code == "" {
		renderEnableError(w, "Telegram sign-in did not return an authorization code. Close this page and try again.")
		return
	}

	// Server-to-server token exchange + id_token verification. The Telegram-leg
	// PKCE verifier and the nonce are replayed from the pending entry; neither
	// was ever exposed to the browser.
	identity, err := s.tgoidc.Exchange(r.Context(), code, pending.TGCodeVerifier, pending.Nonce)
	if err != nil {
		// The raw error may embed Telegram's token-endpoint response body
		// (oauth2.RetrieveError), which can carry a Telegram user id — log it
		// server-side, return an opaque message to the browser.
		slog.Error("telegram OIDC token exchange failed", "err", err)
		http.Error(w, "telegram authentication failed", http.StatusUnauthorized)
		return
	}
	if identity.TelegramID <= 0 {
		// The primary migration path keys on the numeric `id` claim (#48). An
		// id_token carrying only an opaque `sub` is the documented contingency
		// and is not handled here — fail loudly rather than mint a token for an
		// unresolved identity.
		http.Error(w, "telegram id_token carried no usable Telegram user id", http.StatusUnauthorized)
		return
	}

	// Bind the Telegram identity to an internal users row. EnsureUserByTelegramID
	// is keyed by telegram_login_id, so the MTProto session the enable_access
	// flow provisions below lands on the SAME users.id this token resolves to
	// on later /mcp calls — closing the duplicate-identity gap the old CLI
	// (github_login-keyed) login left open.
	uid, err := s.store.EnsureUserByTelegramID(r.Context(), identity.TelegramID, identity.Username, strings.TrimSpace(identity.FirstName+" "+identity.LastName))
	if err != nil {
		slog.Error("ensure user failed", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	oc := oauthCtx{
		ClientID:      pending.ClientID,
		RedirectURI:   pending.RedirectURI,
		CodeChallenge: pending.CodeChallenge,
		ClientState:   pending.State,
		Scope:         pending.Scope,
		TelegramID:    identity.TelegramID,
		Username:      identity.Username,
	}

	// If the user already has a usable MTProto session, hand back the
	// authorization code immediately. Otherwise walk admins and clients
	// through the in-browser enable_access flow to provision one. A user who
	// will receive no scopes gets the code regardless: an MTProto session
	// would be unusable for them — no point collecting their phone number.
	_, sessErr := s.store.CheckSessionValid(r.Context(), uid)
	switch {
	case sessErr == nil:
		// A valid session exists — issue the code directly.
		s.issueAuthCode(w, r, oc)
		return
	case errors.Is(sessErr, db.ErrNoActiveSession), errors.Is(sessErr, db.ErrSessionExpired):
		// Expected: no usable session. Fall through to the enable_access
		// decision below.
	default:
		// An unexpected storage error must not be silently treated as
		// "no session" — that would divert the user into re-login (and a
		// possible session overwrite) on a transient DB blip.
		slog.Error("session check failed", "err", sessErr)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// enable_access provisions an MTProto session, which is only useful to a
	// user who will actually receive scopes. Offer it to admins and clients;
	// anyone who will get no scopes just receives the (scopeless) code. The
	// client check must mirror ResolveScopes (env ∪ DB) — otherwise a
	// DB-granted client would be 302'd past enable_access, get a scoped token,
	// and then fail every tool call for lack of a session.
	isClient, err := s.isClientTier(r.Context(), identity.TelegramID)
	if err != nil {
		slog.Error("resolve client tier failed", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !s.cfg.AdminTelegramIDs[identity.TelegramID] && !isClient {
		s.issueAuthCode(w, r, oc)
		return
	}

	es := &enableSession{
		oc:        oc,
		uid:       uid,
		tgID:      identity.TelegramID,
		createdAt: s.clock(),
		step:      stepPhone,
	}
	esTok := randomToken(32)
	s.mu.Lock()
	if s.cfg.MaxPendingEnable > 0 && len(s.enables) >= s.cfg.MaxPendingEnable {
		var oldestKey string
		var oldestAt time.Time
		for k, e := range s.enables {
			if oldestKey == "" || e.createdAt.Before(oldestAt) {
				oldestKey = k
				oldestAt = e.createdAt
			}
		}
		if oldestKey != "" {
			// Eviction must enforce the map cap, so the entry is dropped
			// regardless of whether the goroutine could be cancelled now; a
			// best-effort cancel still fires and, failing that, the
			// goroutine's CodeTTL-bounded context terminates it.
			if old := s.enables[oldestKey]; old != nil {
				_ = cancelEnableFlow(old)
			}
			delete(s.enables, oldestKey)
		}
	}
	s.enables[esTok] = es
	s.mu.Unlock()
	renderEnablePhone(w, enablePhonePage{Issuer: s.cfg.Issuer, EnableToken: esTok})
}

// oauthCtx bundles the per-flow OAuth parameters needed to mint and deliver an
// authorization code, independent of how the user's identity was established
// (direct Telegram callback when a session exists, or after the enable_access
// detour when one had to be provisioned).
type oauthCtx struct {
	ClientID      string
	RedirectURI   string
	CodeChallenge string
	ClientState   string
	Scope         string
	TelegramID    int64
	Username      string
}

// issueAuthCode mints an authorization_code for oc and 302-redirects the
// browser to the client's redirect_uri with ?code=&state=. Shared by the
// has-session Telegram-callback path and the enable_access success path. State
// is echoed verbatim per RFC 6749 §4.1.2.
func (s *Server) issueAuthCode(w http.ResponseWriter, r *http.Request, oc oauthCtx) {
	code := randomToken(32)
	now := s.clock()
	s.mu.Lock()
	// Cap the authorization-code map. Oldest-evict on insert mirrors the
	// pending/clients pattern and keeps the sweeper as a backstop.
	if s.cfg.MaxAuthCodes > 0 && len(s.codes) >= s.cfg.MaxAuthCodes {
		var oldestKey string
		var oldestAt time.Time
		for k, c := range s.codes {
			if oldestKey == "" || c.CreatedAt.Before(oldestAt) {
				oldestKey = k
				oldestAt = c.CreatedAt
			}
		}
		if oldestKey != "" {
			delete(s.codes, oldestKey)
		}
	}
	s.codes[code] = &authCode{
		ClientID:            oc.ClientID,
		RedirectURI:         oc.RedirectURI,
		CodeChallenge:       oc.CodeChallenge,
		CodeChallengeMethod: "S256",
		TelegramID:          oc.TelegramID,
		TelegramUsername:    oc.Username,
		Scope:               oc.Scope,
		CreatedAt:           now,
	}
	s.mu.Unlock()

	u, err := url.Parse(oc.RedirectURI)
	if err != nil {
		http.Error(w, "invalid redirect_uri", http.StatusInternalServerError)
		return
	}
	q := u.Query()
	q.Set("code", code)
	if oc.ClientState != "" {
		q.Set("state", oc.ClientState)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// ----- /oauth/token -----

// handleToken dispatches the RFC 6749 token endpoint by grant_type. Two grants
// are supported: authorization_code (the PKCE exchange after the Telegram
// OIDC sign-in flow) and refresh_token (silent renewal of a short-lived access
// token, with no Telegram interaction).
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeTokenError(w, "invalid_request", "could not parse form", http.StatusBadRequest)
		return
	}
	switch r.FormValue("grant_type") {
	case "authorization_code":
		s.handleTokenAuthCode(w, r)
	case "refresh_token":
		s.handleTokenRefresh(w, r)
	default:
		writeTokenError(w, "unsupported_grant_type",
			"only authorization_code and refresh_token are supported", http.StatusBadRequest)
	}
}

// handleTokenAuthCode implements grant_type=authorization_code: it redeems a
// one-time PKCE-bound code for an access token plus a fresh refresh token.
func (s *Server) handleTokenAuthCode(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	clientID := r.FormValue("client_id")
	redirectURI := r.FormValue("redirect_uri")
	codeVerifier := r.FormValue("code_verifier")

	if code == "" || clientID == "" || codeVerifier == "" {
		writeTokenError(w, "invalid_request", "code, client_id, code_verifier are required", http.StatusBadRequest)
		return
	}
	if err := validPKCEString(codeVerifier); err != nil {
		writeTokenError(w, "invalid_request", "code_verifier "+err.Error(), http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	entry, ok := s.codes[code]
	if ok {
		delete(s.codes, code)
	}
	s.mu.Unlock()
	if !ok {
		writeTokenError(w, "invalid_grant", "code not found, expired, or already used", http.StatusBadRequest)
		return
	}
	if s.clock().Sub(entry.CreatedAt) > s.cfg.CodeTTL {
		writeTokenError(w, "invalid_grant", "code expired", http.StatusBadRequest)
		return
	}
	if entry.ClientID != clientID {
		writeTokenError(w, "invalid_grant", "client_id mismatch", http.StatusBadRequest)
		return
	}
	if entry.RedirectURI != redirectURI {
		writeTokenError(w, "invalid_grant", "redirect_uri mismatch", http.StatusBadRequest)
		return
	}
	if !pkceVerify(codeVerifier, entry.CodeChallenge) {
		writeTokenError(w, "invalid_grant", "code_verifier does not match code_challenge", http.StatusBadRequest)
		return
	}

	groups, scopes, err := s.ResolveScopes(r.Context(), entry.TelegramID)
	if err != nil {
		writeTokenError(w, "server_error", "could not resolve scopes", http.StatusInternalServerError)
		return
	}
	tok, err := s.mintAccessToken(entry.TelegramID, entry.TelegramUsername, groups, scopes)
	if err != nil {
		writeTokenError(w, "server_error", "could not mint token", http.StatusInternalServerError)
		return
	}
	// Bind the refresh token to the internal users.id so a later refresh —
	// and operator-facing tooling — resolves the same identity the access
	// token authenticates as. EnsureUserByTelegramID is idempotent; the empty
	// displayName is safe because its metadata refresh is NULLIF-guarded and
	// will not clobber a name the Telegram callback already stored.
	uid, err := s.store.EnsureUserByTelegramID(r.Context(), entry.TelegramID, entry.TelegramUsername, "")
	if err != nil {
		writeTokenError(w, "server_error", "could not resolve user", http.StatusInternalServerError)
		return
	}
	refreshTok, err := s.issueRefreshToken(r.Context(), db.RefreshToken{
		FamilyID:         randomToken(16),
		UserID:           uid,
		ClientID:         clientID,
		TelegramID:       entry.TelegramID,
		TelegramUsername: entry.TelegramUsername,
		Scope:            strings.Join(scopes, " "),
	})
	if err != nil {
		writeTokenError(w, "server_error", "could not issue refresh token", http.StatusInternalServerError)
		return
	}
	writeTokenJSON(w, tok, refreshTok, int(s.cfg.AccessTokenTTL.Seconds()), scopes)
}

// handleTokenRefresh implements grant_type=refresh_token: it renews a
// (typically expired) access token from a stored, rotating refresh token with
// no Telegram interaction. This is what stops MCP clients losing access
// once an access token's short TTL elapses. The presented refresh token is
// rotated — the old one revoked, a new one returned. Presenting an
// already-rotated token is treated as reuse and revokes the whole family.
func (s *Server) handleTokenRefresh(w http.ResponseWriter, r *http.Request) {
	refreshTok := r.FormValue("refresh_token")
	clientID := r.FormValue("client_id")
	if refreshTok == "" || clientID == "" {
		writeTokenError(w, "invalid_request", "refresh_token and client_id are required", http.StatusBadRequest)
		return
	}
	rt, err := s.store.LookupRefreshToken(r.Context(), refreshTok)
	if errors.Is(err, db.ErrRefreshTokenNotFound) {
		writeTokenError(w, "invalid_grant", "refresh token not found, expired, or already used", http.StatusBadRequest)
		return
	}
	if err != nil {
		writeTokenError(w, "server_error", "could not look up refresh token", http.StatusInternalServerError)
		return
	}
	// Reuse detection: an already-rotated (revoked) token is presented again.
	// Either an honest client double-submitted or a stolen token is in play —
	// kill the family and force a fresh login. If the revoke itself fails we
	// must NOT fall through to a plain invalid_grant: that would leave the
	// family's still-live token usable after a detected theft. Fail closed
	// with a 500 so the incident surfaces and the caller retries.
	if rt.Revoked() {
		if _, revErr := s.store.RevokeRefreshTokenFamily(r.Context(), rt.FamilyID); revErr != nil {
			slog.Error("refresh token family revoke failed — reuse detection not enforced",
				"err", revErr, "family_id", rt.FamilyID)
			writeTokenError(w, "server_error", "could not complete reuse detection", http.StatusInternalServerError)
			return
		}
		writeTokenError(w, "invalid_grant", "refresh token already used", http.StatusBadRequest)
		return
	}
	if rt.Expired(s.clock()) {
		writeTokenError(w, "invalid_grant", "refresh token expired", http.StatusBadRequest)
		return
	}
	if rt.ClientID != clientID {
		writeTokenError(w, "invalid_grant", "client_id mismatch", http.StatusBadRequest)
		return
	}
	// Re-resolve scopes from the current identity state: a user demoted since
	// the token was issued must lose scopes on refresh, not keep them for the
	// refresh token's full lifetime.
	groups, scopes, err := s.ResolveScopes(r.Context(), rt.TelegramID)
	if err != nil {
		writeTokenError(w, "server_error", "could not resolve scopes", http.StatusInternalServerError)
		return
	}
	tok, err := s.mintAccessToken(rt.TelegramID, rt.TelegramUsername, groups, scopes)
	if err != nil {
		writeTokenError(w, "server_error", "could not mint token", http.StatusInternalServerError)
		return
	}
	newRefresh := randomToken(32)
	if err := s.store.RotateRefreshToken(r.Context(), refreshTok, newRefresh, db.RefreshToken{
		FamilyID:         rt.FamilyID,
		UserID:           rt.UserID,
		ClientID:         rt.ClientID,
		TelegramID:       rt.TelegramID,
		TelegramUsername: rt.TelegramUsername,
		Scope:            strings.Join(scopes, " "),
		// Carry the original expiry forward — RefreshTokenTTL is an *absolute*
		// lifetime, not a sliding window. Re-stamping now+TTL on every
		// rotation would let a client that refreshes hourly hold a token that
		// never expires; instead the whole family dies TTL after first issue.
		ExpiresAt: rt.ExpiresAt,
	}); err != nil {
		if errors.Is(err, db.ErrRefreshTokenNotFound) {
			// The token was revoked between LookupRefreshToken and the
			// rotation — a concurrent request rotated the same token first.
			// That is a same-token double-use, indistinguishable from a theft
			// race, so treat it like any other reuse and kill the family.
			// Without this, the request that won the race would keep a live
			// rotated token while the family stays intact. The cost is that a
			// (rare) honest concurrent double-submit forces one re-login —
			// well-behaved OAuth clients serialise refresh, so this path is
			// effectively attacker-only in practice.
			//
			// Unlike the explicit-reuse path above, a revoke failure here is
			// logged but not turned into a 500: the loser's token is already
			// definitively gone (the winner revoked it), so invalid_grant is
			// the correct client-facing answer regardless, and the family will
			// still be caught if the now-revoked token is replayed.
			if _, revErr := s.store.RevokeRefreshTokenFamily(r.Context(), rt.FamilyID); revErr != nil {
				slog.Error("refresh token family revoke failed after rotation race",
					"err", revErr, "family_id", rt.FamilyID)
			}
			writeTokenError(w, "invalid_grant", "refresh token already used", http.StatusBadRequest)
			return
		}
		writeTokenError(w, "server_error", "could not rotate refresh token", http.StatusInternalServerError)
		return
	}
	writeTokenJSON(w, tok, newRefresh, int(s.cfg.AccessTokenTTL.Seconds()), scopes)
}

// mintAccessToken signs a localjwt access token for the given Telegram
// identity and resolved scope set.
//
// aud policy: when the deployment configures OAUTH_JWT_AUDIENCE, every minted
// token MUST carry exactly that value so the localjwt verifier on /mcp accepts
// it. When unconfigured, no aud is emitted (the verifier tolerates absent aud
// per RFC 7519). Binding aud to client_id like an earlier default would have
// failed /mcp authentication whenever an operator set OAUTH_JWT_AUDIENCE — a
// misconfiguration trap codex flagged.
func (s *Server) mintAccessToken(tgID int64, tgUsername string, groups, scopes []string) (string, error) {
	var audience []string
	if s.cfg.JWTAudience != "" {
		audience = []string{s.cfg.JWTAudience}
	}
	return s.issuer.Mint(localjwt.Claims{
		Subject:          fmt.Sprintf("tg:%d", tgID),
		TelegramID:       tgID,
		TelegramUsername: tgUsername,
		Groups:           groups,
		Scopes:           scopes,
		Audience:         audience,
	}, s.cfg.AccessTokenTTL)
}

// issueRefreshToken generates an opaque refresh token, persists it (hashed),
// and returns the plaintext for the token response. ExpiresAt is stamped here
// from RefreshTokenTTL so callers supply only identity fields.
func (s *Server) issueRefreshToken(ctx context.Context, rt db.RefreshToken) (string, error) {
	plaintext := randomToken(32)
	rt.ExpiresAt = s.clock().Add(s.cfg.RefreshTokenTTL)
	if err := s.store.SaveRefreshToken(ctx, plaintext, rt); err != nil {
		return "", err
	}
	return plaintext, nil
}

// writeTokenJSON writes a successful RFC 6749 §5.1 token response.
//
// scope is always echoed (the *granted* set, which may be empty) so a client
// never believes it holds privileges it cannot exercise — a non-admin who
// asked for "telegram:messages:send" still sees the empty granted set.
// refresh_token is omitted only when empty.
func writeTokenJSON(w http.ResponseWriter, accessToken, refreshToken string, expiresIn int, scopes []string) {
	resp := map[string]any{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   expiresIn,
		"scope":        strings.Join(scopes, " "),
	}
	if refreshToken != "" {
		resp["refresh_token"] = refreshToken
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	_ = json.NewEncoder(w).Encode(resp)
}

func writeTokenError(w http.ResponseWriter, code, desc string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": desc,
	})
}

// ----- /oauth/register (RFC 7591) -----

func (s *Server) handleClientRegistration(w http.ResponseWriter, r *http.Request) {
	// /oauth/register is unauthenticated. Wrap the body with MaxBytesReader
	// before json.Decode so a 1-MB attack payload cannot force the JSON
	// decoder to allocate proportional memory. The cap is generous for
	// RFC 7591 metadata fields but a non-starter for OOM probes.
	if s.cfg.MaxRegisterBodyBytes > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxRegisterBodyBytes)
	}
	var req struct {
		ClientName   string   `json:"client_name"`
		RedirectURIs []string `json:"redirect_uris"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeTokenError(w, "invalid_client_metadata", "could not decode request", http.StatusBadRequest)
		return
	}
	if len(req.RedirectURIs) == 0 {
		writeTokenError(w, "invalid_client_metadata", "redirect_uris is required", http.StatusBadRequest)
		return
	}
	if s.cfg.MaxRedirectURIs > 0 && len(req.RedirectURIs) > s.cfg.MaxRedirectURIs {
		writeTokenError(w, "invalid_client_metadata", fmt.Sprintf("too many redirect_uris (max %d)", s.cfg.MaxRedirectURIs), http.StatusBadRequest)
		return
	}
	for _, raw := range req.RedirectURIs {
		if s.cfg.MaxRedirectURILength > 0 && len(raw) > s.cfg.MaxRedirectURILength {
			writeTokenError(w, "invalid_redirect_uri", fmt.Sprintf("redirect_uri exceeds %d bytes", s.cfg.MaxRedirectURILength), http.StatusBadRequest)
			return
		}
	}
	// Apply the SAME scheme + host policy as implicit clients. Without
	// this, a malicious /oauth/register call could supply an http://
	// attacker-controlled redirect_uri, and a later /oauth/authorize
	// call against that client_id would skip the implicit-host check
	// because validateClient trusts registered redirect_uris on
	// exact-match. Result: authorization codes redirected to an
	// attacker URL.
	for _, raw := range req.RedirectURIs {
		if err := s.validateImplicitRedirectURI(raw); err != nil {
			writeTokenError(w, "invalid_redirect_uri", err.Error(), http.StatusBadRequest)
			return
		}
	}
	clientID := "tgmcp_" + randomToken(16)
	now := s.clock()
	s.mu.Lock()
	// Enforce the global cap. If we are at the limit, evict the oldest
	// entry (linear scan — fine at N≈1000). This keeps the public
	// endpoint bounded even before the periodic sweeper runs.
	if s.cfg.MaxRegisteredClients > 0 && len(s.clients) >= s.cfg.MaxRegisteredClients {
		var oldestKey string
		var oldestAt time.Time
		for k, c := range s.clients {
			if oldestKey == "" || c.CreatedAt.Before(oldestAt) {
				oldestKey = k
				oldestAt = c.CreatedAt
			}
		}
		if oldestKey != "" {
			delete(s.clients, oldestKey)
		}
	}
	s.clients[clientID] = &clientReg{
		ClientID:     clientID,
		ClientName:   req.ClientName,
		RedirectURIs: req.RedirectURIs,
		CreatedAt:    now,
	}
	s.mu.Unlock()
	resp := map[string]any{
		"client_id":                  clientID,
		"client_name":                req.ClientName,
		"redirect_uris":              req.RedirectURIs,
		"token_endpoint_auth_method": "none",
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

// validateImplicitRedirectURI applies the same policy as the implicit-client
// branch of validateClient. Factored out so /oauth/register can enforce it
// at registration time instead of waiting until /oauth/authorize.
//
// Loopback exception per RFC 8252 §7.3: native clients must be able to use
// any free port on a loopback interface. We accept the three loopback host
// forms — "localhost", IPv4 "127.0.0.1", and IPv6 "::1" — under http (no
// TLS required) so a native client on an IPv6-only host is not locked out.
func (s *Server) validateImplicitRedirectURI(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("redirect_uri %q is not a valid URL: %w", raw, err)
	}
	if u.Scheme != "https" {
		if u.Scheme != "http" || !isLoopbackHost(u.Hostname()) {
			return fmt.Errorf("redirect_uri scheme %q is not allowed (must be https except for http loopback)", u.Scheme)
		}
	}
	host := u.Hostname()
	hostWithPort := u.Host
	for _, allowed := range s.cfg.AllowedImplicitHosts {
		// If the allowlist entry specifies a port, require an exact host:port
		// match so that port-level separation is respected. Without a port in the
		// entry, any port on the named host is permitted.
		if strings.Contains(allowed, ":") {
			if hostWithPort == allowed {
				return nil
			}
		} else {
			if host == allowed {
				return nil
			}
		}
	}
	// Loopback addresses are accepted even when not explicitly listed in
	// AllowedImplicitHosts — the implicit deny on a non-loopback host
	// remains, but loopback is universally safe for native clients.
	if isLoopbackHost(host) {
		return nil
	}
	return fmt.Errorf("redirect_uri host %q is not in the allowlist", host)
}

// isLoopbackHost is true for the three RFC 8252 §7.3 loopback host forms.
// url.Hostname() strips the brackets around IPv6 literals so we compare
// against the bare "::1" string, not "[::1]".
func isLoopbackHost(h string) bool {
	switch h {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}

// ----- helpers -----

// validateClient confirms client_id was registered with redirect_uri (or, if
// AllowImplicitClient is true and the client_id was never registered, that
// redirect_uri's host appears in AllowedImplicitHosts).
//
// Implicit-client acceptance lets Claude.ai connectors work without an extra
// setup step. The host allowlist prevents the OAuth flow from being abused as
// an open redirector: even though the eventual /oauth/token call binds the
// code to the redirect_uri (so an attacker without the code_verifier cannot
// exchange a hijacked code), shipping a URL fragment to an attacker-controlled
// host would still leak the authorization_code briefly. Constraining the host
// closes that window.
func (s *Server) validateClient(clientID, redirectURI string) error {
	s.mu.Lock()
	reg, ok := s.clients[clientID]
	s.mu.Unlock()
	if ok {
		for _, u := range reg.RedirectURIs {
			if u == redirectURI {
				return nil
			}
		}
		return fmt.Errorf("redirect_uri %q is not registered for client_id %q", redirectURI, clientID)
	}
	if !s.cfg.AllowImplicitClient {
		return fmt.Errorf("unknown client_id %q (call /oauth/register first)", clientID)
	}
	u, err := url.Parse(redirectURI)
	if err != nil {
		return fmt.Errorf("redirect_uri is not a valid URL: %w", err)
	}
	// http:// is acceptable only for loopback addresses (RFC 8252 §7.3 —
	// including IPv6 ::1 for native clients on IPv6-only hosts).
	if u.Scheme != "https" {
		if u.Scheme != "http" || !isLoopbackHost(u.Hostname()) {
			return fmt.Errorf("redirect_uri scheme %q is not allowed (must be https except for http loopback)", u.Scheme)
		}
	}
	host := u.Hostname()
	hostWithPort := u.Host
	for _, allowed := range s.cfg.AllowedImplicitHosts {
		if strings.Contains(allowed, ":") {
			if hostWithPort == allowed {
				return nil
			}
		} else {
			if host == allowed {
				return nil
			}
		}
	}
	if isLoopbackHost(host) {
		return nil
	}
	return fmt.Errorf("redirect_uri host %q is not in the implicit-client allowlist", host)
}

// pkceVerify checks that SHA256(verifier) base64url-encoded equals challenge.
// Per RFC 7636 §4.6. Uses subtle.ConstantTimeCompare so a timing oracle does
// not leak how many leading bytes of the challenge match.
func pkceVerify(verifier, challenge string) bool {
	if verifier == "" || challenge == "" {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}

// PKCE length bounds per RFC 7636 §4.1 (code_verifier) and §4.2 (code_challenge):
// both values are derived from a 43–128 character alphabet of unreserved
// ASCII. Accepting shorter values would weaken the brute-force-resistance
// PKCE is meant to provide on the redirect_uri interception path.
const (
	pkceMinLen = 43
	pkceMaxLen = 128
)

// validPKCEString returns nil when s satisfies RFC 7636's syntax for both the
// code_challenge and the code_verifier: 43–128 characters drawn from
// [A-Z][a-z][0-9]-._~. Any character outside that set or any length outside
// the range is rejected.
func validPKCEString(s string) error {
	n := len(s)
	if n < pkceMinLen || n > pkceMaxLen {
		return fmt.Errorf("must be %d–%d characters (got %d)", pkceMinLen, pkceMaxLen, n)
	}
	for i := 0; i < n; i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z',
			c >= 'a' && c <= 'z',
			c >= '0' && c <= '9',
			c == '-' || c == '.' || c == '_' || c == '~':
			// allowed unreserved
		default:
			return fmt.Errorf("contains disallowed character %q at index %d (only [A-Za-z0-9-._~] permitted)", c, i)
		}
	}
	return nil
}

// randomToken returns a base64url-encoded random string of approximately the
// requested byte length. Used for state tokens, codes, and client_ids.
func randomToken(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic("oauth: rand.Read failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

// pkceChallenge generates the Telegram-leg PKCE pair: a random code_verifier —
// 32 random bytes base64url-encoded is 43 characters, satisfying RFC 7636's
// 43–128 unreserved-character syntax — and its S256 code_challenge. The
// verifier is stored in pendingAuth.TGCodeVerifier and replayed at the
// Telegram token exchange; the challenge is sent to Telegram up front.
func pkceChallenge() (verifier, challenge string) {
	verifier = randomToken(32)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

// sanitizeOIDCError reduces a Telegram-supplied `error` query parameter to a
// short, safe token before it is shown on an error page. Standard OIDC error
// codes are lowercase snake_case; anything else — or an over-long value —
// collapses to "unknown" so a crafted callback URL cannot inject markup.
func sanitizeOIDCError(code string) string {
	if code == "" || len(code) > 64 {
		return "unknown"
	}
	for i := 0; i < len(code); i++ {
		c := code[i]
		if !((c >= 'a' && c <= 'z') || c == '_') {
			return "unknown"
		}
	}
	return code
}
