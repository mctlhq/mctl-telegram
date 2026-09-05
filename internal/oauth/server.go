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
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/auth/localjwt"
	"github.com/mctlhq/mctl-telegram/internal/auth/telegramoidc"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/telegram"
	"github.com/mctlhq/mctl-telegram/internal/workertoken"
)

// Server wires the OAuth endpoints. Construct with New, mount handlers with
// Register.
type Server struct {
	cfg    Config
	issuer *localjwt.Issuer
	tgoidc telegramoidc.Authenticator
	store  *db.Store
	clock  func() time.Time
	// useDB is true when a Postgres DATABASE_URL is active and the three new
	// OAuth tables have been migrated. When true, pending/codes/clients are
	// persisted to the DB instead of in-memory maps, enabling cross-replica
	// continuity. When false (SQLite or missing DB), the in-memory maps are
	// used unchanged.
	useDB   bool
	metrics metricsIface

	mu      sync.Mutex
	pending map[string]*pendingAuth   // keyed by "state" issued at /oauth/authorize
	codes   map[string]*authCode      // keyed by the authorization_code value
	clients map[string]*clientReg     // keyed by client_id
	enables map[string]*enableSession // keyed by the "es" token of an enable_access flow

	// Local Bridge self-service device activation (issue #482). Three indexes
	// over the same set of *localBridgeActivation values, mirroring the
	// enables/pending sibling-map shape rather than a fourth, unrelated
	// mechanism. See local_bridge_activate.go.
	activations           map[string]*localBridgeActivation // keyed by device_code
	activationsByState    map[string]*localBridgeActivation // keyed by the Telegram-leg OIDC state
	activationsByUserCode map[string]*localBridgeActivation // keyed by normalizeUserCode(user_code)
	// activationFails is the failed-submission rate limiter shared by the
	// user_code form and the consent endpoint, keyed by the client IP derived
	// via clientIP (trusted-proxy-aware). Read/written under mu, swept
	// alongside the activations. Issue-483 extends this same limiter/budget
	// to a failed PoP verification at the device credential/refresh
	// endpoints (local_bridge_credential.go), sharing one posture across
	// every unauthenticated-but-secret-bearing endpoint in this file.
	activationFails map[string]*activationFailWindow

	// deviceNonces is the in-memory, TTL-bounded, capacity-bounded PoP nonce
	// store for self-service Local Bridge device issuance/refresh
	// (issue-483), keyed by device_id -- one live (unconsumed) nonce per
	// device at a time; minting a new one for the same device_id supersedes
	// whatever was pending. See local_bridge_credential.go. Mirrors
	// s.activations's map/eviction-cap/sweep discipline rather than adding a
	// database table -- nonces live for seconds, so a lost nonce on pod
	// restart costs one retried call.
	deviceNonces map[string]*deviceNonce
	// deviceMinter issues self-service Local Bridge device credentials
	// (workertoken.MintForDevice), built once at New() from the same
	// signing secret/issuer/audience as every other token this service
	// mints. Never used for the admin worker-token mint path -- that stays
	// entirely inside internal/workertoken's own admin-gated handler.
	deviceMinter *workertoken.Minter

	// loginFn performs the Telegram MTProto phone -> code -> 2FA login. It is
	// a field (not a direct telegram.Login call) so tests can substitute a
	// stub without dialing real Telegram. New sets it to telegram.Login.
	loginFn LoginFunc

	// loginCfg is forwarded to loginFn on every enable_access login. It carries
	// the shared api_id-wide rate-limit middleware so the interactive login
	// client throttles against the same budget as the pool. Zero value = no
	// extra wiring. Set via WithLoginConfig.
	loginCfg telegram.LoginConfig

	// loginMu serialises enable_access login goroutines per users.id (key
	// int64 -> *sync.Mutex). Two flows for the same uid must not interleave,
	// or a cancelled-but-still-running predecessor could revoke the session a
	// newer flow just provisioned. Entries are created on demand and never
	// removed — one mutex per onboarded user is negligible.
	loginMu sync.Map

	// demoLimiter throttles /oauth/demo/login attempts per client IP so the
	// password-gated reviewer path cannot be brute-forced. Non-nil only when
	// the reviewer/demo auth-mode is enabled.
	demoLimiter *demoRateLimiter
}

// metricsIface is the minimum surface of metrics.Registry used by oauth.Server.
// Defined as an interface so the oauth package does not import the metrics
// package directly (avoiding a circular import if metrics ever needs oauth).
type metricsIface interface {
	SetOAuthPendingAuthSize(float64)
	// ObserveLoginPhoneStep records the duration and outcome of the enable_access
	// phone -> SendCode wait. result is "ok", "timeout", or "error".
	ObserveLoginPhoneStep(result string, seconds float64)
}

// WithMetrics wires a metrics registry so oauth.Server can update the
// mctl_oauth_pending_auth_size gauge from the sweeper goroutine.
// Returns the receiver for chaining.
func (s *Server) WithMetrics(m metricsIface) *Server {
	s.metrics = m
	return s
}

// WithLoginConfig sets the telegram.LoginConfig forwarded to every
// enable_access login (e.g. the shared api_id-wide rate-limit middleware).
// Returns the receiver for chaining.
func (s *Server) WithLoginConfig(cfg telegram.LoginConfig) *Server {
	s.loginCfg = cfg
	return s
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
	cfgs ...telegram.LoginConfig,
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
	// LookupAdminTelegramIDs is the allowlist of Telegram user ids that get
	// ONLY admin:users:read — the two read-only admin lookups
	// (list_telegram_identities, get_user_audit_log) and nothing else. It is
	// deliberately NOT the flat admin:users scope: that one is the only gate
	// on every admin WRITE tool (set_telegram_access, set_account_send,
	// set_account_mode, provision_local_account, revoke_telegram_session,
	// revoke_worker_token, mint_worker_token) and on the three admin mint
	// routes in internal/agentapi and internal/workertoken, so granting it
	// here would have made a "lookup-only" consumer a full platform admin
	// over other people's accounts. mint_worker_token was the sharpest case:
	// it mints for an ARBITRARY telegram_id and purpose "local-bridge" adds
	// send and pin, so the tier could have granted itself exactly the
	// capability it is described as not needing.
	//
	// This is the tier for a lookup-only consumer (e.g. an OpenClaw bot
	// answering "who is Telegram user X") that must never need a
	// real/working MTProto session of its own with read/send/pin capability.
	// Checked after AdminTelegramIDs and before the client tier, so
	// full-admin membership always takes precedence over a dual listing.
	LookupAdminTelegramIDs map[int64]bool
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
	// chatgpt.com, localhost, 127.0.0.1) is used. The check is exact-match
	// on the URL's Host (including any port); never substring-match.
	//
	// In the server binary this is populated from OAUTH_ALLOWED_IMPLICIT_HOSTS
	// (comma-separated), so onboarding a new MCP client is a deployment
	// change rather than a code change. Note that supplying the variable
	// replaces the default outright rather than extending it: a deployment
	// that adds a host must restate the ones it still wants.
	//
	// Loopback redirects are accepted regardless of this list (see
	// isLoopbackHost), so CLI clients binding an ephemeral port need no entry.
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
	// UseDBForOAuth routes pending-auth, auth-codes, and client-registrations
	// through the Postgres-backed store methods (InsertOAuthPending, etc.)
	// instead of the in-memory maps. Set to true when DATABASE_URL starts with
	// "postgres://" or "postgresql://". Has no effect when the store is nil.
	UseDBForOAuth bool

	// MaxPendingActivations caps the in-memory Local Bridge activation map.
	// /api/local-bridge/activate/start is unauthenticated, so without this
	// bound an attacker could grow process memory by calling it repeatedly.
	// Oldest-evict on insert, mirroring MaxPendingAuth/MaxPendingEnable.
	// Defaults to 5000.
	MaxPendingActivations int
	// MaxActivationsPerIP caps how many live activations a single
	// rate-limiter key (see TrustedProxyCIDRs) may hold at once. It is what
	// keeps MaxPendingActivations from becoming an eviction weapon: without
	// it, an unauthenticated flood from one address fills the map and pushes
	// other users' in-flight activations out mid-sign-in. Asking for one more
	// than this recycles the requester's own oldest activation. Defaults
	// to 16 -- far above any real CLI, which holds one at a time and retries.
	MaxActivationsPerIP int
	// MaxActivationFailKeys caps the failed-submission rate-limiter map.
	// Entries are created for whatever key clientIP derives, from an
	// unauthenticated path, so a spread-out source would otherwise grow it
	// unboundedly between sweeps. Defaults to MaxPendingActivations.
	MaxActivationFailKeys int
	// ActivationTTL bounds how long a Local Bridge activation (device_code,
	// user_code, and — once resolved — its outcome) stays reachable before
	// the sweeper drops it. Measured from the activation's createdAt, so a
	// resolved activation is swept on the same schedule as an abandoned one;
	// this must be long enough for the CLI's next poll to observe the
	// outcome. Defaults to 10 minutes, matching RFC 8628's expires_in
	// convention for a short-lived device code.
	ActivationTTL time.Duration
	// ActivationFailBudget is the number of failed user_code / consent
	// submissions a single rate-limiter key (see TrustedProxyCIDRs) may make
	// within ActivationFailWindow before further submissions are refused with
	// the same generic message as a wrong code, without a lookup. Defaults
	// to 10.
	ActivationFailBudget int
	// ActivationFailWindow is the sliding window ActivationFailBudget is
	// measured over. Defaults to 10 minutes.
	ActivationFailWindow time.Duration

	// DeviceNonceTTL bounds how long a self-service Local Bridge PoP nonce
	// (issue-483) stays valid after minting. Short and single-use by design
	// -- a device mints one, signs it immediately, and presents it once.
	// Defaults to 30 seconds.
	DeviceNonceTTL time.Duration
	// MaxPendingDeviceNonces caps the in-memory device-nonce map. The nonce
	// mint endpoint is unauthenticated (possession of an unguessable
	// device_id, not identity), so without a bound a flood of distinct
	// device_id values could grow process memory. Oldest-evict on insert
	// when full, mirroring MaxPendingActivations. Defaults to 5000.
	MaxPendingDeviceNonces int
	// TrustedProxyCIDRs is the trust boundary the Local Bridge activation
	// rate limiter's client-IP derivation depends on (see clientIP in
	// local_bridge_activate.go): a forwarding header (X-Forwarded-For) is
	// only consulted when the immediate transport peer (r.RemoteAddr) falls
	// inside one of these prefixes; otherwise the peer address itself is the
	// key and the header is ignored outright. Evaluating trust in that order
	// — peer first, header second — is the whole guarantee: checking the
	// header before the peer lets a directly-connected attacker choose their
	// own limiter key.
	//
	// Nil (the caller never set it) is defaulted in New from the
	// TRUSTED_PROXY_CIDRS env var: unset ⇒ the cluster's own ranges,
	// 10.42.0.0/16 (pods) and 10.43.0.0/16 (services); set but empty or
	// entirely unparseable ⇒ an empty, non-nil slice, meaning "trust
	// nothing" — the safe direction. A caller that explicitly wants to
	// trust nothing should pass a non-nil empty slice directly, which New
	// leaves untouched.
	TrustedProxyCIDRs []netip.Prefix

	// Reviewer/demo auth-mode for the ChatGPT App Directory review.
	//
	// When DemoReviewerEnabled is true, /oauth/authorize renders a chooser page
	// offering both the normal "Sign in with Telegram" path and a password-gated
	// "reviewer access" form. A correct DemoReviewerUsername/DemoReviewerPassword
	// posted to /oauth/demo/login authenticates as DemoReviewerTGID directly,
	// bypassing the live Telegram OIDC login (no phone/SMS). The demo account is
	// expected to be a throwaway with a pre-seeded MTProto session and
	// send_enabled=false, so every send stays a dry-run preview. Off by default.
	DemoReviewerEnabled  bool
	DemoReviewerUsername string
	DemoReviewerPassword string // compared in constant time, never logged
	DemoReviewerTGID     int64
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
	if cfg.LookupAdminTelegramIDs == nil {
		cfg.LookupAdminTelegramIDs = map[int64]bool{}
	}
	if len(cfg.AllowedImplicitHosts) == 0 {
		cfg.AllowedImplicitHosts = []string{
			"claude.ai",
			"claude.com",
			"chatgpt.com",
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
	if cfg.MaxPendingActivations == 0 {
		cfg.MaxPendingActivations = 5000
	}
	if cfg.MaxActivationsPerIP == 0 {
		cfg.MaxActivationsPerIP = 16
	}
	if cfg.MaxActivationFailKeys == 0 {
		cfg.MaxActivationFailKeys = cfg.MaxPendingActivations
	}
	if cfg.ActivationTTL <= 0 {
		cfg.ActivationTTL = 10 * time.Minute
	}
	if cfg.ActivationFailBudget == 0 {
		cfg.ActivationFailBudget = 10
	}
	if cfg.ActivationFailWindow <= 0 {
		cfg.ActivationFailWindow = 10 * time.Minute
	}
	if cfg.DeviceNonceTTL <= 0 {
		cfg.DeviceNonceTTL = 30 * time.Second
	}
	if cfg.MaxPendingDeviceNonces == 0 {
		cfg.MaxPendingDeviceNonces = 5000
	}
	if cfg.TrustedProxyCIDRs == nil {
		cfg.TrustedProxyCIDRs = trustedProxyCIDRsFromEnv()
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
	// deviceMinter shares this service's own signing secret/issuer/audience
	// with every other locally-issued token (mintAccessToken, the bridge
	// token handler, etc.) -- issue-483's device credentials are minted by
	// the same server that mints everything else, just through a narrower,
	// PoP-gated policy (workertoken.MintForDevice) instead of the admin-only
	// HTTP mint path. NewMinter's own validation (non-empty secret/issuer)
	// can only fail here if cfg.JWTSecret/cfg.Issuer were empty, both of
	// which are already rejected above.
	deviceMinter, err := workertoken.NewMinter(cfg.JWTSecret, cfg.Issuer, cfg.JWTAudience)
	if err != nil {
		return nil, fmt.Errorf("oauth: device credential minter: %w", err)
	}
	s := &Server{
		cfg:                   cfg,
		issuer:                issuer,
		tgoidc:                auth,
		store:                 store,
		clock:                 time.Now,
		useDB:                 cfg.UseDBForOAuth && store != nil,
		pending:               map[string]*pendingAuth{},
		codes:                 map[string]*authCode{},
		clients:               map[string]*clientReg{},
		enables:               map[string]*enableSession{},
		activations:           map[string]*localBridgeActivation{},
		activationsByState:    map[string]*localBridgeActivation{},
		activationsByUserCode: map[string]*localBridgeActivation{},
		activationFails:       map[string]*activationFailWindow{},
		deviceNonces:          map[string]*deviceNonce{},
		deviceMinter:          deviceMinter,
		loginFn:               telegram.Login,
	}
	if cfg.DemoReviewerEnabled {
		s.demoLimiter = newDemoRateLimiter(s.clock)
	}
	// Pre-register the built-in self-connect client. Zero CreatedAt ensures the
	// background sweeper never evicts it (the sweep condition
	// now.Sub(c.CreatedAt) > ClientRegistrationTTL is never true for zero time
	// with a positive TTL). No /oauth/register call is needed for this client.
	s.clients[ConnectClientID] = &clientReg{
		ClientID:     ConnectClientID,
		ClientName:   "mctl-telegram connect",
		RedirectURIs: []string{cfg.Issuer + "/telegram/connect/done"},
		CreatedAt:    time.Time{}, // zero — never swept
	}
	return s, nil
}

// defaultTrustedProxyCIDRs are the cluster's own pod and service ranges —
// where the ingress that terminates every inbound request actually sits.
var defaultTrustedProxyCIDRs = []netip.Prefix{
	netip.MustParsePrefix("10.42.0.0/16"),
	netip.MustParsePrefix("10.43.0.0/16"),
}

// trustedProxyCIDRsFromEnv parses TRUSTED_PROXY_CIDRS: a comma-separated
// list of CIDRs. Called from New only when the caller left
// Config.TrustedProxyCIDRs nil.
//
// The env var being genuinely UNSET (not present in the environment) is
// what selects the safe cluster-default. Once it is present at all, an
// empty value or one whose entries all fail to parse degrades to an empty,
// non-nil slice — "trust nothing" — rather than silently falling back to
// the permissive default: a typo in the deployment manifest must not
// re-admit the header-spoofing hole this trust boundary exists to close.
func trustedProxyCIDRsFromEnv() []netip.Prefix {
	raw, present := os.LookupEnv("TRUSTED_PROXY_CIDRS")
	if !present {
		out := make([]netip.Prefix, len(defaultTrustedProxyCIDRs))
		copy(out, defaultTrustedProxyCIDRs)
		return out
	}
	out := []netip.Prefix{}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		p, err := netip.ParsePrefix(part)
		if err != nil {
			slog.Warn("oauth: TRUSTED_PROXY_CIDRS entry could not be parsed; ignoring it", "entry", part, "err", err)
			continue
		}
		out = append(out, p)
	}
	return out
}

// ConnectClientID is the client_id for the built-in self-connect OAuth client.
// It is pre-registered in oauth.New and used by internal/web/connect.go.
const ConnectClientID = "mctl_self_connect"

// ExchangeConnect redeems a one-time PKCE-bound authorization code on behalf
// of the built-in mctl_self_connect client. It mirrors the PKCE verification
// and scope resolution in handleTokenAuthCode but is callable in-process from
// the /telegram/connect/done handler, avoiding a loopback HTTP round-trip.
//
// The returned access token is discarded by the caller; ExchangeConnect is
// called only to confirm that the code is valid and that the MTProto session
// was provisioned successfully. An error signals that the code was invalid,
// expired, or the PKCE verifier did not match.
func (s *Server) ExchangeConnect(ctx context.Context, code, verifier, clientID, redirectURI string) (string, error) {
	if code == "" || verifier == "" || clientID == "" || redirectURI == "" {
		return "", errors.New("invalid_request: code, verifier, client_id, redirect_uri are required")
	}
	if clientID != ConnectClientID {
		return "", fmt.Errorf("invalid_request: client_id must be %s", ConnectClientID)
	}
	if err := validPKCEString(verifier); err != nil {
		return "", fmt.Errorf("invalid_request: code_verifier %w", err)
	}

	var entry *authCode
	if s.useDB {
		dbCode, err := s.store.ConsumeOAuthCode(ctx, code, s.cfg.CodeTTL)
		if errors.Is(err, db.ErrOAuthNotFound) {
			return "", errors.New("invalid_grant: code not found, expired, or already used")
		}
		if err != nil {
			return "", fmt.Errorf("server_error: could not redeem code: %w", err)
		}
		entry = &authCode{
			ClientID:            dbCode.ClientID,
			RedirectURI:         dbCode.RedirectURI,
			CodeChallenge:       dbCode.CodeChallenge,
			CodeChallengeMethod: dbCode.ChallengeMethod,
			TelegramID:          dbCode.TelegramID,
			TelegramUsername:    dbCode.TelegramUsername,
			Scope:               dbCode.Scope,
			CreatedAt:           dbCode.CreatedAt,
		}
	} else {
		s.mu.Lock()
		var ok bool
		entry, ok = s.codes[code]
		if ok {
			if s.clock().Sub(entry.CreatedAt) > s.cfg.CodeTTL {
				delete(s.codes, code)
				ok = false
			} else {
				delete(s.codes, code)
			}
		}
		s.mu.Unlock()
		if !ok {
			return "", errors.New("invalid_grant: code not found, expired, or already used")
		}
	}
	if entry.ClientID != clientID {
		return "", errors.New("invalid_grant: client_id mismatch")
	}
	if entry.RedirectURI != redirectURI {
		return "", errors.New("invalid_grant: redirect_uri mismatch")
	}
	if !pkceVerify(verifier, entry.CodeChallenge) {
		return "", errors.New("invalid_grant: code_verifier does not match code_challenge")
	}

	groups, scopes, err := s.ResolveScopes(ctx, entry.TelegramID)
	if err != nil {
		return "", fmt.Errorf("server_error: could not resolve scopes: %w", err)
	}
	tok, err := s.mintAccessToken(entry.TelegramID, entry.TelegramUsername, groups, scopes)
	if err != nil {
		return "", fmt.Errorf("server_error: could not mint token: %w", err)
	}
	return tok, nil
}

// StartSweeper runs a background loop that drops expired in-memory state.
// When useDB is true it also sweeps the DB OAuth tables and samples the
// OAuthPendingAuthSize gauge. Caller controls the lifetime via the stop channel.
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
				s.sweepDB(now)
				s.samplePendingAuthGauge()
			}
		}
	}()
}

// sweepDB deletes expired rows from the Postgres OAuth tables. No-op when
// useDB is false. Errors are logged and not propagated — the in-memory sweeper
// is the authoritative gate; DB sweeping is a bounded-growth safety net.
func (s *Server) sweepDB(_ time.Time) {
	if !s.useDB || s.store == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, _, err := s.store.DeleteExpiredOAuthRows(ctx, s.cfg.CodeTTL); err != nil {
		slog.Warn("oauth db sweep failed", "err", err)
	}
	if s.cfg.ClientRegistrationTTL > 0 {
		if _, err := s.store.DeleteExpiredClientRegs(ctx, s.cfg.ClientRegistrationTTL); err != nil {
			slog.Warn("oauth db client_reg sweep failed", "err", err)
		}
	}
}

// samplePendingAuthGauge refreshes the mctl_oauth_pending_auth_size gauge.
// When useDB is true the count comes from the DB; otherwise from the in-memory
// map. No-op when no metrics registry is wired.
func (s *Server) samplePendingAuthGauge() {
	if s.metrics == nil {
		return
	}
	if s.useDB && s.store != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		n, err := s.store.CountOAuthPending(ctx, s.cfg.CodeTTL)
		if err != nil {
			slog.Warn("oauth pending_auth gauge sample failed", "err", err)
			return
		}
		s.metrics.SetOAuthPendingAuthSize(float64(n))
		return
	}
	// In-memory path.
	s.mu.Lock()
	n := len(s.pending)
	s.mu.Unlock()
	s.metrics.SetOAuthPendingAuthSize(float64(n))
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
	// Entries with a zero CreatedAt are built-in (pre-registered) clients that
	// must never be evicted.
	if s.cfg.ClientRegistrationTTL > 0 {
		for k, c := range s.clients {
			if c.CreatedAt.IsZero() {
				continue // built-in client — never sweep
			}
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
	// Local Bridge activations. ActivationTTL is measured from createdAt for
	// both abandoned and resolved activations — dropActivation (not
	// unindexActivation) is correct here because the activation is genuinely
	// gone at this point, not merely finished; resolution itself already
	// unindexed it from the browser-reachable maps while keeping it pollable.
	for k, act := range s.activations {
		if now.Sub(act.createdAt) > s.cfg.ActivationTTL {
			s.dropActivation(act)
			_ = k // dropActivation removes by act.deviceCode, which is k here
		}
	}
	// Failed-submission rate-limiter entries, swept in the same pass.
	for k, w := range s.activationFails {
		if now.Sub(w.startedAt) > s.cfg.ActivationFailWindow {
			delete(s.activationFails, k)
		}
	}
	// Device PoP nonces (issue-483). expiresAt is set at mint time from
	// DeviceNonceTTL, so this is a plain expiry check, not a createdAt/TTL
	// recomputation.
	for k, n := range s.deviceNonces {
		if now.After(n.expiresAt) {
			delete(s.deviceNonces, k)
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

// ResolveScopes maps a Telegram identity to a scope set. Four tiers, checked
// in this order:
//   - admins (TG_LOGIN_ADMINS env) → platform-admins: full telegram:* plus
//     admin:users.
//   - lookup-admins (TG_LOGIN_LOOKUP_ADMINS env) → admin-lookup:
//     admin:users:read only — the two read-only admin lookups, no telegram:*
//     messaging scopes and none of the admin write tools the flat
//     admin:users scope gates. For a lookup-only consumer (e.g. an OpenClaw
//     bot answering "who is Telegram user X") that must never need a
//     real/working MTProto session of its own. Checked after the full-admin
//     tier, so an id listed in both always resolves via the full-admin
//     branch above, unchanged.
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
			// account:manage (issue-483): an admin is also a Local Bridge
			// owner of their own account, so they get the same self-service
			// consent/revocation tools a client-tier owner gets -- on top
			// of, not instead of, admin:users's operator-recovery path
			// (set_account_send / revoke_local_bridge_device-for-any-user
			// stays admin:users-only; see design.md's open question on
			// admin-initiated device revocation).
			"account:manage",
		}, nil
	}
	// The lookup tier's scope is admin:users:read, NOT admin:users. That
	// distinction is the whole tier: admin:users is a single flat scope
	// gating nine MCP tools, only two of which are the read-only lookups
	// this tier exists for (list_telegram_identities, get_user_audit_log).
	// The other seven are writes -- set_telegram_access, set_account_send,
	// set_account_mode, provision_local_account, revoke_telegram_session,
	// revoke_worker_token and mint_worker_token -- plus three admin HTTP
	// mint routes (internal/agentapi's two handlers and
	// internal/workertoken's). Granting admin:users here would have handed
	// a "lookup-only" consumer every one of them, and mint_worker_token in
	// particular would have defeated this tier's own reason to exist: it
	// mints a credential for an ARBITRARY target account, and purpose
	// "local-bridge" adds send and pin. Withholding telegram:* from an
	// identity that can mint itself a sending credential for anyone is a
	// decorative restriction, not a boundary.
	//
	// admin:users:read is implicit-privileged the same way admin:users is:
	// granted here, never in DCRNegotiableScopes, and absent from both of
	// internal/workertoken's mint allowlists (which are subset-validated
	// against fixed literals), so no worker or device credential can ever
	// carry it.
	//
	// Checked before the client tier, so lookup-admin membership WINS over
	// it: an id in both LookupAdminTelegramIDs and the client allowlist (env
	// TG_LOGIN_CLIENTS or a DB access_tier) resolves to admin:users:read
	// alone and keeps none of the telegram:* scopes. That is deliberate --
	// the two are meant to be disjoint populations, a lookup admin being an
	// operator bot rather than a messaging account -- and listing an id in
	// both is a configuration mistake, not a way to combine the bundles. It
	// resolves quietly rather than erroring because the alternative is
	// failing a login over a config typo; the precedence is pinned by
	// TestResolveScopes_Tiers so it cannot be swapped unnoticed. The
	// background executor's agentSendGate mirrors this precedence
	// explicitly (cmd/server/agentsendgate.go) -- it reconstructs send
	// capability from the same tier inputs without calling this function,
	// so a tier added here and not there is a silent divergence.
	//
	// It is also checked before isClientTier's database call, so THIS
	// FUNCTION resolves a statically-listed lookup admin without touching the
	// DB, the same way an AdminTelegramIDs entry above does. That is a
	// property of scope resolution only -- it is NOT a login-wide guarantee
	// that static tiers survive a database outage. handleTelegramCallback
	// needs the database well before it reaches any tier logic
	// (EnsureUserByTelegramID for the user row, GetAccessTier in the
	// auto-approve block, and CheckSessionValid, whose default branch is an
	// explicit 500), so a DB outage fails the callback for every tier
	// including env-only admins.
	if s.cfg.LookupAdminTelegramIDs[tgID] {
		return []string{"admin-lookup"}, []string{"admin:users:read"}, nil
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
			// account:manage (issue-483): lets a client-tier owner call
			// set_send_consent / revoke_local_bridge_device for their OWN
			// account without admin:users. Deliberately never granted to a
			// worker or device credential -- see scopes.go's comment on
			// this scope and internal/workertoken's allowlists.
			"account:manage",
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
	mux.Post("/oauth/revoke", s.handleRevoke)
	mux.Post("/oauth/register", s.handleClientRegistration)
	// In-browser "enable message access" flow. Public (no auth gate): the
	// caller's identity is carried by the unguessable "es" token minted at
	// the Telegram callback, which also serves as the CSRF token.
	mux.Post("/oauth/telegram/enable_access/permissions", s.handleEnablePermissions)
	mux.Post("/oauth/telegram/enable_access/start", s.handleEnableStart)
	mux.Post("/oauth/telegram/enable_access/code", s.handleEnableCode)
	mux.Post("/oauth/telegram/enable_access/password", s.handleEnablePassword)
	// Reviewer/demo auth-mode. Registered unconditionally; the handler is a
	// no-op (404-equivalent) unless DemoReviewerEnabled is set, so a route
	// table is stable across config. CSRF/state is carried by the server-side
	// "state" token minted at /oauth/authorize.
	mux.Post("/oauth/demo/login", s.handleDemoLogin)
	// Local Bridge self-service device activation (issue #482). /start and
	// /poll are unauthenticated API endpoints for the CLI; the GET/POST pair
	// at /local-bridge/activate is the browser-driven user_code + Telegram
	// OIDC leg; /consent is the explicit, CSRF-protected approval that alone
	// authorises the database writes. See local_bridge_activate.go.
	mux.Post("/api/local-bridge/activate/start", s.handleActivateStart)
	mux.Get("/local-bridge/activate", s.handleActivateForm)
	mux.Post("/local-bridge/activate", s.handleActivateVerify)
	mux.Post("/local-bridge/activate/consent", s.handleActivateConsent)
	mux.Post("/api/local-bridge/activate/poll", s.handleActivatePoll)
	// Self-service device credential issuance/refresh (issue-483). All three
	// are unauthenticated-but-device_id-scoped, like /activate/start: the
	// device_id is a 128-bit crypto/rand value, so this is "possession of
	// the id" gated further by Ed25519 proof of possession, not "no auth at
	// all". See local_bridge_credential.go.
	mux.Post("/api/local-bridge/devices/{device_id}/nonce", s.handleDeviceNonce)
	mux.Post("/api/local-bridge/devices/{device_id}/credential", s.handleDeviceCredential)
	mux.Post("/api/local-bridge/devices/{device_id}/refresh", s.handleDeviceRefresh)
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
		"issuer":                                     s.cfg.Issuer,
		"authorization_endpoint":                     s.cfg.Issuer + "/oauth/authorize",
		"token_endpoint":                             s.cfg.Issuer + "/oauth/token",
		"registration_endpoint":                      s.cfg.Issuer + "/oauth/register",
		"revocation_endpoint":                        s.cfg.Issuer + "/oauth/revoke",
		"response_types_supported":                   []string{"code"},
		"grant_types_supported":                      []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":           []string{"S256"},
		"token_endpoint_auth_methods_supported":      []string{"none"},
		"revocation_endpoint_auth_methods_supported": []string{"none"},
		// scopes_supported intentionally omits admin:users — that scope is
		// implicit-privileged (granted by ResolveScopes based on
		// TG_LOGIN_ADMINS membership, not negotiable via DCR). Advertising
		// it would cause DCR clients (ChatGPT, claude.ai) to request it
		// for every user; client-tier users would then see "not all
		// requested permissions were granted" warnings even though the
		// token works correctly. Admins still receive admin:users in the
		// JWT scopes claim; MCP per-tool gates check the claim, not this
		// metadata field.
		"scopes_supported": DCRNegotiableScopes,
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
	// state is an opaque pass-through the client echoes back on redirect. The
	// OpenAI Apps platform packs a base64 relay blob (oauth_id, app_id,
	// version_id, org_id, target_uri) into it that already runs ~525 bytes, and
	// can grow with longer target URIs, so the cap must clear that with headroom
	// while still bounding the in-memory pending entry against OOM abuse.
	if len(state) > 4096 {
		s.writeAuthorizeError(w, "invalid_request", "state exceeds 4096 bytes")
		return
	}
	if len(scope) > 1024 {
		s.writeAuthorizeError(w, "invalid_request", "scope exceeds 1024 bytes")
		return
	}
	if err := s.validateClient(r.Context(), clientID, redirectURI); err != nil {
		s.writeAuthorizeError(w, "invalid_client", err.Error())
		return
	}

	// Diagnostic: capture exactly what the MCP client requests, so we can
	// reconcile scope mismatches surfaced by DCR clients' UI. Emitted only
	// after the length-bounded + validateClient gates — an unauthenticated
	// caller cannot drive log volume past 4 KB per accepted request. PII-
	// safe: scope is opaque OAuth strings, state/code_challenge are random
	// tokens (len-only), redirect_uri is observed at the host level.
	{
		ru, _ := url.Parse(redirectURI)
		host := ""
		if ru != nil {
			host = ru.Host
		}
		extraParams := make([]string, 0, len(q))
		for k := range q {
			switch k {
			case "client_id", "redirect_uri", "state", "code_challenge",
				"code_challenge_method", "response_type", "scope":
			default:
				extraParams = append(extraParams, k)
			}
		}
		sort.Strings(extraParams)
		slog.Info("oauth: authorize request",
			"user_agent", r.Header.Get("User-Agent"),
			"client_id", clientID,
			"redirect_uri_host", host,
			"response_type", responseType,
			"scope", scope,
			"state_len", len(state),
			"code_challenge_method", codeChallengeMethod,
			"extra_query_params", strings.Join(extraParams, ","),
		)
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
	if s.useDB {
		// Persist to Postgres; skip the in-memory map so reads on other replicas
		// resolve the same entry.
		// Cap enforcement is best-effort under concurrent load: evict and insert
		// are separate round-trips with no transaction between them, so N
		// concurrent requests near the cap boundary can each skip eviction and
		// all insert, temporarily exceeding MaxPendingAuth by at most N. The
		// sweeper converges the count back below the cap within its next tick.
		if err := s.store.EvictOldestOAuthPendingIfOver(r.Context(), s.cfg.MaxPendingAuth, s.cfg.CodeTTL); err != nil {
			slog.Warn("oauth: pending_auth eviction failed", "err", err)
		}
		if err := s.store.InsertOAuthPending(r.Context(), db.OAuthPendingAuth{
			State:           serverState,
			ClientID:        clientID,
			RedirectURI:     redirectURI,
			ClientState:     state,
			CodeChallenge:   codeChallenge,
			ChallengeMethod: codeChallengeMethod,
			Scope:           scope,
			Nonce:           nonce,
			TGCodeVerifier:  tgVerifier,
			CreatedAt:       now,
		}); err != nil {
			slog.Error("oauth: persist pending_auth failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	} else {
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
	}

	tgURL := s.tgoidc.AuthCodeURL(serverState, nonce, tgChallenge)

	// Reviewer/demo auth-mode: instead of redirecting straight to Telegram,
	// render a chooser offering both the normal Telegram sign-in and a
	// password-gated reviewer path. The reviewer form posts the server-side
	// state to /oauth/demo/login, which authenticates as the pre-provisioned
	// demo identity without the live Telegram OIDC login. Off by default, so
	// the normal redirect below is unchanged for every other deployment.
	if s.cfg.DemoReviewerEnabled {
		renderDemoChooser(w, demoChooserPage{
			Issuer:      s.cfg.Issuer,
			TelegramURL: tgURL,
			State:       serverState,
		})
		return
	}

	// Hand the browser to Telegram's OIDC authorization endpoint. Telegram
	// renders its own account-selection and consent screen, then 302s back to
	// /oauth/telegram/callback with ?code=&state=serverState. tgChallenge is
	// the Telegram-leg PKCE challenge — independent of the MCP client's
	// codeChallenge held in pending and verified later at /oauth/token.
	http.Redirect(w, r, tgURL, http.StatusFound)
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

	// Local Bridge activation dispatch. Must run BEFORE the pendingAuth
	// lookup below and BEFORE any other check: a state minted by
	// handleActivateVerify never appears in s.pending, so this is a pure
	// addition with no behavioral change for any state /oauth/authorize
	// minted. isActivation false falls straight through unchanged.
	s.mu.Lock()
	act, isActivation := s.activationsByState[serverState]
	var actVerifier, actNonce string
	if isActivation {
		delete(s.activationsByState, serverState)
		// Copy under the lock — never read act.oidcVerifier/act.oidcNonce
		// again after Unlock, including inside finishActivation: a concurrent
		// form submission for the same activation can rewrite those fields
		// while the exchange is in flight, which in Go is a genuine data
		// race, not merely a stale read.
		actVerifier, actNonce = act.oidcVerifier, act.oidcNonce
	}
	s.mu.Unlock()
	if isActivation {
		// Login-CSRF binding: this callback is only honoured for the browser
		// that submitted the user_code on this activation. Without this check
		// the user_code step is bypassable — the attacker can type their own
		// code in their own browser, capture the resulting Telegram
		// authorization URL, and forward that URL to the victim, whose
		// sign-in would otherwise land on the attacker's activation having
		// never seen the code entry form. Refuse before doing anything else;
		// never fall through to the pendingAuth path below.
		c, cerr := r.Cookie(activationStateCookieName)
		if cerr != nil || !hmac.Equal([]byte(hashActivationState(serverState)), []byte(c.Value)) {
			s.denyActivation(act, "verification link was opened in a different browser or has expired")
			clearActivationStateCookie(w)
			renderActivationError(w, "That sign-in link is no longer valid. Return to your terminal and run the activation command again.")
			return
		}
		clearActivationStateCookie(w) // single use
		s.finishActivation(w, r, act, q, actVerifier, actNonce)
		return
	}

	// Consume the pending entry up front — state is single-use whatever the
	// outcome, so an error redirect cannot be replayed against a fresh code.
	var pending *pendingAuth
	if s.useDB {
		dbPA, err := s.store.ConsumeOAuthPending(r.Context(), serverState, s.cfg.CodeTTL)
		if errors.Is(err, db.ErrOAuthNotFound) {
			http.Error(w, "unknown or expired state", http.StatusBadRequest)
			return
		}
		if err != nil {
			slog.Error("oauth: consume pending_auth failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		pending = &pendingAuth{
			ClientID:            dbPA.ClientID,
			RedirectURI:         dbPA.RedirectURI,
			State:               dbPA.ClientState,
			CodeChallenge:       dbPA.CodeChallenge,
			CodeChallengeMethod: dbPA.ChallengeMethod,
			Scope:               dbPA.Scope,
			Nonce:               dbPA.Nonce,
			TGCodeVerifier:      dbPA.TGCodeVerifier,
			CreatedAt:           dbPA.CreatedAt,
		}
	} else {
		s.mu.Lock()
		var ok bool
		pending, ok = s.pending[serverState]
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

	// When open registration is on (AutoApproveClients), materialize the
	// transient client grant to DB so admin tools reflect the real tier and
	// revokes stay unambiguous. Only writes on first sign-in (dbTier=="");
	// an explicit "none" set by an admin is never overwritten. The whole
	// block is best-effort: the transient grant in isClientTier already
	// covers the user regardless, so a DB read/write hiccup here must not
	// turn an otherwise-valid sign-in into an HTTP 500.
	//
	// A statically-listed lookup admin is exempt. Without the exemption its
	// first sign-in finds dbTier=="" and persists access_tier='client' --
	// harmless while the id stays in TG_LOGIN_LOOKUP_ADMINS, since both
	// ResolveScopes and agentSendGate.hasSendScope check that allowlist
	// BEFORE the client tier, but a trap on removal: taking the bot out of
	// the allowlist when it is rotated out would PROMOTE it to the full
	// client tier off the persisted row (telegram:* plus account:manage)
	// instead of dropping it to no scopes. Operators reasonably read
	// "remove from the allowlist" as de-provisioning, so removal has to mean
	// removal. It also keeps the bot from showing up as a client in
	// list_telegram_identities and in the new-client digest.
	//
	// Guarded with !AdminTelegramIDs for the same reason every other tier
	// site in this file is (ResolveScopes' branch order, isLookupOnlyAdmin
	// below, agentSendGate.hasSendScope): full-admin membership wins over a
	// dual listing everywhere, so a full admin who is also listed as a lookup
	// admin keeps the normal materialization. Nothing about their scopes
	// changes either way -- those come from the env allowlist -- but letting
	// the exemption fire for them would leave one site disagreeing with the
	// rest about what a dual listing means.
	isLookupOnly := s.cfg.LookupAdminTelegramIDs[identity.TelegramID] &&
		!s.cfg.AdminTelegramIDs[identity.TelegramID]
	if s.cfg.AutoApproveClients && !isLookupOnly {
		dbTier, err := s.store.GetAccessTier(r.Context(), identity.TelegramID)
		if err != nil {
			slog.Error("get access tier for auto-grant failed", "err", err)
			// non-fatal: skip the write, transient grant in isClientTier still covers this user
		}
		if err == nil && dbTier == "" {
			if err := s.store.SetAccessTier(r.Context(), identity.TelegramID, db.TierClient); err != nil {
				slog.Error("auto-set client tier failed", "telegram_id", identity.TelegramID, "err", err)
				// non-fatal: transient grant in isClientTier still covers this user
			} else {
				slog.Info("auto-granted client tier on sign-in", "telegram_id", identity.TelegramID)
			}
		}
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
	case errors.Is(sessErr, db.ErrNoActiveSession), errors.Is(sessErr, db.ErrSessionExpired),
		errors.Is(sessErr, db.ErrSessionUnauthorized), errors.Is(sessErr, db.ErrSessionRevoked):
		// Expected: no usable session. ErrSessionUnauthorized/ErrSessionRevoked
		// mean a prior session was unfinished or killed server-side;
		// CheckSessionValid has already revoked that row, so the user
		// self-recovers by falling through to enable_access here.
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
	// A lookup-admin-only identity (in LookupAdminTelegramIDs but not
	// AdminTelegramIDs) resolves to admin:users:read alone, per ResolveScopes —
	// no telegram:* messaging scopes, so an MTProto session would be as
	// unusable for them as for the no-scopes case above. Route them straight
	// to the code, skipping the phone/SMS/2FA enable_access flow entirely.
	// isLookupOnly is bound once above, at the auto-approve block: the two
	// sites need the identical "lookup admin, and not also a full admin"
	// predicate, and recomputing it is how the two would drift apart.
	if (!s.cfg.AdminTelegramIDs[identity.TelegramID] && !isClient) || isLookupOnly {
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
	s.store.LogToolCall(r.Context(), uid, "connect:oidc_callback", "", "ok", "", "")
	if es.isWizardMode() {
		es.step = stepPermissions
		renderEnablePermissions(w, enablePermissionsPage{Issuer: s.cfg.Issuer, EnableToken: esTok})
	} else {
		es.step = stepPhone
		// SendOptIn defaults true so the send checkbox renders pre-checked:
		// sending is opt-out, not opt-in. Unchecking it omits the field and
		// the server falls back to read-only.
		renderEnablePhone(w, enablePhonePage{Issuer: s.cfg.Issuer, EnableToken: esTok, SendOptIn: true})
	}
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
	if s.useDB {
		// Best-effort cap enforcement — see same comment in handleAuthorize.
		if err := s.store.EvictOldestOAuthCodeIfOver(r.Context(), s.cfg.MaxAuthCodes, s.cfg.CodeTTL); err != nil {
			slog.Warn("oauth: auth_code eviction failed", "err", err)
		}
		if err := s.store.InsertOAuthCode(r.Context(), db.OAuthCode{
			Code:             code,
			ClientID:         oc.ClientID,
			RedirectURI:      oc.RedirectURI,
			CodeChallenge:    oc.CodeChallenge,
			ChallengeMethod:  "S256",
			TelegramID:       oc.TelegramID,
			TelegramUsername: oc.Username,
			Scope:            oc.Scope,
			CreatedAt:        now,
		}); err != nil {
			slog.Error("oauth: persist auth_code failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	} else {
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
	}

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

	// For external OAuth clients (claude.ai / chatgpt.com) render a success
	// interstitial instead of a bare 302. The final claude.ai -> Desktop-app
	// hand-off is Anthropic-side and can silently fail to refocus the
	// backgrounded app, leaving the user unsure the connection worked (they then
	// retry, each retry a fresh dynamic registration). The interstitial gives a
	// visible confirmation + an explicit return control while still
	// auto-redirecting so the web flow stays near-seamless. The self-hosted
	// wizard's own same-host redirect keeps the 302 — it renders its own page.
	if s.isExternalRedirect(u) {
		renderConnectSuccess(w, connectSuccessPage{
			RedirectURL: u.String(),
			AppName:     connectAppName(u.Host),
		})
		return
	}
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// isExternalRedirect reports whether u targets a different host than the issuer.
// Same-host redirects are the self-hosted connect wizard
// (Issuer + "/telegram/connect/done"), which renders its own completion page;
// only genuinely external clients get the success interstitial.
func (s *Server) isExternalRedirect(u *url.URL) bool {
	iss, err := url.Parse(s.cfg.Issuer)
	if err != nil {
		// Issuer is validated non-empty at startup, so this should never fire;
		// log it so a future misconfiguration is discoverable rather than
		// silently routing every redirect (including same-host) through the
		// interstitial.
		slog.Warn("oauth: issuer parse failed; treating redirect as external", "issuer", s.cfg.Issuer, "err", err)
		return true
	}
	return !strings.EqualFold(u.Host, iss.Host)
}

// connectAppName maps a redirect_uri host to a human label for the success page.
func connectAppName(host string) string {
	h := strings.ToLower(host)
	switch {
	case hostMatches(h, "claude.ai", "anthropic.com"):
		return "Claude"
	case hostMatches(h, "chatgpt.com", "openai.com"):
		return "ChatGPT"
	default:
		return "your app"
	}
}

// hostMatches reports whether host equals one of domains or is a subdomain of
// one. Exact/suffix matching avoids the substring trap where an unrelated host
// such as "claude-shim.example.com" would be mislabelled.
func hostMatches(host string, domains ...string) bool {
	for _, d := range domains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
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

	var entry *authCode
	if s.useDB {
		dbCode, err := s.store.ConsumeOAuthCode(r.Context(), code, s.cfg.CodeTTL)
		if errors.Is(err, db.ErrOAuthNotFound) {
			writeTokenError(w, "invalid_grant", "code not found, expired, or already used", http.StatusBadRequest)
			return
		}
		if err != nil {
			slog.Error("oauth: consume auth_code failed", "err", err)
			writeTokenError(w, "server_error", "could not redeem code", http.StatusInternalServerError)
			return
		}
		entry = &authCode{
			ClientID:            dbCode.ClientID,
			RedirectURI:         dbCode.RedirectURI,
			CodeChallenge:       dbCode.CodeChallenge,
			CodeChallengeMethod: dbCode.ChallengeMethod,
			TelegramID:          dbCode.TelegramID,
			TelegramUsername:    dbCode.TelegramUsername,
			Scope:               dbCode.Scope,
			CreatedAt:           dbCode.CreatedAt,
		}
	} else {
		s.mu.Lock()
		var ok bool
		entry, ok = s.codes[code]
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
	// Diagnostic: requested-vs-granted scope reconciliation.
	slog.Info("oauth: token authorization_code grant",
		"user_agent", r.Header.Get("User-Agent"),
		"client_id", clientID,
		"requested_scope", entry.Scope,
		"granted_scope", strings.Join(scopes, " "),
		"groups", strings.Join(groups, ","),
	)
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
	var clientName string
	if reg, regErr := s.store.GetClientReg(r.Context(), clientID); regErr == nil {
		clientName = reg.ClientName
	}
	refreshTok, err := s.issueRefreshToken(r.Context(), db.RefreshToken{
		FamilyID:         randomToken(16),
		UserID:           uid,
		ClientID:         clientID,
		ClientName:       clientName,
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

// rotationGraceWindow is how long after a rotation a replay of the
// predecessor token is treated as a possible lost-response retry (see
// handleTokenRefresh) rather than reuse. A package-level var, not a const,
// so tests can advance the server clock past the window without sleeping
// real wall-clock time.
//
// Originally, and deliberately kept at, 30s-to-1m: sized only for
// concurrent-request races and lost HTTP responses (PR #343). 2026-08-19:
// briefly widened to 5m, then 24h, to tolerate a client (OpenAI Codex, via
// the MCP OAuth client registered on mctl-telegram) that presented an
// already-rotated token ~70 minutes after rotation and had its whole
// refresh-token family killed as reuse. Reverted after review (agy pilot
// finding, confirmed correct): rotation-based reuse detection exists
// specifically to bound how long a stolen predecessor refresh token is
// redeemable via attemptGraceRecovery's grace-recovery path. A 70-minute
// gap is a client bug — it failed to persist its rotated token and kept
// presenting the stale one — not a network race, and the fix for that is
// forcing the client to re-authenticate, not widening the server's
// tolerance for stale (and, if stolen, already-compromised) credentials
// to hours. Set to 1m: the top of PR #343's original network-race
// justification, no wider.
var rotationGraceWindow = time.Minute

// graceRecoveryOutcome distinguishes what handleTokenRefresh should do next
// after attemptGraceRecovery runs.
type graceRecoveryOutcome int

const (
	// graceRecovered: a live successor was found and re-issued; response
	// already written.
	graceRecovered graceRecoveryOutcome = iota
	// graceRejectedSoft: no eligible successor, but this is NOT trusted as
	// proof of theft (wrong client, expired successor, or no match at all);
	// response already written as invalid_grant WITHOUT revoking anything.
	graceRejectedSoft
	// graceServerError: an internal failure occurred verifying or minting;
	// response already written as a 500. Must not be treated as reuse — a
	// transient failure must not kill a live token family.
	graceServerError
	// graceNotEligible: the presented token was not revoked by a recent
	// normal rotation (outside the window, or revoked for a different
	// reason). Nothing written yet; caller should proceed to hard-revoke
	// the family as genuine reuse.
	graceNotEligible
)

// attemptGraceRecovery checks whether refreshTok's predecessor was revoked
// by a normal rotation within rotationGraceWindow, and if so, recovers the
// live, unexpired successor a deterministic-derivation caller would have
// recomputed and mints a fresh access token for it instead of treating the
// replay as reuse. Shared by both places handleTokenRefresh discovers a
// revoked predecessor: the direct case (LookupRefreshToken already showed it
// revoked) and the concurrent-race case (RotateRefreshToken lost the race
// against another request rotating the same token first) — both need
// identical grace-window bounding, expiry checking, and error propagation,
// so recovery logic lives in exactly one place.
func (s *Server) attemptGraceRecovery(w http.ResponseWriter, r *http.Request, refreshTok, revokedReason string, revokedAt time.Time, familyID, clientID string) graceRecoveryOutcome {
	if revokedReason != "rotated" || s.clock().Sub(revokedAt) >= rotationGraceWindow {
		return graceNotEligible
	}
	candidate := deriveSuccessorRefreshToken(s.cfg.JWTSecret, refreshTok)
	child, lookupErr := s.store.LookupRefreshTokenByHashPair(r.Context(), refreshTok, candidate, familyID, clientID)
	if lookupErr != nil {
		if !errors.Is(lookupErr, db.ErrRefreshTokenNotFound) {
			// A transient failure verifying the candidate must not be
			// mistaken for "no match" — that would let a DB blip fall
			// through to family revocation in the caller.
			writeTokenError(w, "server_error", "could not verify grace-window replay", http.StatusInternalServerError)
			return graceServerError
		}
		writeTokenError(w, "invalid_grant", "refresh token already used", http.StatusBadRequest)
		return graceRejectedSoft
	}
	if child.Expired(s.clock()) {
		// A successor minted just before the family's absolute expiry could
		// otherwise be recovered and used to mint a fresh access token after
		// that expiry — the same window that made the original token
		// unusable must also close this recovery path.
		writeTokenError(w, "invalid_grant", "refresh token already used", http.StatusBadRequest)
		return graceRejectedSoft
	}
	groups, scopes, sErr := s.ResolveScopes(r.Context(), child.TelegramID)
	if sErr != nil {
		writeTokenError(w, "server_error", "could not resolve scopes", http.StatusInternalServerError)
		return graceServerError
	}
	tok, mErr := s.mintAccessToken(child.TelegramID, child.TelegramUsername, groups, scopes)
	if mErr != nil {
		writeTokenError(w, "server_error", "could not mint token", http.StatusInternalServerError)
		return graceServerError
	}
	slog.Info("oauth refresh token grace-window replay: re-issuing existing successor", "family_id", familyID)
	writeTokenJSON(w, tok, candidate, int(s.cfg.AccessTokenTTL.Seconds()), scopes)
	return graceRecovered
}

// handleTokenRefresh implements grant_type=refresh_token: it renews a
// (typically expired) access token from a stored, rotating refresh token with
// no Telegram interaction. This is what stops MCP clients losing access
// once an access token's short TTL elapses. The presented refresh token is
// rotated — the old one revoked, a new one returned. Presenting an
// already-rotated token within rotationGraceWindow is treated as a possible
// lost-response retry and recovers the existing successor; past the window
// it's treated as reuse and revokes the whole family.
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
	if rt.Revoked() {
		// Grace window: if this row was superseded by a normal rotation very
		// recently, the caller may be legitimately retrying after a dropped
		// response. attemptGraceRecovery proves the caller already held
		// refreshTok before it was rotated (by recomputing the deterministic
		// successor and matching it against the live child) before re-issuing
		// anything. A non-eligible outcome (wrong client, expired successor,
		// or no match) is NOT treated as proof of theft: it soft-fails with
		// invalid_grant WITHOUT revoking the family, so a wrong client_id or
		// an unlucky lost race can't be used to kill a legitimate concurrent
		// session. Only a replay outside the grace window (or of a token
		// already revoked for a different reason) escalates to a full family
		// revocation, below.
		switch s.attemptGraceRecovery(w, r, refreshTok, rt.RevokedReason, rt.RevokedAt, rt.FamilyID, clientID) {
		case graceRecovered, graceRejectedSoft, graceServerError:
			return
		case graceNotEligible:
			// fall through to hard revoke
		}
		// Either an honest client double-submitted outside the grace window
		// or a stolen token is in play — kill the family and force a fresh
		// login. If the revoke itself fails we must NOT fall through to a
		// plain invalid_grant: that would leave the family's still-live
		// token usable after a detected theft. Fail closed with a 500 so the
		// incident surfaces and the caller retries.
		if _, revErr := s.store.RevokeRefreshTokenFamily(r.Context(), rt.FamilyID, "reuse_detected"); revErr != nil {
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
	newRefresh := deriveSuccessorRefreshToken(s.cfg.JWTSecret, refreshTok)
	if err := s.store.RotateRefreshToken(r.Context(), refreshTok, newRefresh, db.RefreshToken{
		FamilyID:         rt.FamilyID,
		UserID:           rt.UserID,
		ClientID:         rt.ClientID,
		ClientName:       rt.ClientName,
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
			// This is the exact race deterministic derivation exists to
			// recover from: since both requests derive the same candidate
			// successor from refreshTok, the loser can recover the winner's
			// already-committed row instead of treating it as reuse. Re-read
			// the predecessor to learn how/when the winner revoked it, and
			// run it through the SAME grace-window-bounded, expiry-checked,
			// error-propagating recovery as a direct replay gets — an
			// unbounded recovery here (no time check at all) would let an
			// arbitrarily stalled request bypass the reuse-detection
			// boundary entirely.
			reRead, reErr := s.store.LookupRefreshToken(r.Context(), refreshTok)
			if reErr != nil && !errors.Is(reErr, db.ErrRefreshTokenNotFound) {
				// A transient failure re-reading the predecessor must not be
				// mistaken for "nothing to recover" — that would let a DB
				// blip fall through to family revocation, same class of bug
				// attemptGraceRecovery itself already guards against.
				slog.Error("could not re-read predecessor after rotation race",
					"err", reErr, "family_id", rt.FamilyID)
				writeTokenError(w, "server_error", "could not verify rotation race", http.StatusInternalServerError)
				return
			}
			if reErr == nil && reRead.Revoked() {
				switch s.attemptGraceRecovery(w, r, refreshTok, reRead.RevokedReason, reRead.RevokedAt, reRead.FamilyID, clientID) {
				case graceRecovered, graceRejectedSoft, graceServerError:
					return
				case graceNotEligible:
					// fall through to hard revoke
				}
			}
			// reErr being ErrRefreshTokenNotFound here means the
			// predecessor row was somehow deleted between the race and this
			// re-read — falls through to hard revoke below, correctly:
			// there is nothing left to verify or recover.
			// No recoverable successor: either a genuinely stolen token is
			// in play, or the race happened outside recovery range (e.g. the
			// winner's row was itself already superseded, or too much time
			// passed). Kill the family. Without this, the request that won
			// the race would keep a live rotated token while the family
			// stays intact. A revoke failure here is logged but not turned
			// into a 500: the loser's token is already definitively gone
			// (the winner revoked it), so invalid_grant is the correct
			// client-facing answer regardless, and the family will still be
			// caught if the now-revoked token is replayed.
			if _, revErr := s.store.RevokeRefreshTokenFamily(r.Context(), rt.FamilyID, "reuse_detected"); revErr != nil {
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

// handleRevoke implements RFC 7009 token revocation for refresh tokens.
// Access tokens are not revocable by this endpoint or by any other means
// short of rotating OAUTH_JWT_SIGNING_KEY — see SECURITY.md. Presenting an
// access token (or any other unrecognized value) as `token` here simply
// falls into the "unknown token" branch below and is a no-op.
//
// Response shape deliberately makes "unknown token" and "known token
// belonging to a different client_id" indistinguishable (both 200, empty
// body): RFC 7009 SS2.1 requires that this endpoint not let a caller who
// cannot prove ownership of a token learn whether it exists at all. Only a
// genuine store error (lookup or revoke) maps to a non-200 response — a
// false 200 on a failed revoke would be worse than a visible error, since
// the caller would believe a leaked token was cut off when it was not.
func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeTokenError(w, "invalid_request", "could not parse form", http.StatusBadRequest)
		return
	}
	token := r.FormValue("token")
	clientID := r.FormValue("client_id")
	if token == "" || clientID == "" {
		writeTokenError(w, "invalid_request", "token and client_id are required", http.StatusBadRequest)
		return
	}
	// token_type_hint (RFC 7009 SS2.1) is accepted but not required or
	// validated: only refresh tokens are revocable here, so any hint value
	// — including "access_token" — still routes through the same
	// refresh-token lookup and correctly falls into the "unknown token"
	// branch if the presented value isn't one.
	rt, err := s.store.LookupRefreshToken(r.Context(), token)
	if errors.Is(err, db.ErrRefreshTokenNotFound) {
		// Unknown token is success per RFC 7009 SS2.2.
		writeRevokeSuccess(w)
		return
	}
	if err != nil {
		writeTokenError(w, "server_error", "could not look up token", http.StatusInternalServerError)
		return
	}
	if rt.ClientID != clientID {
		// Same response as "unknown" so this endpoint cannot be used to
		// fingerprint another client's tokens (RFC 7009 SS2.1).
		writeRevokeSuccess(w)
		return
	}
	// Revoking an already-revoked family is a no-op inside
	// RevokeRefreshTokenFamily (it only touches rows WHERE revoked_at IS
	// NULL), so a repeat revoke of the same token is naturally idempotent.
	if _, err := s.store.RevokeRefreshTokenFamily(r.Context(), rt.FamilyID, "explicit_revoke"); err != nil {
		writeTokenError(w, "server_error", "could not revoke token", http.StatusInternalServerError)
		return
	}
	writeRevokeSuccess(w)
}

// writeRevokeSuccess writes the RFC 7009 SS2.2 success response: HTTP 200
// with an empty body.
func writeRevokeSuccess(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
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
	// Decode into a loose map first so we can observe RFC 7591 fields we
	// otherwise drop (scope, token_endpoint_auth_method, etc.) — useful
	// for diagnosing scope-mismatch warnings in DCR clients. Re-decode
	// into the typed struct for actual processing.
	var raw map[string]any
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		writeTokenError(w, "invalid_client_metadata", "could not decode request", http.StatusBadRequest)
		return
	}
	keys := make([]string, 0, len(raw))
	for k := range raw {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	rawScope, _ := raw["scope"].(string)
	rawClientName, _ := raw["client_name"].(string)
	redirectURICount := 0
	if uris, ok := raw["redirect_uris"].([]any); ok {
		redirectURICount = len(uris)
	}
	slog.Info("oauth: client_registration request",
		"user_agent", r.Header.Get("User-Agent"),
		"keys", strings.Join(keys, ","),
		"client_name", rawClientName,
		"redirect_uri_count", redirectURICount,
		"scope_in_request", rawScope,
	)
	// Re-encode + decode to extract the typed shape we actually use.
	buf, err := json.Marshal(raw)
	if err != nil {
		writeTokenError(w, "invalid_client_metadata", "could not decode request", http.StatusBadRequest)
		return
	}
	var req struct {
		ClientName   string   `json:"client_name"`
		RedirectURIs []string `json:"redirect_uris"`
	}
	if err := json.Unmarshal(buf, &req); err != nil {
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
	if s.useDB {
		// Best-effort cap enforcement — see same comment in handleAuthorize.
		if err := s.store.EvictOldestClientRegIfOver(r.Context(), s.cfg.MaxRegisteredClients); err != nil {
			slog.Warn("oauth: client_reg eviction failed", "err", err)
		}
		if err := s.store.InsertClientReg(r.Context(), db.OAuthClientReg{
			ClientID:     clientID,
			ClientName:   req.ClientName,
			RedirectURIs: req.RedirectURIs,
			CreatedAt:    now,
		}); err != nil {
			slog.Error("oauth: persist client_reg failed", "err", err)
			writeTokenError(w, "server_error", "could not persist registration", http.StatusInternalServerError)
			return
		}
	} else {
		s.mu.Lock()
		// Enforce the global cap. If we are at the limit, evict the oldest
		// dynamic entry (linear scan — fine at N≈1000). Built-in clients
		// (zero CreatedAt) are not counted toward the cap and are never evicted.
		if s.cfg.MaxRegisteredClients > 0 {
			var dynamicCount int
			var oldestKey string
			var oldestAt time.Time
			for k, c := range s.clients {
				if c.CreatedAt.IsZero() {
					continue // built-in client — skip
				}
				dynamicCount++
				if oldestKey == "" || c.CreatedAt.Before(oldestAt) {
					oldestKey = k
					oldestAt = c.CreatedAt
				}
			}
			if dynamicCount >= s.cfg.MaxRegisteredClients && oldestKey != "" {
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
	}
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
	// A backslash is not a valid URI character, and parsers disagree on it:
	// some read it as a path separator, others as part of userinfo. That
	// disagreement is what turns a host allowlist into an open redirect, since
	// the host approved here need not be the host a browser dials. Reject
	// before parsing so the two can never diverge.
	if strings.ContainsRune(raw, '\\') {
		return errors.New("redirect_uri must not contain a backslash")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("redirect_uri %q is not a valid URL: %w", raw, err)
	}
	// Userinfo has no place in a redirect target, and accepting it defeats the
	// host checks below: https://evil.com@claude.ai/cb and
	// http://evil.com@localhost/cb both parse with an approved host while
	// reading as evil.com to anything that splits on the first '@' or renders
	// the URL to a user.
	if u.User != nil {
		return errors.New("redirect_uri must not contain userinfo")
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
	// Host names are case-insensitive (RFC 3986 §3.2.2) but url.Parse preserves
	// whatever case it was given, so a client emitting "LOCALHOST" would
	// otherwise be turned away.
	switch strings.ToLower(h) {
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
func (s *Server) validateClient(ctx context.Context, clientID, redirectURI string) error {
	if s.useDB {
		// Look up registration in the Postgres table.
		dbReg, err := s.store.GetClientReg(ctx, clientID)
		if err == nil {
			for _, u := range dbReg.RedirectURIs {
				if u == redirectURI {
					return nil
				}
			}
			return fmt.Errorf("redirect_uri %q is not registered for client_id %q", redirectURI, clientID)
		}
		if !errors.Is(err, db.ErrOAuthNotFound) {
			// Unexpected DB error — fail closed.
			return fmt.Errorf("client validation error: %w", err)
		}
		// Not found in DB — fall through to in-memory check below so that
		// pre-registered built-in clients (e.g. ConnectClientID) are
		// recognised even when useDB is true.
	}
	// In-memory map: covers non-DB deployments and pre-registered built-in
	// clients that are not persisted to the DB.
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
	// One policy, one implementation. This branch and POST /oauth/register used
	// to carry near-identical copies of the same checks, which is how the first
	// version of this hardening left a hole: tightening only this copy still let
	// a caller register the spoofed URI, after which the exact-match path above
	// waved it through without ever re-running these checks.
	return s.validateImplicitRedirectURI(redirectURI)
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
