// Package oauth implements an RFC 6749/RFC 8414/RFC 7591 authorization server
// scoped to a single resource (the mctl-telegram MCP endpoint). It replaces
// the cross-service shared-hmac coupling with api.mctl.ai — mctl-telegram is
// now its own issuer.
//
// Identity provider is the Telegram Login Widget: /oauth/authorize renders a
// page with the widget, and Telegram POSTs back a signed payload that
// /oauth/telegram/callback verifies via internal/auth/telegramwidget.
//
// Tokens are minted by internal/auth/localjwt. PKCE-S256 is mandatory — the
// only supported response_type is "code". Clients are public (no
// client_secret); dynamic registration per RFC 7591 returns an ephemeral
// client_id keyed to a redirect_uri.
//
// Storage is in-memory (codes, registrations, pending widget flows). Each
// store has a TTL; a background goroutine sweeps expired entries. For a
// single-replica deployment (current mctl-telegram in `labs`) this is fine;
// horizontal scale-out would need to externalise the code store to Redis or
// Postgres — out of scope for the first cut.
package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/auth/localjwt"
	"github.com/mctlhq/mctl-telegram/internal/auth/telegramwidget"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

// Server wires the OAuth endpoints. Construct with New, mount handlers with
// Register.
type Server struct {
	cfg      Config
	issuer   *localjwt.Issuer
	verifier *telegramwidget.Verifier
	store    *db.Store
	clock    func() time.Time

	mu      sync.Mutex
	pending map[string]*pendingAuth // keyed by "state" issued at /oauth/authorize
	codes   map[string]*authCode    // keyed by the authorization_code value
	clients map[string]*clientReg   // keyed by client_id
}

// Config captures everything the OAuth server needs at construction time.
type Config struct {
	// Issuer is the canonical PublicBaseURL of mctl-telegram, e.g.
	// "https://tg.mctl.ai". Used for iss claims and metadata.
	Issuer string
	// JWTSecret signs+verifies access tokens. Same value as the localjwt
	// Provider on the /mcp path.
	JWTSecret []byte
	// BotToken is the Telegram bot token whose /setdomain points at Issuer.
	// Used to verify widget callbacks.
	BotToken string
	// BotUsername is the @username of the bot (without leading @). Required
	// for the Login Widget HTML to know which bot to embed. The widget JS
	// reads this from data-telegram-login.
	BotUsername string
	// AdminTelegramIDs is the allowlist of Telegram user ids that get
	// admin/platform-admins scopes. Anyone else still authenticates but
	// receives an empty scope set (and therefore 403s on every MCP tool).
	AdminTelegramIDs map[int64]bool
	// AccessTokenTTL is how long the issued access tokens live. Default 1h.
	AccessTokenTTL time.Duration
	// CodeTTL bounds how long an authorization code is valid after issuance.
	// Default 10 minutes (RFC 6749 §4.1.2 recommends "as short as possible").
	CodeTTL time.Duration
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
}

// pendingAuth is the state captured between /oauth/authorize and the widget
// callback. Survives 10 minutes by default.
type pendingAuth struct {
	ClientID            string
	RedirectURI         string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	Scope               string
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
func New(cfg Config, store *db.Store) (*Server, error) {
	if cfg.Issuer == "" {
		return nil, errors.New("oauth: issuer required")
	}
	if len(cfg.JWTSecret) == 0 {
		return nil, errors.New("oauth: JWTSecret required")
	}
	if cfg.BotToken == "" {
		return nil, errors.New("oauth: BotToken required (Telegram Login Widget cannot verify without it)")
	}
	if cfg.BotUsername == "" {
		return nil, errors.New("oauth: BotUsername required (widget HTML needs data-telegram-login)")
	}
	if cfg.AccessTokenTTL <= 0 {
		cfg.AccessTokenTTL = 1 * time.Hour
	}
	if cfg.CodeTTL <= 0 {
		cfg.CodeTTL = 10 * time.Minute
	}
	if cfg.AdminTelegramIDs == nil {
		cfg.AdminTelegramIDs = map[int64]bool{}
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
	if cfg.MaxRegisterBodyBytes == 0 {
		cfg.MaxRegisterBodyBytes = 64 * 1024
	}
	if cfg.MaxRedirectURIs == 0 {
		cfg.MaxRedirectURIs = 16
	}
	if cfg.MaxRedirectURILength == 0 {
		cfg.MaxRedirectURILength = 2048
	}
	issuer, err := localjwt.NewIssuer(cfg.JWTSecret, cfg.Issuer)
	if err != nil {
		return nil, err
	}
	v, err := telegramwidget.New(cfg.BotToken)
	if err != nil {
		return nil, err
	}
	return &Server{
		cfg:      cfg,
		issuer:   issuer,
		verifier: v,
		store:    store,
		clock:    time.Now,
		pending:  map[string]*pendingAuth{},
		codes:    map[string]*authCode{},
		clients:  map[string]*clientReg{},
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
}

// ResolveScopes maps a Telegram identity to a scope set. For the MVP the
// only meaningful distinction is "is this id in AdminTelegramIDs": admins
// get the full read+write+pin set; everyone else gets nothing and will fail
// the per-tool scope gate.
func (s *Server) ResolveScopes(tgID int64) (groups, scopes []string) {
	if s.cfg.AdminTelegramIDs[tgID] {
		return []string{"platform-admins", "admins"}, []string{
			"telegram:dialogs:read",
			"telegram:messages:read",
			"telegram:messages:send",
			"telegram:messages:pin",
			"admin:users",
		}
	}
	return nil, nil
}

// Register mounts the OAuth handlers onto the supplied router. Each route is
// idempotent — Register may be called once at server boot.
func (s *Server) Register(mux Router) {
	mux.Get("/.well-known/oauth-authorization-server", s.handleAuthorizationServerMetadata)
	mux.Get("/oauth/authorize", s.handleAuthorize)
	// /oauth/telegram/callback is POST-only on purpose: the embedded widget
	// (data-onauth) JS submits a form. Accepting GET would let a third-party
	// site mount a CSRF-by-link attack — the widget hash + server-state
	// nonce mitigate exchange, but POST-only narrows the abuse window.
	mux.Post("/oauth/telegram/callback", s.handleWidgetCallback)
	mux.Post("/oauth/token", s.handleToken)
	mux.Post("/oauth/register", s.handleClientRegistration)
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
		"grant_types_supported":                 []string{"authorization_code"},
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
// renders the Telegram Login Widget page. We never redirect through the
// /oauth/authorize step itself; the user clicks the widget which POSTs to
// /oauth/telegram/callback, and only that handler issues the redirect-with-
// code back to the client's redirect_uri.
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
	if err := s.validateClient(clientID, redirectURI); err != nil {
		s.writeAuthorizeError(w, "invalid_client", err.Error())
		return
	}

	// Persist pending state, indexed by a fresh random server-side state token.
	// We DO NOT trust the client-supplied state — that survives only as a
	// pass-through value the widget callback echoes back on redirect.
	serverState := randomToken(32)
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
		CreatedAt:           now,
	}
	s.mu.Unlock()

	// Render the widget HTML. The widget's `data-onauth` JS posts the signed
	// payload to /oauth/telegram/callback?st=<serverState>; we read st from
	// the form on the callback side.
	//
	// We render the redirect_uri host rather than any client-supplied name
	// because the host is the only piece bound to the OAuth flow that the
	// user can verify against where they expect their authorization code
	// to be delivered. Trusting client_name from dynamic registration
	// (currently unauthenticated) would let an attacker mint a consent
	// screen labeled with any brand.
	redirectHost := ""
	if u, err := url.Parse(redirectURI); err == nil {
		redirectHost = u.Host
	}
	renderAuthorizeHTML(w, authorizePage{
		Issuer:       s.cfg.Issuer,
		BotUsername:  s.cfg.BotUsername,
		ServerState:  serverState,
		RedirectHost: redirectHost,
	})
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

// handleWidgetCallback receives the signed Telegram payload (from the widget
// data-onauth JS) along with the server-issued state token. We verify the
// signature, intersect the user against the admin allowlist, issue an
// authorization_code, and redirect the browser to the client's redirect_uri.
func (s *Server) handleWidgetCallback(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	serverState := r.FormValue("st")
	if serverState == "" {
		http.Error(w, "missing st", http.StatusBadRequest)
		return
	}
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

	// Collect the widget fields. Spec says GET query OR POST form depending
	// on data-auth-url config; we accept either.
	widgetFields := map[string]string{}
	for _, k := range []string{"id", "first_name", "last_name", "username", "photo_url", "auth_date", "hash"} {
		if v := r.FormValue(k); v != "" {
			widgetFields[k] = v
		}
	}
	payload, err := s.verifier.Verify(widgetFields)
	if err != nil {
		http.Error(w, fmt.Sprintf("widget verification failed: %v", err), http.StatusUnauthorized)
		return
	}

	// Bind the Telegram identity to an internal users row. We do this even
	// when the user is not in the admin allowlist — the row is needed so
	// the localjwt provider can resolve UserID on subsequent /mcp calls,
	// and so audit-log entries have something to reference.
	if _, err := s.store.EnsureUserByTelegramID(r.Context(), payload.ID, payload.Username, strings.TrimSpace(payload.FirstName+" "+payload.LastName)); err != nil {
		http.Error(w, fmt.Sprintf("ensure user: %v", err), http.StatusInternalServerError)
		return
	}

	code := randomToken(32)
	s.mu.Lock()
	s.codes[code] = &authCode{
		ClientID:            pending.ClientID,
		RedirectURI:         pending.RedirectURI,
		CodeChallenge:       pending.CodeChallenge,
		CodeChallengeMethod: pending.CodeChallengeMethod,
		TelegramID:          payload.ID,
		TelegramUsername:    payload.Username,
		Scope:               pending.Scope,
		CreatedAt:           s.clock(),
	}
	s.mu.Unlock()

	// Build the redirect URL. State is the original client-supplied state,
	// echoed verbatim per RFC 6749 §4.1.2.
	u, err := url.Parse(pending.RedirectURI)
	if err != nil {
		http.Error(w, "invalid redirect_uri", http.StatusInternalServerError)
		return
	}
	q := u.Query()
	q.Set("code", code)
	if pending.State != "" {
		q.Set("state", pending.State)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// ----- /oauth/token -----

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeTokenError(w, "invalid_request", "could not parse form", http.StatusBadRequest)
		return
	}
	grant := r.FormValue("grant_type")
	if grant != "authorization_code" {
		writeTokenError(w, "unsupported_grant_type", "only authorization_code is supported", http.StatusBadRequest)
		return
	}
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

	groups, scopes := s.ResolveScopes(entry.TelegramID)
	// aud policy: when the deployment configures OAUTH_JWT_AUDIENCE,
	// every minted token MUST carry exactly that value so the localjwt
	// verifier on /mcp accepts it. When unconfigured, no aud is emitted
	// (the verifier policy in turn tolerates absent aud per RFC 7519).
	// Binding aud to client_id like the old default would have failed
	// /mcp authentication whenever an operator set OAUTH_JWT_AUDIENCE to
	// something else, which codex flagged as a real misconfiguration
	// trap.
	var audience []string
	if s.cfg.JWTAudience != "" {
		audience = []string{s.cfg.JWTAudience}
	}
	tok, err := s.issuer.Mint(localjwt.Claims{
		Subject:          fmt.Sprintf("tg:%d", entry.TelegramID),
		TelegramID:       entry.TelegramID,
		TelegramUsername: entry.TelegramUsername,
		Groups:           groups,
		Scopes:           scopes,
		Audience:         audience,
	}, s.cfg.AccessTokenTTL)
	if err != nil {
		writeTokenError(w, "server_error", "could not mint token", http.StatusInternalServerError)
		return
	}

	resp := map[string]any{
		"access_token": tok,
		"token_type":   "Bearer",
		"expires_in":   int(s.cfg.AccessTokenTTL.Seconds()),
	}
	// Echo the *granted* scope set, not what the client asked for. A
	// non-admin who asks for "telegram:messages:send" still gets an empty
	// JWT scope set, and the token response must mirror that so the client
	// does not believe it has privileges it cannot exercise. Per RFC 6749
	// §5.1 we MUST include scope when it differs from the request, and we
	// always include it here for clarity.
	if len(scopes) > 0 {
		resp["scope"] = strings.Join(scopes, " ")
	} else {
		resp["scope"] = ""
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
		"grant_types":                []string{"authorization_code"},
		"response_types":             []string{"code"},
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

// validateImplicitRedirectURI applies the same policy as the implicit-client
// branch of validateClient. Factored out so /oauth/register can enforce it
// at registration time instead of waiting until /oauth/authorize.
func (s *Server) validateImplicitRedirectURI(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("redirect_uri %q is not a valid URL: %w", raw, err)
	}
	if u.Scheme != "https" {
		if u.Scheme != "http" || (u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1") {
			return fmt.Errorf("redirect_uri scheme %q is not allowed (must be https except for http://localhost)", u.Scheme)
		}
	}
	host := u.Hostname()
	for _, allowed := range s.cfg.AllowedImplicitHosts {
		if host == allowed {
			return nil
		}
	}
	return fmt.Errorf("redirect_uri host %q is not in the allowlist", host)
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
	// http:// is acceptable only for loopback addresses (RFC 8252 §7.3).
	if u.Scheme != "https" {
		if u.Scheme != "http" || (u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1") {
			return fmt.Errorf("redirect_uri scheme %q is not allowed (must be https except for http://localhost)", u.Scheme)
		}
	}
	host := u.Hostname()
	for _, allowed := range s.cfg.AllowedImplicitHosts {
		if host == allowed {
			return nil
		}
	}
	return fmt.Errorf("redirect_uri host %q is not in the implicit-client allowlist", host)
}

// lookupClientName is retained as a documented no-op: we never display a
// self-supplied client_name on the consent screen because /oauth/register is
// unauthenticated and would allow brand spoofing. Kept as a function so
// tests can still pin the policy.
//
// Deprecated: do not use. Render redirect_uri host instead.
func (s *Server) lookupClientName(clientID string) string {
	_ = clientID
	return ""
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
