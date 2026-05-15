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

	mu         sync.Mutex
	pending    map[string]*pendingAuth // keyed by "state" issued at /oauth/authorize
	codes      map[string]*authCode    // keyed by the authorization_code value
	clients    map[string]*clientReg   // keyed by client_id
	widgetTmps map[string]*widgetTemp  // keyed by short-lived nonce so widget POST can carry the OAuth context across requests

	// session cookies for the multi-step flow. We deliberately do not use a
	// shared secret-store; everything we need to carry across requests is
	// either in the URL (state) or in a single short-lived cookie (mctl_oauth_state).
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
	AllowedImplicitHosts []string
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

// widgetTemp lets the multi-step flow carry the OAuth context (state) from
// the authorize step through the widget POST. Keyed by a server-issued
// random nonce held in a short-lived signed cookie.
type widgetTemp struct {
	State     string
	CreatedAt time.Time
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
	issuer, err := localjwt.NewIssuer(cfg.JWTSecret, cfg.Issuer)
	if err != nil {
		return nil, err
	}
	v, err := telegramwidget.New(cfg.BotToken)
	if err != nil {
		return nil, err
	}
	return &Server{
		cfg:        cfg,
		issuer:     issuer,
		verifier:   v,
		store:      store,
		clock:      time.Now,
		pending:    map[string]*pendingAuth{},
		codes:      map[string]*authCode{},
		clients:    map[string]*clientReg{},
		widgetTmps: map[string]*widgetTemp{},
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
	for k, w := range s.widgetTmps {
		if now.Sub(w.CreatedAt) > s.cfg.CodeTTL {
			delete(s.widgetTmps, k)
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
	mux.Post("/oauth/telegram/callback", s.handleWidgetCallback)
	mux.Get("/oauth/telegram/callback", s.handleWidgetCallback) // widget can issue either; accept both
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
	if err := s.validateClient(clientID, redirectURI); err != nil {
		s.writeAuthorizeError(w, "invalid_client", err.Error())
		return
	}

	// Persist pending state, indexed by a fresh random server-side state token.
	// We DO NOT trust the client-supplied state — that survives only as a
	// pass-through value the widget callback echoes back on redirect.
	serverState := randomToken(32)
	s.mu.Lock()
	s.pending[serverState] = &pendingAuth{
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		State:               state,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		Scope:               scope,
		CreatedAt:           s.clock(),
	}
	s.mu.Unlock()

	// Render the widget HTML. The widget's `data-onauth` JS posts the signed
	// payload to /oauth/telegram/callback?st=<serverState>; we read st from
	// the form on the callback side.
	renderAuthorizeHTML(w, authorizePage{
		Issuer:      s.cfg.Issuer,
		BotUsername: s.cfg.BotUsername,
		ServerState: serverState,
		ClientName:  s.lookupClientName(clientID),
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
	tok, err := s.issuer.Mint(localjwt.Claims{
		Subject:          fmt.Sprintf("tg:%d", entry.TelegramID),
		TelegramID:       entry.TelegramID,
		TelegramUsername: entry.TelegramUsername,
		Groups:           groups,
		Scopes:           scopes,
		Audience:         []string{clientID},
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
	for _, u := range req.RedirectURIs {
		if _, err := url.Parse(u); err != nil {
			writeTokenError(w, "invalid_redirect_uri", fmt.Sprintf("redirect_uri %q is not a valid URL", u), http.StatusBadRequest)
			return
		}
	}
	clientID := "tgmcp_" + randomToken(16)
	s.mu.Lock()
	s.clients[clientID] = &clientReg{
		ClientID:     clientID,
		ClientName:   req.ClientName,
		RedirectURIs: req.RedirectURIs,
		CreatedAt:    s.clock(),
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

// lookupClientName returns a label safe to render on the consent screen.
// Registered clients get their declared name; unregistered (implicit)
// clients get a neutral "Unknown application" plus a truncated client_id so
// the user can still distinguish two simultaneous attempts. We deliberately
// do NOT default to a recognised brand like "Claude" — an attacker with an
// allowlisted redirect_uri host could otherwise craft a phishing consent
// screen by picking a client_id no one has registered.
func (s *Server) lookupClientName(clientID string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.clients[clientID]; ok && c.ClientName != "" {
		return c.ClientName
	}
	id := clientID
	if len(id) > 16 {
		id = id[:13] + "…"
	}
	return "Unknown application (" + id + ")"
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

// randomToken returns a base64url-encoded random string of approximately the
// requested byte length. Used for state tokens, codes, and client_ids.
func randomToken(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic("oauth: rand.Read failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}
