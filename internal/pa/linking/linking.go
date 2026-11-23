// Package linking is the Personal Assistant's cookie-free account-linking
// flow (issue #1314, threat model T1, test ids S1-L1..L14). It drives a
// connection of internal/pa/connection through
//
//	pending_link -> pending_oauth -> pending_return -> pending_confirm -> active
//
// in six steps:
//
//  1. StartLink (from /connect in the principal's private chat): checks the
//     server's flag (S1-L14), creates the connection and a single-use link
//     token (10 minutes) bound to the principal, and returns the Mini App
//     URL for an inline web_app button.
//  2. BeginOAuth (Mini App, POST /pa/link/begin): verifies the raw initData
//     against the PA bot's token, consumes the link token only for the user
//     it was minted for, and builds the authorization request: PKCE S256
//     with the verifier kept server-side, a 256-bit single-use state bound to
//     principal, server, connection and redirect URI (10 minutes), RFC 8707
//     resource, and prompt=consent where the server supports it.
//  3. Callback (GET /pa/oauth/callback/{server}): checks state, the redirect
//     URI and RFC 9207 iss, stores the code sealed and unexchanged
//     (pending_return), and shows a page that names the target Telegram
//     account, masked. Only after "This is my Telegram account" (Handoff,
//     POST /pa/oauth/handoff) does it show the completion link
//     t.me/<bot>/<app>?startapp=<completion code> (5 minutes from the
//     callback).
//  4. Complete (Mini App, POST /pa/link/complete): verifies initData again,
//     reads the completion code only from the signed start_param, requires
//     the opener to be the principal, then exchanges the code. The manager
//     checks the effective scope; for tg, get_my_identity must return the
//     principal's telegram_id before the connection may reach
//     pending_confirm (S1-L13).
//  5. The bot posts a confirm card with the stable account id. HandleCallback
//     activates the connection only for a callback_query from the principal
//     before the card expires (10 minutes), after making sure the principal
//     has a users row so its calls can be audited.
//
// Nothing here is mounted unless the server wires it in behind PA_ENABLED,
// and every server's linking flag is off by default.
package linking

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/pa"
	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
	"github.com/mctlhq/mctl-telegram/internal/pa/convo"
	"github.com/mctlhq/mctl-telegram/internal/pa/output/safetext"
)

// TTLs of threat model T1.
const (
	LinkTokenTTL  = 10 * time.Minute
	StateTTL      = 10 * time.Minute
	CompletionTTL = 5 * time.Minute
	ConfirmTTL    = 10 * time.Minute
)

// Store is the part of *db.Store the flow uses.
type Store interface {
	CreatePALinkSecret(ctx context.Context, l db.PALinkSecret, now time.Time) error
	ConsumePALinkSecret(ctx context.Context, kind db.PALinkKind, hash string, now time.Time, check func(db.PALinkSecret) error) (db.PALinkSecret, error)
	ExpiredPALinkSecrets(ctx context.Context, kind db.PALinkKind, now time.Time, limit int) ([]db.PALinkSecret, error)
	RetirePALinkSecret(ctx context.Context, kind db.PALinkKind, hash string, now time.Time) error
	StalePendingPAConnections(ctx context.Context, updatedBefore time.Time, limit int) ([]db.StalePAConnection, error)
	EnsurePAUser(ctx context.Context, tgID int64) (int64, error)
	// ReadPAConsent is convo.Store's GetPAConsent in its own transaction:
	// convo.ErrNotFound only when no row exists.
	ReadPAConsent(ctx context.Context, principal int64) (convo.ConsentRecord, error)
	// PAPrincipalDisabledState reads an admin's disable of principal
	// (#1318 A1). Any error refuses.
	PAPrincipalDisabledState(ctx context.Context, principal int64) (bool, error)
}

// Allowlist is the preview allowlist (PA_ALLOWED_PRINCIPALS, *pa.Allowlist).
type Allowlist interface {
	Allowed(principal int64) bool
}

var _ Store = (*db.Store)(nil)

// ExchangeRequest is one authorization-code grant (RFC 6749 4.1.3 with PKCE
// and RFC 8707 resource).
type ExchangeRequest struct {
	TokenEndpoint string
	ClientID      string
	RedirectURI   string
	Resource      string
	Code          connection.Secret
	Verifier      connection.Secret
}

// TokenClient performs the code exchange and returns the raw token response
// for the manager to check. Production builds it on an internal/pa/egress
// client (see FormTokenClient).
type TokenClient interface {
	ExchangeCode(ctx context.Context, server connection.Server, req ExchangeRequest) ([]byte, error)
}

// Account is what a server's pinned identity source says about a token.
type Account struct {
	// ID is the stable, unique account identifier (an account id or a masked
	// login). It is what the confirm card shows.
	ID string
	// TelegramID is the account's Telegram user id, for servers whose
	// accounts are Telegram identities (tg's get_my_identity). Zero
	// elsewhere.
	TelegramID int64
	// DisplayName is the server's display name. It is never shown on the
	// confirm card: a display name can be set to anything (S1-L10).
	DisplayName string
}

// AccountSource reads the account behind a new access token. For tg it
// calls get_my_identity through the executor (#1315); the call runs with
// the token that was just issued and nothing else.
type AccountSource interface {
	Account(ctx context.Context, server connection.Server, accessToken connection.Secret) (Account, error)
}

// Button is one inline keyboard button of a card.
type Button struct {
	Label string
	Data  string
}

// Card is a plain-text bot message with an inline keyboard.
type Card struct {
	Text string
	// TextRU is Text in Russian, sent to a principal whose Telegram client
	// is in Russian; "" sends Text to everyone.
	TextRU  string
	Buttons []Button
}

// Messenger sends a card to the principal's private chat. It is the seam to
// the PA output Sender of #1313 slice (c), which applies the output
// hardening of T14; this package builds no Bot API client of its own.
type Messenger interface {
	SendCard(ctx context.Context, chatID int64, card Card) error
}

// ServerConfig is one catalog server's OAuth client registration and
// linking flag.
type ServerConfig struct {
	// Enabled is PA_SERVER_<NAME>_ENABLED. For a server without a
	// Telegram-bound identity (alice) it may only be turned on after the
	// owner has recorded acceptance of the T1 residual risk (S1-L14).
	Enabled bool
	// Issuer is the one pinned issuer (RFC 9207 iss must equal it).
	Issuer string
	// RequireIss: the server sends iss on every callback, so a callback
	// without it is refused. It is derived from Metadata: set here it can
	// only add the requirement, never remove it.
	RequireIss bool
	// Metadata is the server's authorization server metadata
	// (FetchASMetadata), required for an enabled server: an enabled server
	// without it, or with metadata of another issuer, is refused at New and
	// on every request. RequireIss is true whenever it says the server
	// sends iss (#1338).
	Metadata              *ASMetadata
	AuthorizationEndpoint string
	TokenEndpoint         string
	ClientID              string
	// RedirectURI is the exact redirect URI registered for this server; it
	// ends in /pa/oauth/callback/<server>.
	RedirectURI string
	// Resource is the RFC 8707 resource indicator.
	Resource string
	// PromptConsent: the server supports prompt=consent.
	PromptConsent bool
}

// Config builds a Service.
type Config struct {
	// BotToken is the PA bot's token: initData is verified against it and
	// nothing else.
	BotToken string
	// LoginBotToken is the login bot's token. It is only used to refuse a
	// configuration in which the two are the same.
	LoginBotToken string
	// BotUsername and MiniAppName form the completion deep link
	// https://t.me/<BotUsername>/<MiniAppName>?startapp=<code>.
	BotUsername string
	MiniAppName string
	// AppURL is the Mini App page URL (…/pa/link/app).
	AppURL string

	Servers   map[connection.Server]ServerConfig
	Manager   *connection.Manager
	Store     Store
	Tokens    TokenClient
	Accounts  AccountSource
	Messenger Messenger
	// Allowed is the preview allowlist the webhook and the run loop use.
	// Required: every step of the flow refuses a principal not on it, or
	// one an admin disabled, the same way the webhook refuses its updates.
	Allowed Allowlist
	// Now defaults to time.Now.
	Now func() time.Time
}

// Service runs the flow.
type Service struct {
	cfg Config
	now func() time.Time
}

// Errors. Each is a refusal; none carries a secret or a user value.
var (
	ErrConfig         = errors.New("pa linking: invalid config")
	ErrServerDisabled = errors.New("pa linking: linking is disabled for this server")
	ErrWrongUser      = errors.New("pa linking: opened by a different Telegram user")
	ErrRefused        = errors.New("pa linking: refused")
	ErrNotOwner       = errors.New("pa linking: the account does not belong to the principal")
	// ErrNoConsent: the principal has no current data-flow consent (it
	// was withdrawn after /connect, or cannot be read), so a link is not
	// activated.
	ErrNoConsent = errors.New("pa linking: no current consent")
	// ErrPrincipalRefused: the principal is not on the preview allowlist,
	// or an admin disabled it, or its disable could not be read.
	ErrPrincipalRefused = errors.New("pa linking: principal refused")
)

// New validates cfg.
func New(cfg Config) (*Service, error) {
	switch {
	case cfg.BotToken == "":
		return nil, fmt.Errorf("%w: no PA bot token", ErrConfig)
	case cfg.BotToken == cfg.LoginBotToken:
		return nil, fmt.Errorf("%w: the PA bot token must not be the login bot's", ErrConfig)
	case cfg.BotUsername == "" || cfg.MiniAppName == "" || cfg.AppURL == "":
		return nil, fmt.Errorf("%w: bot username, Mini App name and app URL are required", ErrConfig)
	case cfg.Manager == nil || cfg.Store == nil || cfg.Tokens == nil || cfg.Accounts == nil || cfg.Messenger == nil:
		return nil, fmt.Errorf("%w: manager, store, token client, account source and messenger are required", ErrConfig)
	case cfg.Allowed == nil:
		return nil, fmt.Errorf("%w: the principal allowlist is required", ErrConfig)
	}
	for name, sc := range cfg.Servers {
		if !name.Valid() {
			return nil, fmt.Errorf("%w: unknown server %q", ErrConfig, name)
		}
		if !sc.Enabled {
			continue
		}
		if sc.Issuer == "" || sc.AuthorizationEndpoint == "" || sc.TokenEndpoint == "" || sc.ClientID == "" ||
			sc.Resource == "" || !strings.HasSuffix(sc.RedirectURI, "/pa/oauth/callback/"+string(name)) {
			return nil, fmt.Errorf("%w: server %s is enabled without a complete registration", ErrConfig, name)
		}
		if _, err := withMetadata(name, sc); err != nil {
			return nil, err
		}
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Service{cfg: cfg, now: now}, nil
}

// admitted refuses, fail-closed, a principal the webhook would refuse: one
// not on the allowlist, one an admin disabled, and one whose disable
// cannot be read. The linking HTTP routes and the post-commit steps do not
// pass through the webhook's gate, so every step that acts for a principal
// checks it here.
func (s *Service) admitted(ctx context.Context, principal int64) error {
	if principal <= 0 || !s.cfg.Allowed.Allowed(principal) {
		return ErrPrincipalRefused
	}
	disabled, err := s.cfg.Store.PAPrincipalDisabledState(ctx, principal)
	if err != nil {
		return fmt.Errorf("%w: disable unreadable: %w", ErrPrincipalRefused, err)
	}
	if disabled {
		return ErrPrincipalRefused
	}
	return nil
}

// refuseLink fails, and revokes any tokens of, the connection behind l
// when its principal is no longer admitted.
func (s *Service) refuseLink(ctx context.Context, l db.PALinkSecret, err error) error {
	_, aerr := s.cfg.Manager.Abandon(ctx, l.Principal, l.ConnectionID, l.Revision, "principal_refused")
	return errors.Join(err, aerr)
}

// server returns the config of an enabled server, or ErrServerDisabled. A
// server absent from the config is disabled. The config is checked against
// its metadata on every call, not only at New: the map may change after.
func (s *Service) server(name connection.Server) (ServerConfig, error) {
	sc, ok := s.cfg.Servers[name]
	if !ok || !sc.Enabled || !name.Valid() {
		return ServerConfig{}, ErrServerDisabled
	}
	return withMetadata(name, sc)
}

// withMetadata returns sc with RequireIss derived from its metadata, or
// ErrConfig when it has none for its issuer.
func withMetadata(name connection.Server, sc ServerConfig) (ServerConfig, error) {
	if sc.Metadata == nil || sc.Metadata.Issuer == "" || sc.Metadata.Issuer != sc.Issuer {
		return ServerConfig{}, fmt.Errorf("%w: server %s has no authorization server metadata for its issuer", ErrConfig, name)
	}
	if sc.Metadata.IssParameterSupported {
		sc.RequireIss = true
	}
	return sc, nil
}

// newSecret returns a 256-bit random value, base64url without padding (43
// characters, valid in a startapp parameter and in callback_data), and its
// storage hash.
func newSecret() (string, string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("pa linking: random: %w", err)
	}
	v := base64.RawURLEncoding.EncodeToString(b)
	return v, hashSecret(v), nil
}

func hashSecret(v string) string {
	h := sha256.Sum256([]byte(v))
	return hex.EncodeToString(h[:])
}

// wellFormed reports whether v looks like a value newSecret made, so junk is
// refused before any store lookup.
func wellFormed(v string) bool {
	if len(v) != 43 {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(v)
	return err == nil
}

// StartLink is /connect <server> (T1 step 1, first half). It refuses a
// server whose flag is off before creating anything (S1-L14), then creates
// a new connection and a link token bound to the principal, and returns the
// Mini App URL for an inline web_app button. The principal comes from a
// verified update.
func (s *Service) StartLink(ctx context.Context, principal pa.Principal, server connection.Server) (string, error) {
	if principal.IsZero() {
		return "", ErrRefused
	}
	if _, err := s.server(server); err != nil {
		return "", err
	}
	p := principal.TelegramID()
	if err := s.admitted(ctx, p); err != nil {
		return "", err
	}
	c, err := s.cfg.Manager.Begin(ctx, p, server)
	if err != nil {
		return "", err
	}
	tok, hash, err := newSecret()
	if err != nil {
		return "", err
	}
	now := s.now()
	if err := s.cfg.Store.CreatePALinkSecret(ctx, db.PALinkSecret{
		Hash: hash, Kind: db.PALinkToken, Principal: p, Server: string(server),
		ConnectionID: c.ID, Revision: c.AuthorityRevision, ExpiresAt: now.Add(LinkTokenTTL),
	}, now); err != nil {
		return "", err
	}
	u, err := url.Parse(s.cfg.AppURL)
	if err != nil {
		return "", fmt.Errorf("%w: app URL", ErrConfig)
	}
	q := u.Query()
	q.Set("link", tok)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// consume consumes a secret, mapping an expired one to the connection
// cleanup the caller wants and every store sentinel to ErrRefused.
func (s *Service) consume(ctx context.Context, kind db.PALinkKind, value string, check func(db.PALinkSecret) error) (db.PALinkSecret, error) {
	if !wellFormed(value) {
		return db.PALinkSecret{}, ErrRefused
	}
	l, err := s.cfg.Store.ConsumePALinkSecret(ctx, kind, hashSecret(value), s.now(), check)
	switch {
	case err == nil:
		return l, nil
	case errors.Is(err, db.ErrPALinkUnknown), errors.Is(err, db.ErrPALinkConsumed):
		return db.PALinkSecret{}, fmt.Errorf("%w: %w", ErrRefused, err)
	case errors.Is(err, db.ErrPALinkExpired):
		return l, fmt.Errorf("%w: %w", ErrRefused, err)
	}
	return db.PALinkSecret{}, err
}

// BeginOAuth is T1 step 1, second half: the Mini App posts the raw initData
// and the link token; the result is the authorization URL the Mini App
// opens.
func (s *Service) BeginOAuth(ctx context.Context, rawInitData, linkToken string) (string, error) {
	id, err := VerifyInitData(rawInitData, s.cfg.BotToken, s.now())
	if err != nil {
		return "", err
	}
	// Refused before the token is consumed: nothing changes, and the
	// linking sweep fails the pending connection.
	if err := s.admitted(ctx, id.UserID); err != nil {
		return "", err
	}
	l, err := s.consume(ctx, db.PALinkToken, linkToken, func(l db.PALinkSecret) error {
		if l.Principal != id.UserID {
			return ErrWrongUser // S1-L3; the token stays usable by its principal
		}
		_, err := s.server(connection.Server(l.Server))
		return err
	})
	if err != nil {
		return "", err
	}
	server := connection.Server(l.Server)
	sc, err := s.server(server)
	if err != nil {
		return "", err
	}
	c, err := s.cfg.Manager.StartOAuth(ctx, l.Principal, l.ConnectionID, l.Revision)
	if err != nil {
		return "", err
	}
	state, stateHash, err := newSecret()
	if err != nil {
		return "", err
	}
	verifier, _, err := newSecret()
	if err != nil {
		return "", err
	}
	now := s.now()
	if err := s.cfg.Store.CreatePALinkSecret(ctx, db.PALinkSecret{
		Hash: stateHash, Kind: db.PALinkState, Principal: l.Principal, Server: l.Server,
		ConnectionID: c.ID, Revision: c.AuthorityRevision, Verifier: verifier, RedirectURI: sc.RedirectURI,
		AccountHint: maskAccount(id), ExpiresAt: now.Add(StateTTL),
	}, now); err != nil {
		return "", err
	}
	return authorizationURL(sc, server, state, verifier)
}

func authorizationURL(sc ServerConfig, server connection.Server, state, verifier string) (string, error) {
	u, err := url.Parse(sc.AuthorizationEndpoint)
	if err != nil || u.Scheme != "https" {
		return "", fmt.Errorf("%w: authorization endpoint", ErrConfig)
	}
	scope, _ := connection.CanonicalScope(server)
	ch := sha256.Sum256([]byte(verifier))
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", sc.ClientID)
	q.Set("redirect_uri", sc.RedirectURI)
	q.Set("scope", scope)
	q.Set("state", state)
	q.Set("code_challenge", base64.RawURLEncoding.EncodeToString(ch[:]))
	q.Set("code_challenge_method", "S256")
	q.Set("resource", sc.Resource)
	if sc.PromptConsent {
		q.Set("prompt", "consent")
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// maskAccount renders the Telegram account the callback page names: the
// first letter of the first name and the last three digits of the id. It
// is enough for the owner to recognise, and little for anyone else.
func maskAccount(id InitData) string {
	first := "?"
	if r, size := utf8.DecodeRuneInString(id.FirstName); size > 0 && r != utf8.RuneError {
		first = string(r)
	}
	digits := strconv.FormatInt(id.UserID, 10)
	if len(digits) > 3 {
		digits = digits[len(digits)-3:]
	}
	return first + "*** (id ending " + digits + ")"
}

// CallbackResult is what the callback page shows.
type CallbackResult struct {
	Server connection.Server
	// AccountHint is the masked Telegram account the server account will be
	// linked to.
	AccountHint string
	// Handoff is the single-use value behind "This is my Telegram account".
	Handoff string
}

// Callback is T1 step 3. query is the callback's raw query; server is the
// {server} path segment, which selects the redirect URI the request
// arrived on.
//
// It refuses (S1-L5) a repeated parameter, an unknown, used or expired
// state, a state minted for another server or redirect URI, and an iss that
// is not the pinned issuer (or is missing where the server always sends
// it). None of those refusals consumes the state. On success the code is
// sealed unexchanged (pending_return).
func (s *Service) Callback(ctx context.Context, server connection.Server, query url.Values) (CallbackResult, error) {
	sc, err := s.server(server)
	if err != nil {
		return CallbackResult{}, err
	}
	for _, k := range []string{"state", "code", "iss", "error"} {
		if len(query[k]) > 1 {
			return CallbackResult{}, ErrRefused
		}
	}
	iss := query.Get("iss")
	if (iss == "" && sc.RequireIss) || (iss != "" && iss != sc.Issuer) {
		return CallbackResult{}, fmt.Errorf("%w: issuer", ErrRefused)
	}
	providerErr := query.Get("error") != ""
	code := query.Get("code")
	if !providerErr && code == "" {
		return CallbackResult{}, ErrRefused
	}
	l, err := s.consume(ctx, db.PALinkState, query.Get("state"), func(l db.PALinkSecret) error {
		if l.Server != string(server) || l.RedirectURI != sc.RedirectURI {
			return fmt.Errorf("%w: state minted for another redirect", ErrRefused)
		}
		return nil
	})
	if err != nil {
		return CallbackResult{}, err
	}
	if err := s.admitted(ctx, l.Principal); err != nil {
		return CallbackResult{}, s.refuseLink(ctx, l, err)
	}
	if providerErr {
		// The user declined, or the server failed: this attempt is over.
		_, _ = s.cfg.Manager.Abandon(ctx, l.Principal, l.ConnectionID, l.Revision, "provider_error")
		return CallbackResult{}, fmt.Errorf("%w: the server returned an error", ErrRefused)
	}
	c, err := s.cfg.Manager.StoreAuthorizationCode(ctx, l.Principal, l.ConnectionID, l.Revision, connection.NewSecret(code))
	if err != nil {
		return CallbackResult{}, err
	}
	handoff, hash, err := newSecret()
	if err != nil {
		return CallbackResult{}, err
	}
	now := s.now()
	if err := s.cfg.Store.CreatePALinkSecret(ctx, db.PALinkSecret{
		Hash: hash, Kind: db.PALinkHandoff, Principal: l.Principal, Server: l.Server,
		ConnectionID: c.ID, Revision: c.AuthorityRevision, Verifier: l.Verifier,
		AccountHint: l.AccountHint, ExpiresAt: now.Add(CompletionTTL),
	}, now); err != nil {
		return CallbackResult{}, err
	}
	return CallbackResult{Server: server, AccountHint: l.AccountHint, Handoff: handoff}, nil
}

// Handoff is the callback page's "This is my Telegram account" button. It
// consumes the handoff value and mints the completion code, which expires
// with the handoff (five minutes after the callback). It returns the
// Mini App deep link carrying the code.
func (s *Service) Handoff(ctx context.Context, handoff string) (string, connection.Server, error) {
	l, err := s.consume(ctx, db.PALinkHandoff, handoff, nil)
	if err != nil {
		return "", "", err
	}
	if err := s.admitted(ctx, l.Principal); err != nil {
		return "", "", s.refuseLink(ctx, l, err)
	}
	if _, err := s.server(connection.Server(l.Server)); err != nil {
		return "", "", err
	}
	code, hash, err := newSecret()
	if err != nil {
		return "", "", err
	}
	if err := s.cfg.Store.CreatePALinkSecret(ctx, db.PALinkSecret{
		Hash: hash, Kind: db.PALinkCompletion, Principal: l.Principal, Server: l.Server,
		ConnectionID: l.ConnectionID, Revision: l.Revision, Verifier: l.Verifier, ExpiresAt: l.ExpiresAt,
	}, s.now()); err != nil {
		return "", "", err
	}
	link := "https://t.me/" + url.PathEscape(s.cfg.BotUsername) + "/" + url.PathEscape(s.cfg.MiniAppName) +
		"?startapp=" + code
	return link, connection.Server(l.Server), nil
}

// Callback data of the confirm card. The value after the prefix is the
// confirm secret (43 characters), so the whole string fits Telegram's
// 64-byte callback_data limit.
const (
	confirmPrefix = "pa:lc:"
	cancelPrefix  = "pa:lx:"
)

// Complete is T1 step 4 and 6. The Mini App posts only the raw initData:
// the completion code is read from its signed start_param and from nowhere
// else (S1-L12). The opener must be the principal the code was minted for
// (S1-L6); a different user neither exchanges nor burns the code.
func (s *Service) Complete(ctx context.Context, rawInitData string) error {
	id, err := VerifyInitData(rawInitData, s.cfg.BotToken, s.now())
	if err != nil {
		return err
	}
	if id.StartParam == "" {
		return fmt.Errorf("%w: no completion code in start_param", ErrRefused)
	}
	// Refused before the code is consumed or exchanged; the linking sweep
	// fails the pending connection.
	if err := s.admitted(ctx, id.UserID); err != nil {
		return err
	}
	l, err := s.consume(ctx, db.PALinkCompletion, id.StartParam, func(l db.PALinkSecret) error {
		if l.Principal != id.UserID {
			return ErrWrongUser
		}
		_, err := s.server(connection.Server(l.Server))
		return err
	})
	if err != nil {
		return err
	}
	server := connection.Server(l.Server)
	sc, err := s.server(server)
	if err != nil {
		return err
	}
	m := s.cfg.Manager
	code, err := m.AuthorizationCode(ctx, l.Principal, l.ConnectionID)
	if err != nil {
		return err
	}
	raw, err := s.cfg.Tokens.ExchangeCode(ctx, server, ExchangeRequest{
		TokenEndpoint: sc.TokenEndpoint, ClientID: sc.ClientID, RedirectURI: sc.RedirectURI,
		Resource: sc.Resource, Code: code, Verifier: connection.NewSecret(l.Verifier),
	})
	if err != nil {
		// Whatever the server did, this attempt is over; nothing was issued
		// that MCTL holds.
		_, ferr := m.Abandon(ctx, l.Principal, l.ConnectionID, l.Revision, "exchange_failed")
		return errors.Join(fmt.Errorf("pa linking: code exchange: %w", err), ferr)
	}
	c, err := m.CompleteExchangeWith(ctx, l.Principal, l.ConnectionID, l.Revision, raw, s.resolver(l.Principal))
	if err != nil {
		if errors.Is(err, connection.ErrUnreadable) || errors.Is(err, connection.ErrNotFound) {
			// The CompleteExchange contract: with the row unreadable the
			// manager could not revoke what was issued; this caller knows the
			// server and does.
			err = errors.Join(err, m.RevokeTokenResponse(ctx, server, raw))
		}
		return err
	}
	return s.sendConfirmCard(ctx, c)
}

// resolver is the account check run on the new token before anything is
// stored. For tg it is the T1 step 6 owner binding: the identity's
// telegram_id must be the principal's.
func (s *Service) resolver(principal int64) connection.AccountResolver {
	return func(ctx context.Context, server connection.Server, ts connection.TokenSet) (string, error) {
		acct, err := s.cfg.Accounts.Account(ctx, server, ts.AccessToken)
		if err != nil {
			return "", fmt.Errorf("pa linking: account source: %w", err)
		}
		if server == connection.ServerTG {
			if acct.TelegramID <= 0 || acct.TelegramID != principal {
				return "", ErrNotOwner
			}
			return "telegram:" + strconv.FormatInt(acct.TelegramID, 10), nil
		}
		return acct.ID, nil
	}
}

func (s *Service) sendConfirmCard(ctx context.Context, c connection.Connection) error {
	nonce, hash, err := newSecret()
	if err != nil {
		return err
	}
	now := s.now()
	if err := s.cfg.Store.CreatePALinkSecret(ctx, db.PALinkSecret{
		Hash: hash, Kind: db.PALinkConfirm, Principal: c.Principal, Server: string(c.Server),
		ConnectionID: c.ID, Revision: c.AuthorityRevision, ExpiresAt: now.Add(ConfirmTTL),
	}, now); err != nil {
		_, aerr := s.cfg.Manager.Abandon(ctx, c.Principal, c.ID, c.AuthorityRevision, "confirm_card")
		return errors.Join(err, aerr)
	}
	card := ConfirmCard(c.Server, c.AccountID, nonce)
	if err := s.cfg.Messenger.SendCard(ctx, c.Principal, card); err != nil {
		_, aerr := s.cfg.Manager.Abandon(ctx, c.Principal, c.ID, c.AuthorityRevision, "confirm_card")
		return errors.Join(fmt.Errorf("pa linking: confirm card: %w", err), aerr)
	}
	return nil
}

// ConfirmCard is the T1 step 5 card. It names the server and the stable
// account id; it never takes a display name (S1-L10).
func ConfirmCard(server connection.Server, accountID, nonce string) Card {
	return Card{
		Text: "Link this " + server.Label() + " account to the assistant?\n\nAccount: " + accountID +
			"\n\nConfirm only if this is your account. Nothing is linked until you do.",
		TextRU: "Подключить этот аккаунт " + server.LabelRU() + " к ассистенту?\n\nАккаунт: " + accountID +
			"\n\nПодтвердите, только если это ваш аккаунт. Пока вы не подтвердите, ничего не подключается.",
		Buttons: []Button{
			{Label: safetext.LabelConfirm.String(), Data: confirmPrefix + nonce},
			{Label: safetext.LabelCancel.String(), Data: cancelPrefix + nonce},
		},
	}
}

// HandleCallback handles a confirm card button. handled is false for a
// callback that is not a linking button, so the caller can route it
// elsewhere.
//
// The button counts only when pressed by the principal the card was sent
// to, before it expires (S1-L9). A press by anyone else changes nothing.
// An expired card fails the connection and revokes its tokens. A confirm
// needs the principal's current consent: /consent withdraw between
// /connect and the press, or a consent row that cannot be read, fails the
// connection and revokes its tokens instead (ErrNoConsent). Before
// activating, the principal gets a users row (EnsurePAUser) so its calls
// can be audited; if that fails, the connection is not activated.
func (s *Service) HandleCallback(ctx context.Context, u pa.VerifiedUpdate) (bool, error) {
	if u.Kind() != pa.KindCallbackQuery {
		return false, nil
	}
	data := u.CallbackData()
	var confirm bool
	var nonce string
	switch {
	case strings.HasPrefix(data, confirmPrefix):
		confirm, nonce = true, strings.TrimPrefix(data, confirmPrefix)
	case strings.HasPrefix(data, cancelPrefix):
		nonce = strings.TrimPrefix(data, cancelPrefix)
	default:
		return false, nil
	}
	from := u.Principal().TelegramID()
	l, err := s.consume(ctx, db.PALinkConfirm, nonce, func(l db.PALinkSecret) error {
		if l.Principal != from {
			return ErrWrongUser
		}
		return nil
	})
	if errors.Is(err, db.ErrPALinkExpired) {
		if l.Principal == from && l.ConnectionID != "" {
			_, aerr := s.cfg.Manager.Abandon(ctx, l.Principal, l.ConnectionID, l.Revision, "confirm_expired")
			_ = s.cfg.Store.RetirePALinkSecret(ctx, db.PALinkConfirm, hashSecret(nonce), s.now())
			return true, errors.Join(err, aerr)
		}
		return true, err
	}
	if err != nil {
		return true, err
	}
	if !confirm {
		_, err := s.cfg.Manager.Abandon(ctx, l.Principal, l.ConnectionID, l.Revision, "cancelled")
		return true, err
	}
	if !s.enabled(connection.Server(l.Server)) {
		_, aerr := s.cfg.Manager.Abandon(ctx, l.Principal, l.ConnectionID, l.Revision, "server_disabled")
		return true, errors.Join(ErrServerDisabled, aerr)
	}
	if err := s.admitted(ctx, l.Principal); err != nil {
		return true, s.refuseLink(ctx, l, err)
	}
	if err := s.consented(ctx, l.Principal); err != nil {
		_, aerr := s.cfg.Manager.Abandon(ctx, l.Principal, l.ConnectionID, l.Revision, "no_consent")
		return true, errors.Join(err, aerr)
	}
	if _, err := s.cfg.Store.EnsurePAUser(ctx, l.Principal); err != nil {
		_, aerr := s.cfg.Manager.Abandon(ctx, l.Principal, l.ConnectionID, l.Revision, "unauditable")
		return true, errors.Join(fmt.Errorf("pa linking: users row: %w", err), aerr)
	}
	// The check above keeps a principal without consent from getting a
	// users row; the activation itself checks again under the principal
	// lock, so a /consent withdraw that commits in between still refuses
	// it (connection.ErrNoConsent).
	_, err = s.cfg.Manager.Confirm(ctx, l.Principal, l.ConnectionID, l.Revision)
	if errors.Is(err, connection.ErrNoConsent) {
		_, aerr := s.cfg.Manager.Abandon(ctx, l.Principal, l.ConnectionID, l.Revision, "no_consent")
		return true, errors.Join(ErrNoConsent, err, aerr)
	}
	// An admin disable that commits after admitted above, or one that
	// cannot be read, refuses the activation under the same lock (#1318).
	if errors.Is(err, connection.ErrPrincipalDisabled) {
		return true, s.refuseLink(ctx, l, errors.Join(ErrPrincipalRefused, err))
	}
	return true, err
}

// consented fails closed: only a readable, current, accepted consent row
// is consent.
func (s *Service) consented(ctx context.Context, principal int64) error {
	rec, err := s.cfg.Store.ReadPAConsent(ctx, principal)
	switch {
	case errors.Is(err, convo.ErrNotFound):
		return ErrNoConsent
	case err != nil:
		return fmt.Errorf("%w: consent unreadable: %w", ErrNoConsent, err)
	case !convo.Satisfied(rec):
		return ErrNoConsent
	}
	return nil
}

// AbandonPending fails, and revokes the tokens of, every pending connection
// of principal: a link it started and may no longer finish (/forget or
// /consent withdraw, pa.LinkAction.Retire). A connection that moved on in
// the meantime is left alone. Every other failure is returned; the linking
// sweep fails what is left once it is PendingMaxAge old.
func (s *Service) AbandonPending(ctx context.Context, principal int64) (int, error) {
	conns, err := s.cfg.Manager.List(ctx, principal)
	if err != nil {
		return 0, err
	}
	var errs []error
	n := 0
	for _, c := range conns {
		// Abandon refuses anything but a pending connection at this
		// revision with ErrConflict, so an active or terminal connection
		// is never touched here.
		out, err := s.cfg.Manager.Abandon(ctx, principal, c.ID, c.AuthorityRevision, "link_retired")
		switch {
		case err == nil:
			n++
			if out.RemoteErr != nil {
				errs = append(errs, out.RemoteErr)
			}
		case errors.Is(err, connection.ErrConflict), errors.Is(err, connection.ErrNotFound):
		default:
			errs = append(errs, err)
		}
	}
	return n, errors.Join(errs...)
}

func (s *Service) enabled(server connection.Server) bool {
	_, err := s.server(server)
	return err == nil
}

// PendingMaxAge is how long a connection may stay in one pending_* state
// before the sweep fails it. Every pending state is bounded by a secret
// that lives at most ten minutes (LinkTokenTTL, StateTTL, ConfirmTTL); the
// margin covers clock skew between replicas.
const PendingMaxAge = 15 * time.Minute

// SweepResult counts what ExpireStale did.
type SweepResult struct {
	// Failed connections were moved to failed and their tokens revoked.
	Failed int
	// Skipped connections had moved on (or were gone) by the time of the
	// sweep.
	Skipped int
	// Errors counts connections the sweep could not observe or fail. They
	// are left for the next sweep; they do not stop this one.
	Errors int
}

// ExpireStale fails, and revokes any tokens of, every connection the
// linking flow abandoned. It runs two passes:
//
//  1. every secret that expired unused (an abandoned Mini App, callback page
//     or confirm card): its connection is failed and the secret retired, so
//     it is listed once;
//  2. every connection still pending PendingMaxAge after its last
//     transition, whatever its secrets say. This catches a row stranded by
//     a store or KEK error after its secret was already consumed (for
//     example a Confirm whose activation write failed), which pass 1 cannot
//     see.
//
// A connection that cannot be observed or failed is counted in Errors,
// logged, and left for the next sweep; the sweep continues past it, and the
// returned error joins every such failure. The caller runs it periodically;
// it does nothing on its own.
func (s *Service) ExpireStale(ctx context.Context, limit int) (SweepResult, error) {
	var res SweepResult
	var errs []error
	now := s.now()
	abandon := func(principal int64, id string, rev int64, reason string) bool {
		out, err := s.cfg.Manager.Abandon(ctx, principal, id, rev, reason)
		switch {
		case err == nil:
			res.Failed++
			if out.RemoteErr != nil {
				// Failed locally, so never usable again; the remote revocation
				// did not go through and needs an operator.
				slog.WarnContext(ctx, "pa linking sweep: remote revocation failed", "reason", reason, "error", out.RemoteErr)
			}
		case errors.Is(err, connection.ErrConflict), errors.Is(err, connection.ErrNotFound):
			res.Skipped++
		default:
			// Could not observe or fail the connection: count it, keep its
			// secret listed for the next sweep, and go on.
			res.Errors++
			errs = append(errs, err)
			slog.WarnContext(ctx, "pa linking sweep: connection not failed", "reason", reason, "error", err)
			return false
		}
		return true
	}
	for _, kind := range []db.PALinkKind{db.PALinkToken, db.PALinkState, db.PALinkHandoff, db.PALinkCompletion, db.PALinkConfirm} {
		stale, err := s.cfg.Store.ExpiredPALinkSecrets(ctx, kind, now, limit)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for _, l := range stale {
			if !abandon(l.Principal, l.ConnectionID, l.Revision, "link_expired") {
				continue
			}
			if err := s.cfg.Store.RetirePALinkSecret(ctx, kind, l.Hash, now); err != nil {
				errs = append(errs, err)
			}
		}
	}
	pending, err := s.cfg.Store.StalePendingPAConnections(ctx, now.Add(-PendingMaxAge), limit)
	if err != nil {
		errs = append(errs, err)
	}
	for _, c := range pending {
		abandon(c.Principal, c.ID, c.AuthorityRevision, "pending_stale")
	}
	return res, errors.Join(errs...)
}
