// Package telegramoidc makes mctl-telegram an OpenID Connect Relying Party to
// Telegram's OpenID Provider (https://oauth.telegram.org). It is the standards-
// based replacement for the legacy Telegram Login Widget: instead of verifying
// an HMAC-signed widget callback, the broker runs an Authorization Code + PKCE
// flow and validates a JWKS-signed id_token.
//
// The package exposes an Authenticator interface so internal/oauth depends on
// behaviour rather than on the go-oidc/oauth2 libraries — the same stub seam
// the widget verifier provided, which keeps the OAuth server unit-testable
// without network access.
package telegramoidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// DefaultIssuerURL is Telegram's OpenID Provider. OIDC discovery is performed
// against {issuer}/.well-known/openid-configuration.
const DefaultIssuerURL = "https://oauth.telegram.org"

// clockSkew tolerates minor clock drift between this service and Telegram when
// checking id_token expiry. Telegram issues very short-lived id_tokens
// (~30s, observed in spike #48), so the broker must exchange and verify
// promptly — but a couple of minutes of pod/NTP drift must not turn into
// spurious authentication failures.
const clockSkew = 2 * time.Minute

// scopes are requested from Telegram on every authorization request.
// `telegram:bot_access` preserves the legacy widget's data-request-access=write
// capability (the login bot may message the user); it must be enabled for the
// OIDC client in BotFather or Telegram rejects the authorization request.
var scopes = []string{oidc.ScopeOpenID, "profile", "telegram:bot_access"}

// Identity is the authenticated Telegram user extracted from a verified
// id_token. TelegramID is the numeric Telegram user id — the value the legacy
// widget delivered as `id` and the value EnsureUserByTelegramID keys on. Sub
// is the OIDC subject: an opaque, provider-scoped identifier distinct from
// TelegramID, retained for the sub-only contingency but unused on the primary
// path.
type Identity struct {
	TelegramID int64
	Sub        string
	Username   string
	FirstName  string
	LastName   string
}

// Authenticator is the behaviour internal/oauth depends on. A real *Client
// talks to Telegram; tests inject a fake.
type Authenticator interface {
	// AuthCodeURL builds the URL to redirect the user's browser to Telegram's
	// authorization endpoint. state, nonce and codeChallenge are generated and
	// stored by the caller; codeChallenge is the S256 challenge of the
	// Telegram-leg PKCE verifier — distinct from the MCP client's own PKCE.
	AuthCodeURL(state, nonce, codeChallenge string) string
	// Exchange completes the flow: it swaps the authorization code for tokens,
	// verifies the id_token (signature via JWKS, iss, aud, expiry) and checks
	// the nonce against expectedNonce, then returns the Telegram identity.
	Exchange(ctx context.Context, code, codeVerifier, expectedNonce string) (*Identity, error)
}

// Config configures Client construction.
type Config struct {
	// IssuerURL is the OIDC issuer; empty means DefaultIssuerURL.
	IssuerURL string
	// ClientID is the OIDC client id — the login bot's numeric id (the part of
	// the bot token before the colon). Not secret.
	ClientID string
	// ClientSecret is the OIDC client secret issued by BotFather; a credential
	// distinct from the bot API token. Sourced from Vault.
	ClientSecret string
	// RedirectURL is this service's Telegram callback endpoint, e.g.
	// https://tg.mctl.ai/oauth/telegram/callback.
	RedirectURL string
	// SigningAlgs restricts accepted id_token signing algorithms. Empty means
	// RS256 — the algorithm spike #48 observed Telegram using.
	SigningAlgs []string
}

// Client is the production Authenticator. Construct once at boot via New.
type Client struct {
	oauth2   *oauth2.Config
	verifier *oidc.IDTokenVerifier
}

var _ Authenticator = (*Client)(nil)

// New performs OIDC discovery against the issuer and returns a ready Client.
// It makes a network call and must be invoked at startup, never in a hot path
// or in offline unit tests — those inject a fake Authenticator instead.
func New(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.ClientID == "" {
		return nil, errors.New("telegramoidc: ClientID is required")
	}
	if cfg.ClientSecret == "" {
		return nil, errors.New("telegramoidc: ClientSecret is required")
	}
	if cfg.RedirectURL == "" {
		return nil, errors.New("telegramoidc: RedirectURL is required")
	}
	issuer := cfg.IssuerURL
	if issuer == "" {
		issuer = DefaultIssuerURL
	}
	algs := cfg.SigningAlgs
	if len(algs) == 0 {
		algs = []string{oidc.RS256}
	}

	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("telegramoidc: OIDC discovery for %q: %w", issuer, err)
	}

	endpoint := provider.Endpoint()
	// Telegram accepts client_secret_basic and client_secret_post; pin Basic.
	endpoint.AuthStyle = oauth2.AuthStyleInHeader

	return &Client{
		oauth2: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     endpoint,
			RedirectURL:  cfg.RedirectURL,
			Scopes:       scopes,
		},
		verifier: provider.Verifier(&oidc.Config{
			ClientID:             cfg.ClientID,
			SupportedSigningAlgs: algs,
			// Expiry is checked below with clockSkew tolerance — Telegram's
			// id_tokens live only ~30s, so a zero-leeway check would be
			// fragile under minor clock drift.
			SkipExpiryCheck: true,
		}),
	}, nil
}

func (c *Client) AuthCodeURL(state, nonce, codeChallenge string) string {
	return c.oauth2.AuthCodeURL(state,
		oidc.Nonce(nonce),
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
}

func (c *Client) Exchange(ctx context.Context, code, codeVerifier, expectedNonce string) (*Identity, error) {
	tok, err := c.oauth2.Exchange(ctx, code,
		oauth2.SetAuthURLParam("code_verifier", codeVerifier))
	if err != nil {
		return nil, fmt.Errorf("telegramoidc: token exchange: %w", err)
	}
	rawIDToken, ok := tok.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, errors.New("telegramoidc: token response did not include an id_token")
	}
	idToken, err := c.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("telegramoidc: id_token verification: %w", err)
	}
	if idToken.Nonce != expectedNonce {
		return nil, errors.New("telegramoidc: id_token nonce does not match the authorization request")
	}
	if !idToken.Expiry.IsZero() && time.Now().Add(-clockSkew).After(idToken.Expiry) {
		return nil, fmt.Errorf("telegramoidc: id_token expired at %s", idToken.Expiry.UTC())
	}
	var claims idTokenClaims
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("telegramoidc: decoding id_token claims: %w", err)
	}
	return parseIdentity(claims)
}

// idTokenClaims is the subset of id_token claims the broker consumes. `id` is
// kept raw because Telegram delivers it as a JSON string (spike #48), not a
// number — parseTelegramID normalises it.
type idTokenClaims struct {
	ID        json.RawMessage `json:"id"`
	Sub       string          `json:"sub"`
	Username  string          `json:"username"`
	FirstName string          `json:"first_name"`
	LastName  string          `json:"last_name"`
}

// parseIdentity converts verified claims into an Identity. It is pure and
// offline-testable — all network and crypto happen before it is called.
func parseIdentity(c idTokenClaims) (*Identity, error) {
	tgID, err := parseTelegramID(c.ID)
	if err != nil {
		return nil, err
	}
	id := &Identity{
		TelegramID: tgID,
		Sub:        c.Sub,
		Username:   c.Username,
		FirstName:  c.FirstName,
		LastName:   c.LastName,
	}
	if id.TelegramID == 0 && id.Sub == "" {
		return nil, errors.New("telegramoidc: id_token carries neither an id claim nor a sub")
	}
	return id, nil
}

// parseTelegramID normalises the `id` claim into a positive int64. Telegram
// delivers it as a JSON string ("210408407", spike #48); a bare JSON number is
// also accepted in case that ever changes. A missing or null claim yields 0
// with no error — the sub-only contingency relies on that.
func parseTelegramID(raw json.RawMessage) (int64, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return 0, nil
	}
	var asString string
	if err := json.Unmarshal(raw, &asString); err == nil {
		n, err := strconv.ParseInt(strings.TrimSpace(asString), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("telegramoidc: id claim %q is not an integer", asString)
		}
		if n <= 0 {
			return 0, fmt.Errorf("telegramoidc: id claim %d is not a positive Telegram id", n)
		}
		return n, nil
	}
	var asNumber int64
	if err := json.Unmarshal(raw, &asNumber); err == nil {
		if asNumber <= 0 {
			return 0, fmt.Errorf("telegramoidc: id claim %d is not a positive Telegram id", asNumber)
		}
		return asNumber, nil
	}
	return 0, fmt.Errorf("telegramoidc: id claim %s is neither a numeric string nor a number", trimmed)
}
