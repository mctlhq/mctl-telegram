package linking

// oauthclient.go holds the production OAuth client calls the connection
// manager and the linking flow need beyond the authorization request
// (#1318 slice C1): the RFC 7009 revocation (connection.Revoker), the
// refresh-token grant (connection.RefreshFunc) and the code exchange
// (FormTokenClient). Every request goes through an internal/pa/egress
// client (threat model T9) allowed only the server's pinned hosts; no token
// ever appears in an error or a log.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
	"github.com/mctlhq/mctl-telegram/internal/pa/egress"
)

// OAuthServer is one server's OAuth client registration, as far as the
// token and revocation calls need it.
type OAuthServer struct {
	ClientID      string
	TokenEndpoint string
	// RevocationEndpoint is optional; without it Revoke returns
	// ErrNotRevocable.
	RevocationEndpoint string
	Resource           string
	// AllowedHosts is the server's egress allowlist.
	AllowedHosts []string
}

// OAuthClient makes the token and revocation calls of every configured
// server. It implements connection.Revoker; its Refresh method is a
// connection.RefreshFunc. It is safe for concurrent use.
type OAuthClient struct {
	servers map[connection.Server]OAuthServer
	token   map[connection.Server]*http.Client
	revoke  map[connection.Server]*http.Client
}

var _ connection.Revoker = (*OAuthClient)(nil)
var _ connection.RefreshFunc = (*OAuthClient)(nil).Refresh

// Errors of OAuthClient.
var (
	// ErrNotRevocable: the server has no revocation endpoint, so a token can
	// only be dropped locally. Disconnect records it as the remote
	// failure; it never means the token was revoked.
	ErrNotRevocable = errors.New("pa linking: the server has no revocation endpoint")
	// ErrRevocationEndpoint is a non-200 answer from the revocation
	// endpoint (RFC 7009 2.2: only 200 is success).
	ErrRevocationEndpoint = errors.New("pa linking: revocation endpoint refused the request")
)

// NewOAuthClient builds the egress clients of every server: purpose token
// for the token endpoint and purpose revocation for the revocation
// endpoint, each allowed exactly the server's AllowedHosts. denied is
// passed to egress as extra refused prefixes.
func NewOAuthClient(servers map[connection.Server]OAuthServer, denied []netip.Prefix) (*OAuthClient, error) {
	c := &OAuthClient{
		servers: map[connection.Server]OAuthServer{},
		token:   map[connection.Server]*http.Client{},
		revoke:  map[connection.Server]*http.Client{},
	}
	for name, s := range servers {
		if !name.Valid() || s.ClientID == "" || s.TokenEndpoint == "" || s.Resource == "" || len(s.AllowedHosts) == 0 {
			return nil, fmt.Errorf("%w: incomplete oauth registration for %s", ErrConfig, name)
		}
		tc, err := egress.New(egress.Config{Purpose: egress.PurposeToken, AllowedHosts: s.AllowedHosts, DeniedPrefixes: denied})
		if err != nil {
			return nil, fmt.Errorf("pa linking: token egress for %s: %w", name, err)
		}
		c.token[name] = tc
		if s.RevocationEndpoint != "" {
			rc, err := egress.New(egress.Config{Purpose: egress.PurposeRevocation, AllowedHosts: s.AllowedHosts, DeniedPrefixes: denied})
			if err != nil {
				return nil, fmt.Errorf("pa linking: revocation egress for %s: %w", name, err)
			}
			c.revoke[name] = rc
		}
		c.servers[name] = s
	}
	return c, nil
}

// TokenClient is the code-exchange client over the same token egress
// clients.
func (c *OAuthClient) TokenClient() FormTokenClient {
	return FormTokenClient{Clients: c.token}
}

// Revoke implements connection.Revoker: an RFC 7009 request for token with
// its hint, authenticated by client_id (the PA is a public client). Only
// HTTP 200 is success; a server without a revocation endpoint is
// ErrNotRevocable, never a success.
func (c *OAuthClient) Revoke(ctx context.Context, server connection.Server, token connection.Secret, hint connection.TokenHint) error {
	s, ok := c.servers[server]
	if !ok {
		return fmt.Errorf("%w: unknown server %s", ErrConfig, server)
	}
	if token.Empty() {
		return fmt.Errorf("%w: no token to revoke", ErrConfig)
	}
	client := c.revoke[server]
	if s.RevocationEndpoint == "" || client == nil {
		return fmt.Errorf("%w (%s)", ErrNotRevocable, server)
	}
	form := url.Values{
		"token":           {token.Reveal()},
		"token_type_hint": {string(hint)},
		"client_id":       {s.ClientID},
	}
	resp, err := postForm(ctx, client, s.RevocationEndpoint, form)
	if err != nil {
		return fmt.Errorf("pa linking: revocation request: %w", err)
	}
	defer resp.Body.Close()
	if _, err := egress.ReadBody(resp); err != nil {
		return fmt.Errorf("pa linking: revocation response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w (HTTP %d)", ErrRevocationEndpoint, resp.StatusCode)
	}
	return nil
}

// Refresh is the connection.RefreshFunc: the refresh-token grant (RFC 6749
// 6) with the RFC 8707 resource. A 2xx answer returns its body for the
// manager to verify. An error answer whose JSON error is invalid_grant
// wraps connection.ErrInvalidGrant. Any other failure, including an error
// answer that cannot be read, is transient: it is never taken for
// invalid_grant.
//
// Refresh-token reuse has no standard error code (RFC 6749 and RFC 9700
// report it as invalid_grant), so it arrives as ErrInvalidGrant: the
// connection becomes expired, never usable again, and the server has
// already revoked the token family on its side.
func (c *OAuthClient) Refresh(ctx context.Context, server connection.Server, refreshToken connection.Secret) ([]byte, error) {
	s, ok := c.servers[server]
	if !ok || c.token[server] == nil {
		return nil, fmt.Errorf("%w: unknown server %s", ErrConfig, server)
	}
	if refreshToken.Empty() {
		return nil, fmt.Errorf("%w: no refresh token", ErrConfig)
	}
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken.Reveal()},
		"client_id":     {s.ClientID},
		"resource":      {s.Resource},
	}
	resp, err := postForm(ctx, c.token[server], s.TokenEndpoint, form)
	if err != nil {
		return nil, fmt.Errorf("pa linking: refresh request: %w", err)
	}
	defer resp.Body.Close()
	body, err := egress.ReadBody(resp)
	if err != nil {
		return nil, fmt.Errorf("pa linking: refresh response: %w", err)
	}
	if resp.StatusCode/100 == 2 {
		return body, nil
	}
	if (resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusUnauthorized) && oauthErrorCode(body) == "invalid_grant" {
		return nil, fmt.Errorf("%w (HTTP %d)", connection.ErrInvalidGrant, resp.StatusCode)
	}
	// The body is not included: it may echo the request.
	return nil, fmt.Errorf("%w (HTTP %d)", ErrTokenEndpoint, resp.StatusCode)
}

// oauthErrorCode is the "error" member of an RFC 6749 5.2 error response,
// or "" when the body is not one.
func oauthErrorCode(body []byte) string {
	var e struct {
		Error *string `json:"error"`
	}
	if err := json.Unmarshal(body, &e); err != nil || e.Error == nil {
		return ""
	}
	return *e.Error
}

func postForm(ctx context.Context, client *http.Client, endpoint string, form url.Values) (*http.Response, error) {
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, errors.New("build request failed")
	}
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Accept", "application/json")
	// The form travels in the body; a transport error names only the
	// endpoint URL, which is configuration, not a secret.
	return client.Do(r)
}
