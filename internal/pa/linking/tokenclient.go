package linking

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
	"github.com/mctlhq/mctl-telegram/internal/pa/egress"
)

// FormTokenClient posts the authorization-code grant as a form to the
// server's token endpoint. Clients maps each server to its egress client
// (internal/pa/egress, purpose token): this package never builds one.
type FormTokenClient struct {
	Clients map[connection.Server]*http.Client
}

// ErrTokenEndpoint is a non-2xx answer from the token endpoint. The body is
// not included: it may echo the code.
var ErrTokenEndpoint = errors.New("pa linking: token endpoint refused the grant")

// ExchangeCode implements TokenClient.
func (f FormTokenClient) ExchangeCode(ctx context.Context, server connection.Server, req ExchangeRequest) ([]byte, error) {
	client := f.Clients[server]
	if client == nil {
		return nil, fmt.Errorf("%w: no egress client for %s", ErrConfig, server)
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {req.Code.Reveal()},
		"redirect_uri":  {req.RedirectURI},
		"client_id":     {req.ClientID},
		"code_verifier": {req.Verifier.Reveal()},
		"resource":      {req.Resource},
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, req.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("pa linking: token request: %w", err)
	}
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Accept", "application/json")
	resp, err := client.Do(r)
	if err != nil {
		return nil, fmt.Errorf("pa linking: token request: %w", err)
	}
	body, err := egress.ReadBody(resp)
	if err != nil {
		return nil, fmt.Errorf("pa linking: token response: %w", err)
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("%w (HTTP %d)", ErrTokenEndpoint, resp.StatusCode)
	}
	return body, nil
}
