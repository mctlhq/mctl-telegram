package mcpprobe

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
)

// OAuthProbeConfig configures the OAuth metadata / 401-challenge probe
// (requirements.md acceptance criterion E, F's public-client compatibility
// gate). It runs independently of Mode: OAuth surface is not protocol-era
// specific.
type OAuthProbeConfig struct {
	// BaseURL is the scheme://host[:port] of the target. Required.
	BaseURL string
	// MCPPath is used only to probe the unauthenticated 401 challenge on the
	// MCP endpoint itself. Defaults to DefaultMCPPath.
	MCPPath string
	// BearerToken, when set, is not itself used by this probe (the
	// authenticated-cell OAuth checks this spike needs -- confirming a
	// minted token's aud/scope -- are exercised by the existing OAuth test
	// suite, not by mcpprobe). Its only effect here is
	// AuthenticatedProbeSkipped, matching requirements.md acceptance
	// criterion C: "missing bearer token shall still allow OAuth metadata
	// and unauthenticated challenge checks; authenticated cells become
	// skipped".
	BearerToken string
	HTTPClient  *http.Client
}

func (c OAuthProbeConfig) mcpPath() string {
	if c.MCPPath != "" {
		return c.MCPPath
	}
	return DefaultMCPPath
}

func (c OAuthProbeConfig) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: 30 * time.Second}
}

// ProbeOAuth collects protected-resource and authorization-server metadata,
// and classifies the unauthenticated 401 challenge on the MCP endpoint. It
// never sends a bearer token, so it never records one, and it never
// attempts an authorization-code or token exchange (no authorization code
// this package could leak into a Report is ever produced).
func ProbeOAuth(ctx context.Context, cfg OAuthProbeConfig) (*OAuthResult, error) {
	client := cfg.httpClient()
	base := strings.TrimRight(cfg.BaseURL, "/")

	result := &OAuthResult{AuthenticatedProbeSkipped: cfg.BearerToken == ""}

	prmStatus, err := getStatus(ctx, client, base+"/.well-known/oauth-protected-resource")
	if err != nil {
		return nil, fmt.Errorf("mcpprobe: protected-resource metadata: %w", err)
	}
	result.ProtectedResourceHTTPStatus = prmStatus

	asStatus, asBody, err := getBody(ctx, client, base+"/.well-known/oauth-authorization-server")
	if err != nil {
		return nil, fmt.Errorf("mcpprobe: authorization-server metadata: %w", err)
	}
	result.AuthorizationServerHTTPStatus = asStatus
	if asStatus == http.StatusOK {
		var decoded struct {
			Issuer                   string   `json:"issuer"`
			TokenEndpointAuthMethods []string `json:"token_endpoint_auth_methods_supported"`
		}
		if err := json.Unmarshal(asBody, &decoded); err == nil {
			result.Issuer = decoded.Issuer
			result.TokenEndpointAuthMethods = decoded.TokenEndpointAuthMethods
			result.PublicClientPKCECompatible = containsString(decoded.TokenEndpointAuthMethods, "none")
		}
	}

	challenge, err := probeUnauthenticated401(ctx, client, base+cfg.mcpPath())
	if err != nil {
		return nil, fmt.Errorf("mcpprobe: unauthenticated 401 challenge: %w", err)
	}
	result.Unauthenticated401 = challenge

	return result, nil
}

func containsString(items []string, target string) bool {
	for _, s := range items {
		if s == target {
			return true
		}
	}
	return false
}

func getStatus(ctx context.Context, client *http.Client, url string) (int, error) {
	status, _, err := getBody(ctx, client, url)
	return status, err
}

func getBody(ctx context.Context, client *http.Client, url string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, nil, fmt.Errorf("build GET %s: %w", url, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("GET %s: %w", url, err)
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("read GET %s body: %w", url, err)
	}
	return resp.StatusCode, body, nil
}

// probeUnauthenticated401 sends a bearer-less tools/list to the MCP endpoint
// and classifies the response. A deployment with AuthRequired=false will
// answer 200; that is itself a valid, recorded observation, not a probe
// failure. It builds its own request (rather than reusing postJSONRPC)
// because it needs the WWW-Authenticate response header, which
// postJSONRPC's httpOutcome deliberately does not expose beyond
// Mcp-Session-Id.
func probeUnauthenticated401(ctx context.Context, client *http.Client, url string) (*Challenge401, error) {
	body, err := json.Marshal(rpcRequest{JSONRPC: "2.0", ID: 1, Method: mcp.MethodToolsList, Params: map[string]any{}})
	if err != nil {
		return nil, fmt.Errorf("marshal tools/list: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("build tools/list request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("POST %s: %w", url, err)
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

	c := &Challenge401{HTTPStatus: resp.StatusCode}
	if resp.StatusCode != http.StatusUnauthorized {
		return c, nil
	}
	// The WWW-Authenticate value itself is never stored -- only whether it
	// was present and what it declared -- so a deployment-specific realm or
	// metadata URL cannot leak into a Report through this path.
	wwwAuth := resp.Header.Get("WWW-Authenticate")
	c.HasWWWAuthenticateHeader = wwwAuth != ""
	c.WWWAuthenticateIsBearer = strings.HasPrefix(wwwAuth, "Bearer")
	c.HasResourceMetadataParam = strings.Contains(wwwAuth, "resource_metadata=")
	return c, nil
}
