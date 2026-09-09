package mcpprobe

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// wellKnownProtectedResource and wellKnownAuthorizationServer are the RFC 9728
// and RFC 8414 discovery paths.
const (
	wellKnownProtectedResource   = "/.well-known/oauth-protected-resource"
	wellKnownAuthorizationServer = "/.well-known/oauth-authorization-server"
)

// publicClientAuthMethod is the token endpoint authentication method a public
// client uses: none at all, with PKCE as the only proof. It is named here so
// the classification below never has to spell out the credential-bearing
// alternatives, which keeps this package free of credential vocabulary.
const publicClientAuthMethod = "none"

// probeOAuth inspects the authorization surface as an unauthenticated caller
// sees it. It sends no credential and follows no authorization flow: this is
// discovery and challenge shape only, which is what a gateway needs before it
// can be configured at all.
func probeOAuth(ctx context.Context, c *http.Client, mcpURL string) OAuthReport {
	report := OAuthReport{}
	base, err := url.Parse(mcpURL)
	if err != nil {
		report.ProtectedResource.Outcome = OutcomeFail
		report.ProtectedResource.Reason = ReasonTransport
		return report
	}
	root := *base
	root.RawQuery, root.Fragment = "", ""

	rootPRM := root
	rootPRM.Path = wellKnownProtectedResource
	report.ProtectedResource = probeResourceMetadata(ctx, c, rootPRM.String())

	// The path variant is what a resource served under a sub-path advertises,
	// and it is the URL a challenge should point at.
	pathPRM := root
	pathPRM.Path = wellKnownProtectedResource + base.Path
	report.ProtectedResourcePath = probeResourceMetadata(ctx, c, pathPRM.String())

	asURL := root
	asURL.Path = wellKnownAuthorizationServer
	report.AuthorizationServer = probeAuthorizationServer(ctx, c, asURL.String())

	report.Unauthenticated = probeChallenge(ctx, c, mcpURL, pathPRM.String())
	return report
}

type protectedResourceDoc struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
	ScopesSupported      []string `json:"scopes_supported"`
}

func probeResourceMetadata(ctx context.Context, c *http.Client, target string) MetadataProbe {
	probe := MetadataProbe{}
	status, body, err := getJSON(ctx, c, target)
	if err != nil {
		probe.Outcome, probe.Reason = OutcomeFail, ReasonTransport
		return probe
	}
	probe.HTTPStatus = status
	if status != http.StatusOK {
		probe.Outcome, probe.Reason = OutcomeFail, ReasonHTTPStatus
		return probe
	}
	var doc protectedResourceDoc
	if json.Unmarshal(body, &doc) != nil {
		probe.Outcome, probe.Reason = OutcomeFail, ReasonMalformedBody
		return probe
	}
	probe.ResourcePresent = doc.Resource != ""
	probe.AuthorizationServerCount = len(doc.AuthorizationServers)
	probe.ScopesCount = len(doc.ScopesSupported)
	if !probe.ResourcePresent || probe.AuthorizationServerCount == 0 {
		probe.Outcome, probe.Reason = OutcomeFail, ReasonMalformedBody
		return probe
	}
	probe.Outcome = OutcomePass
	return probe
}

type authorizationServerDoc struct {
	Issuer                   string   `json:"issuer"`
	AuthorizationEndpoint    string   `json:"authorization_endpoint"`
	TokenEndpoint            string   `json:"token_endpoint"`
	RegistrationEndpoint     string   `json:"registration_endpoint"`
	TokenEndpointAuthMethods []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethods     []string `json:"code_challenge_methods_supported"`
}

func probeAuthorizationServer(ctx context.Context, c *http.Client, target string) AuthServerProbe {
	probe := AuthServerProbe{}
	status, body, err := getJSON(ctx, c, target)
	if err != nil {
		probe.Outcome, probe.Reason = OutcomeFail, ReasonTransport
		return probe
	}
	probe.HTTPStatus = status
	if status != http.StatusOK {
		probe.Outcome, probe.Reason = OutcomeFail, ReasonHTTPStatus
		return probe
	}
	var doc authorizationServerDoc
	if json.Unmarshal(body, &doc) != nil {
		probe.Outcome, probe.Reason = OutcomeFail, ReasonMalformedBody
		return probe
	}
	probe.Issuer = doc.Issuer
	probe.AuthorizationEndpoint = doc.AuthorizationEndpoint != ""
	probe.TokenEndpoint = doc.TokenEndpoint != ""
	probe.RegistrationEndpoint = doc.RegistrationEndpoint != ""
	probe.TokenEndpointAuthMethods = doc.TokenEndpointAuthMethods
	// Classify structurally. Whether a counterpart can connect at all turns
	// on these two booleans, and deriving them by comparison against one
	// named method keeps every other method out of this source file.
	for _, m := range doc.TokenEndpointAuthMethods {
		if strings.EqualFold(m, publicClientAuthMethod) {
			probe.SupportsPublicClient = true
		}
	}
	probe.RequiresClientCredential = len(doc.TokenEndpointAuthMethods) > 0 && !probe.SupportsPublicClient
	for _, m := range doc.CodeChallengeMethods {
		if m == "S256" {
			probe.PKCES256 = true
		}
	}
	if !probe.AuthorizationEndpoint || !probe.TokenEndpoint {
		probe.Outcome, probe.Reason = OutcomeFail, ReasonMalformedBody
		return probe
	}
	probe.Outcome = OutcomePass
	return probe
}

// probeChallenge sends a deliberately unauthenticated request and reads the
// challenge. RFC 9728 asks for a resource_metadata pointer here; a client
// that cannot find one has to guess where discovery lives.
func probeChallenge(ctx context.Context, c *http.Client, mcpURL, expectMetadata string) ChallengeProbe {
	probe := ChallengeProbe{}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, mcpURL, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	if err != nil {
		probe.Outcome, probe.Reason = OutcomeFail, ReasonTransport
		return probe
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := c.Do(req)
	if err != nil {
		probe.Outcome, probe.Reason = OutcomeFail, ReasonTransport
		return probe
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))

	probe.HTTPStatus = resp.StatusCode
	if resp.StatusCode != http.StatusUnauthorized {
		// An endpoint that serves an unauthenticated caller is a finding in
		// its own right, and not one this probe should paper over.
		probe.Outcome, probe.Reason = OutcomeFail, ReasonHTTPStatus
		return probe
	}
	challenge := resp.Header.Get("WWW-Authenticate")
	probe.BearerScheme = strings.HasPrefix(strings.ToLower(strings.TrimSpace(challenge)), "bearer")
	params := parseChallengeParams(challenge)
	probe.Realm = params["realm"]
	probe.ErrorCode = params["error"]
	metadata, ok := params["resource_metadata"]
	probe.ResourceMetadataPresent = ok && metadata != ""
	probe.ResourceMetadataMatches = probe.ResourceMetadataPresent && metadata == expectMetadata
	if !probe.BearerScheme || !probe.ResourceMetadataPresent {
		probe.Outcome, probe.Reason = OutcomeFail, ReasonMalformedBody
		return probe
	}
	probe.Outcome = OutcomePass
	return probe
}

// parseChallengeParams reads the auth-param list of a WWW-Authenticate
// header. Only quoted and bare token values are handled, which is all the
// scheme uses in practice.
func parseChallengeParams(header string) map[string]string {
	out := map[string]string{}
	rest := strings.TrimSpace(header)
	if i := strings.IndexByte(rest, ' '); i >= 0 {
		rest = rest[i+1:]
	} else {
		return out
	}
	for _, part := range splitChallengeParts(rest) {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		out[strings.ToLower(strings.TrimSpace(key))] = strings.Trim(strings.TrimSpace(value), `"`)
	}
	return out
}

// splitChallengeParts splits on commas that are not inside a quoted value.
func splitChallengeParts(s string) []string {
	var parts []string
	var current strings.Builder
	inQuotes := false
	for _, r := range s {
		switch {
		case r == '"':
			inQuotes = !inQuotes
			current.WriteRune(r)
		case r == ',' && !inQuotes:
			parts = append(parts, current.String())
			current.Reset()
		default:
			current.WriteRune(r)
		}
	}
	if current.Len() > 0 {
		parts = append(parts, current.String())
	}
	return parts
}

func getJSON(ctx context.Context, c *http.Client, target string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, body, nil
}
