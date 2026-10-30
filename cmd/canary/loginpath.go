package main

// Login-path probes (mctl-telegram#959, epic mctlhq/.github#279).
//
// The tool-path steps in main.go prove that an already-connected account can
// call tools. They say nothing about the path a NEW connector takes: protected
// resource discovery, the authorize redirect to Telegram's OIDC, the callback,
// the connect page, MCP on the bare origin, and the edge in front of all of
// it. Two incidents lived exactly there while the canary stayed green (the
// connector-UA 403 at Cloudflare on 2026-10-29, MCP refused on "/" on
// 2026-10-30). These probes walk every hop up to the Telegram boundary and
// stop there: no Telegram API call, no login, no account touched.
//
// They publish mctl_telegram_canary_login_path_success separately from
// mctl_telegram_canary_success so the two can be alerted on independently,
// and they reuse mctl_telegram_canary_step_failure_total with their own step
// labels. Each step is independent: one failing does not skip the others, so
// a single run names every broken hop.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// connectClientID is the built-in self-connect OAuth client
// (internal/oauth.ConnectClientID). The canary reuses it rather than a
// dedicated client: it is pre-registered in every deployment, so no DCR row is
// created per run, and it is the client the real /telegram/connect page uses.
// Duplicated, not imported: this binary stays a black-box HTTP client.
const connectClientID = "mctl_self_connect"

// edgeConnectorUserAgents are the User-Agent tokens the AI connectors send on
// their server-side MCP calls. Cloudflare's block_spoofed_crawlers rule
// answered 403 to exactly these on 2026-10-29 (mctl-gitops#2261).
var edgeConnectorUserAgents = []string{"Claude-User", "ChatGPT-User", "Perplexity-User"}

// reusedLinkMarker is the text of the page /oauth/telegram/callback renders
// for an unknown or expired state (internal/oauth renderEnableReused).
const reusedLinkMarker = "already used or has expired"

// loginPathSteps lists every login-path step label in run order.
var loginPathSteps = []string{
	"prm_root",
	"prm_mcp",
	"connect_page",
	"authorize_redirect",
	"callback_unknown_state",
	"mcp_root",
	"edge_connector_ua",
}

// newLoginPathSuccessGauge is registered only when the login-path probes are
// enabled: a gauge that is registered but never set pushes 0, which would read
// as "the login path is broken" on a deployment that never probed it.
func newLoginPathSuccessGauge() prometheus.Gauge {
	return prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "mctl_telegram_canary_login_path_success",
		Help: "1 if every connector login-path probe succeeded in the last run; 0 if any failed. Absent when the login-path probes are disabled.",
	})
}

// loginPathClient returns a client that never follows redirects: the
// authorize step asserts the redirect itself, and following it would leave
// this origin for oauth.telegram.org.
func loginPathClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func canaryUserAgent() string { return "mctl-telegram-canary/" + version }

// getBody performs a GET and returns the status, headers and a bounded body.
// A transport error or an unreadable body is returned as an error: could not
// observe is never treated as an answer.
func getBody(ctx context.Context, client *http.Client, rawURL, userAgent string) (int, http.Header, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("GET %s: %w", rawURL, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, nil, nil, fmt.Errorf("read body: %w", err)
	}
	return resp.StatusCode, resp.Header, body, nil
}

// probeProtectedResource checks one RFC 9728 document: 200, JSON, resource
// equal to wantResource and at least one authorization server.
func probeProtectedResource(ctx context.Context, client *http.Client, baseURL, path, wantResource string) error {
	status, _, body, err := getBody(ctx, client, baseURL+path, canaryUserAgent())
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("GET %s returned HTTP %d", path, status)
	}
	var meta struct {
		Resource             string   `json:"resource"`
		AuthorizationServers []string `json:"authorization_servers"`
	}
	if err := json.Unmarshal(body, &meta); err != nil {
		return fmt.Errorf("parse JSON: %w", err)
	}
	if meta.Resource != wantResource {
		return fmt.Errorf("resource is %q, want %q", meta.Resource, wantResource)
	}
	if len(meta.AuthorizationServers) == 0 {
		return errors.New("authorization_servers is empty")
	}
	return nil
}

var authorizeHrefRe = regexp.MustCompile(`href="([^"]*/oauth/authorize\?[^"]*)"`)

// probeConnectPage checks that /telegram/connect renders and carries a
// "Connect with Telegram" link to this issuer's /oauth/authorize for the
// self-connect client.
func probeConnectPage(ctx context.Context, client *http.Client, baseURL string) error {
	status, _, body, err := getBody(ctx, client, baseURL+"/telegram/connect", canaryUserAgent())
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("GET /telegram/connect returned HTTP %d", status)
	}
	m := authorizeHrefRe.FindSubmatch(body)
	if m == nil {
		return errors.New("connect page has no /oauth/authorize link")
	}
	u, err := url.Parse(html.UnescapeString(string(m[1])))
	if err != nil {
		return fmt.Errorf("parse authorize link: %w", err)
	}
	if got := u.Scheme + "://" + u.Host + u.Path; got != baseURL+"/oauth/authorize" {
		return fmt.Errorf("authorize link points at %q, want %q", got, baseURL+"/oauth/authorize")
	}
	if got := u.Query().Get("client_id"); got != connectClientID {
		return fmt.Errorf("authorize link client_id is %q, want %q", got, connectClientID)
	}
	return nil
}

// pkceChallenge returns the S256 challenge of a random RFC 7636 verifier. Only the
// challenge is used: the canary never redeems a code.
func pkceChallenge() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(base64.RawURLEncoding.EncodeToString(b)))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

func randomState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// probeAuthorizeRedirect starts the self-connect authorization and checks the
// server hands the browser to Telegram's OIDC with the parameters the callback
// needs. The redirect is not followed. The pending entry it creates expires
// with the code TTL like any abandoned sign-in.
func probeAuthorizeRedirect(ctx context.Context, client *http.Client, baseURL, oidcHost string) error {
	challenge, err := pkceChallenge()
	if err != nil {
		return fmt.Errorf("generate PKCE challenge: %w", err)
	}
	state, err := randomState()
	if err != nil {
		return fmt.Errorf("generate state: %w", err)
	}
	q := url.Values{
		"client_id":             {connectClientID},
		"redirect_uri":          {baseURL + "/telegram/connect/done"},
		"response_type":         {"code"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"state":                 {state},
	}
	status, hdr, _, err := getBody(ctx, client, baseURL+"/oauth/authorize?"+q.Encode(), canaryUserAgent())
	if err != nil {
		return err
	}
	if status != http.StatusFound {
		return fmt.Errorf("authorize returned HTTP %d, want 302 to Telegram OIDC", status)
	}
	loc, err := url.Parse(hdr.Get("Location"))
	if err != nil {
		return fmt.Errorf("parse Location: %w", err)
	}
	if loc.Scheme != "https" || loc.Host != oidcHost {
		return fmt.Errorf("authorize redirected to %s://%s, want https://%s", loc.Scheme, loc.Host, oidcHost)
	}
	lq := loc.Query()
	if lq.Get("client_id") == "" {
		return errors.New("Telegram redirect has no client_id")
	}
	if got, want := lq.Get("redirect_uri"), baseURL+"/oauth/telegram/callback"; got != want {
		return fmt.Errorf("Telegram redirect_uri is %q, want %q", got, want)
	}
	if lq.Get("response_type") != "code" {
		return fmt.Errorf("Telegram response_type is %q, want code", lq.Get("response_type"))
	}
	if lq.Get("code_challenge") == "" || lq.Get("code_challenge_method") != "S256" {
		return errors.New("Telegram redirect lacks an S256 PKCE challenge")
	}
	if lq.Get("state") == "" {
		return errors.New("Telegram redirect has no state")
	}
	return nil
}

// probeCallbackUnknownState sends a callback for a state the server never
// issued and expects the "link already used" page, not a 5xx or a blank
// response. It logs one unknown_state rejection server-side per run; the
// canary User-Agent tells those apart from real users.
func probeCallbackUnknownState(ctx context.Context, client *http.Client, baseURL string) error {
	state, err := randomState()
	if err != nil {
		return fmt.Errorf("generate state: %w", err)
	}
	q := url.Values{"state": {"canary-" + state}, "code": {"canary"}}
	status, _, body, err := getBody(ctx, client, baseURL+"/oauth/telegram/callback?"+q.Encode(), canaryUserAgent())
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("callback returned HTTP %d, want 200", status)
	}
	if !strings.Contains(string(body), reusedLinkMarker) {
		return fmt.Errorf("callback page does not contain %q", reusedLinkMarker)
	}
	return nil
}

// postUnauthenticated sends an MCP initialize with no credentials and returns
// the status and the WWW-Authenticate header.
func postUnauthenticated(ctx context.Context, client *http.Client, rawURL, userAgent string) (int, string, error) {
	body, err := json.Marshal(jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
		Params: mcpInitParams{
			ProtocolVersion: "2024-11-05",
			Capabilities:    map[string]any{},
			ClientInfo:      mcpClientInfo{Name: "mctl-telegram-canary", Version: version},
		},
	})
	if err != nil {
		return 0, "", fmt.Errorf("marshal initialize: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, strings.NewReader(string(body)))
	if err != nil {
		return 0, "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("User-Agent", userAgent)
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", fmt.Errorf("POST %s: %w", rawURL, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, resp.Header.Get("WWW-Authenticate"), nil
}

// expectAppChallenge accepts only the application's own 401: status 401 with
// a Bearer challenge naming wantMetadata. An edge block (403, challenge page),
// a 405 or a 200 all fail, and status alone is never enough, because an edge
// could answer 401 too.
func expectAppChallenge(status int, challenge, wantMetadata string) error {
	if status != http.StatusUnauthorized {
		return fmt.Errorf("HTTP %d, want the app's 401", status)
	}
	// The realm is the app's own: a Bearer challenge from an auth proxy in
	// front of it would carry its own realm.
	if !strings.HasPrefix(challenge, `Bearer realm="mctl-telegram"`) {
		return fmt.Errorf("WWW-Authenticate %q is not the app's Bearer challenge", challenge)
	}
	if !strings.Contains(challenge, `resource_metadata="`+wantMetadata+`"`) {
		return fmt.Errorf("WWW-Authenticate %q does not name %s", challenge, wantMetadata)
	}
	return nil
}

// probeMCPRoot checks that the bare origin is served by the MCP handler
// (mctl-telegram#957): an unauthenticated initialize on "/" must get the app's
// challenge pointing at the origin's protected-resource document. The 405 the
// server answered before #957 is a failure, never an expected value.
func probeMCPRoot(ctx context.Context, client *http.Client, baseURL string) error {
	status, challenge, err := postUnauthenticated(ctx, client, baseURL+"/", canaryUserAgent())
	if err != nil {
		return err
	}
	return expectAppChallenge(status, challenge, baseURL+"/.well-known/oauth-protected-resource")
}

// probeEdgeConnectorUA sends an unauthenticated initialize to the MCP path
// with each connector User-Agent and requires the app's 401 for every one: a
// Cloudflare block answers 403 or a challenge page instead.
func probeEdgeConnectorUA(ctx context.Context, client *http.Client, baseURL, mcpPath string) error {
	var failed []string
	for _, ua := range edgeConnectorUserAgents {
		status, challenge, err := postUnauthenticated(ctx, client, baseURL+mcpPath, ua)
		if err == nil {
			err = expectAppChallenge(status, challenge, baseURL+"/.well-known/oauth-protected-resource"+mcpPath)
		}
		if err != nil {
			failed = append(failed, ua+": "+err.Error())
		}
	}
	if len(failed) > 0 {
		return errors.New(strings.Join(failed, "; "))
	}
	return nil
}

// runLoginPath runs every login-path step, records step failures and the
// login-path success gauge, and returns true when all passed. It does not
// touch mctl_telegram_canary_success.
func runLoginPath(ctx context.Context, cfg *config, met *canaryMetrics) bool {
	log := slog.Default()
	client := loginPathClient(cfg.timeout)
	base := strings.TrimRight(cfg.baseURL, "/")

	probes := map[string]func(context.Context) error{
		"prm_root": func(c context.Context) error {
			return probeProtectedResource(c, client, base, "/.well-known/oauth-protected-resource", base)
		},
		"prm_mcp": func(c context.Context) error {
			return probeProtectedResource(c, client, base, "/.well-known/oauth-protected-resource"+cfg.mcpPath, base+cfg.mcpPath)
		},
		"connect_page": func(c context.Context) error { return probeConnectPage(c, client, base) },
		"authorize_redirect": func(c context.Context) error {
			return probeAuthorizeRedirect(c, client, base, cfg.oidcHost)
		},
		"callback_unknown_state": func(c context.Context) error { return probeCallbackUnknownState(c, client, base) },
		"mcp_root":               func(c context.Context) error { return probeMCPRoot(c, client, base) },
		"edge_connector_ua":      func(c context.Context) error { return probeEdgeConnectorUA(c, client, base, cfg.mcpPath) },
	}

	ok := true
	for _, step := range loginPathSteps {
		stepCtx, cancel := context.WithTimeout(ctx, cfg.timeout)
		err := probes[step](stepCtx)
		cancel()
		if err != nil {
			log.Error("probe failed", "step", step, "err", err)
			met.stepFailures.WithLabelValues(step).Inc()
			ok = false
			continue
		}
		log.Info("probe ok", "step", step)
	}

	if ok {
		met.loginPathSuccess.Set(1)
	} else {
		met.loginPathSuccess.Set(0)
	}
	log.Info("login path run complete", "ok", ok)
	return ok
}
