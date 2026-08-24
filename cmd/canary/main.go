// Package main implements a synthetic end-to-end canary probe for mctl-telegram.
// It exercises the OAuth metadata endpoint and the MCP list_dialogs tool using
// a pre-issued read-only bearer token. It emits three Prometheus metric families
// and either pushes them to a Pushgateway or serves them locally for scraping.
//
// This binary has no imports from github.com/mctlhq/mctl-telegram/internal/.
// It is intentionally a black-box HTTP client so it validates the public surface.
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/client_golang/prometheus/push"
)

var version = "dev"

// config holds all runtime configuration sourced from environment variables.
type config struct {
	baseURL     string
	bearerToken string
	tgUserID    string
	timeout     time.Duration
	mcpPath     string
	probeUnread bool
	pushgateway string
	metricsAddr string
}

// canaryMetrics holds the three Prometheus metric families for the canary.
type canaryMetrics struct {
	success      prometheus.Gauge
	duration     prometheus.Histogram
	stepFailures *prometheus.CounterVec
	// tokenExpiresIn is created in newCanaryMetrics but registered in run(),
	// once there is a real deadline to report — see the rationale there.
	tokenExpiresIn prometheus.Gauge
	registry       *prometheus.Registry
}

// loadConfig reads and validates environment variables. It returns an error
// when any required variable is absent.
func loadConfig() (*config, error) {
	cfg := &config{}

	cfg.baseURL = os.Getenv("CANARY_BASE_URL")
	if cfg.baseURL == "" {
		return nil, errors.New("CANARY_BASE_URL is required")
	}

	cfg.bearerToken = os.Getenv("CANARY_BEARER_TOKEN")
	if cfg.bearerToken == "" {
		return nil, errors.New("CANARY_BEARER_TOKEN is required")
	}

	cfg.tgUserID = os.Getenv("CANARY_TG_USER_ID")
	if cfg.tgUserID == "" {
		return nil, errors.New("CANARY_TG_USER_ID is required")
	}

	timeoutStr := os.Getenv("CANARY_TIMEOUT")
	if timeoutStr == "" {
		cfg.timeout = 30 * time.Second
	} else {
		d, err := time.ParseDuration(timeoutStr)
		if err != nil {
			return nil, fmt.Errorf("CANARY_TIMEOUT invalid duration %q: %w", timeoutStr, err)
		}
		cfg.timeout = d
	}

	cfg.mcpPath = os.Getenv("CANARY_MCP_PATH")
	if cfg.mcpPath == "" {
		cfg.mcpPath = "/mcp"
	}

	cfg.probeUnread = os.Getenv("CANARY_PROBE_UNREAD") == "true"

	cfg.pushgateway = os.Getenv("PUSHGATEWAY_URL")

	cfg.metricsAddr = os.Getenv("CANARY_METRICS_ADDR")
	if cfg.metricsAddr == "" {
		cfg.metricsAddr = ":9090"
	}

	return cfg, nil
}

// newCanaryMetrics creates and registers the three canary metric families on a
// fresh prometheus.Registry (not the global default registerer).
func newCanaryMetrics() *canaryMetrics {
	reg := prometheus.NewRegistry()

	success := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "mctl_telegram_canary_success",
		Help: "1 if all canary probes succeeded in the last run; 0 if any failed.",
	})

	duration := prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "mctl_telegram_canary_duration_seconds",
		Help:    "Wall-clock time of the complete canary run in seconds.",
		Buckets: []float64{1, 2.5, 5, 10, 15, 20, 30},
	})

	stepFailures := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "mctl_telegram_canary_step_failure_total",
		Help: "1 if the named step failed in the last canary run, 0 if it succeeded. Pushgateway replace semantics mean this reflects the most recent run only; use the instant value (> 0) rather than rate() for triage queries.",
	}, []string{"step"})

	// Deliberately NOT registered here. A registered gauge that is never set
	// pushes 0, and 0 on this metric reads as "the token expired" — the exact
	// false alarm the metric exists to avoid. run() registers it only once it
	// has a real deadline to report; when the token carries no readable exp
	// the series is simply absent, which the CanaryAbsent-style alert already
	// covers.
	tokenExpiresIn := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "mctl_telegram_canary_token_expires_in_seconds",
		Help: "Seconds until CANARY_BEARER_TOKEN expires. Negative once past exp. Absent when the token carries no readable exp claim.",
	})

	reg.MustRegister(success, duration, stepFailures)

	return &canaryMetrics{
		success:        success,
		duration:       duration,
		stepFailures:   stepFailures,
		tokenExpiresIn: tokenExpiresIn,
		registry:       reg,
	}
}

// tokenExpiry reads the exp claim out of a JWT WITHOUT verifying it. The
// canary holds no signing key and has no business validating its own
// credential — the server does that on every call, and a forged exp would only
// mislead this one gauge. Returns ok=false for anything unparseable so the
// caller can leave the metric absent rather than publish a wrong deadline.
func tokenExpiry(token string) (time.Time, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, false
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Exp <= 0 {
		return time.Time{}, false
	}
	return time.Unix(claims.Exp, 0).UTC(), true
}

// oauthMetadataResponse contains the fields we validate in the OAuth AS metadata.
type oauthMetadataResponse struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
}

// probeOAuthMetadata fetches /.well-known/oauth-authorization-server and
// validates the HTTP status and required JSON fields.
func probeOAuthMetadata(ctx context.Context, client *http.Client, baseURL string) error {
	url := baseURL + "/.well-known/oauth-authorization-server"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s returned HTTP %d", url, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}

	var meta oauthMetadataResponse
	if err := json.Unmarshal(body, &meta); err != nil {
		return fmt.Errorf("parse JSON: %w", err)
	}

	if !strings.HasPrefix(meta.Issuer, "https://") {
		return fmt.Errorf("oauth metadata issuer must use https: %q", meta.Issuer)
	}
	if !strings.HasPrefix(meta.AuthorizationEndpoint, "https://") && !strings.HasPrefix(meta.AuthorizationEndpoint, "http://") {
		return fmt.Errorf("oauth metadata authorization_endpoint is not a URL: %q", meta.AuthorizationEndpoint)
	}
	if !strings.HasPrefix(meta.TokenEndpoint, "https://") && !strings.HasPrefix(meta.TokenEndpoint, "http://") {
		return fmt.Errorf("oauth metadata token_endpoint is not a URL: %q", meta.TokenEndpoint)
	}

	return nil
}

// isFloodWaitMsg reports whether the string contains a Telegram FLOOD_WAIT signal.
func isFloodWaitMsg(s string) bool {
	return strings.Contains(s, "FLOOD_WAIT_") || strings.Contains(s, "FLOOD_PREMIUM_WAIT_")
}

// isFloodWaitContent reports whether any content item's text field contains a
// Telegram FLOOD_WAIT signal. Only called when isError=true so we do not
// false-positive on user message content that happens to contain the substring.
func isFloodWaitContent(content []map[string]any) bool {
	for _, c := range content {
		if text, ok := c["text"].(string); ok && isFloodWaitMsg(text) {
			return true
		}
	}
	return false
}

// jsonRPCRequest is the JSON-RPC 2.0 request body sent to the MCP endpoint.
type jsonRPCRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Method  string `json:"method"`
	Params  any    `json:"params"`
}

// mcpInitParams holds the MCP initialize request parameters.
type mcpInitParams struct {
	ProtocolVersion string         `json:"protocolVersion"`
	Capabilities    map[string]any `json:"capabilities"`
	ClientInfo      mcpClientInfo  `json:"clientInfo"`
}

// mcpClientInfo identifies the canary client in the initialize handshake.
type mcpClientInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// mcpCallParams holds the MCP tools/call parameters.
type mcpCallParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

// initMCPSession performs the MCP initialize handshake and returns the
// Mcp-Session-Id value that must be sent with subsequent requests.
// The MCP Streamable HTTP transport requires session initialization before
// any tools/call request.
func initMCPSession(ctx context.Context, client *http.Client, baseURL, mcpPath, bearerToken string) (string, error) {
	url := baseURL + mcpPath

	reqBody := jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
		Params: mcpInitParams{
			ProtocolVersion: "2024-11-05",
			Capabilities:    map[string]any{},
			ClientInfo:      mcpClientInfo{Name: "mctl-telegram-canary", Version: version},
		},
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshal initialize request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", fmt.Errorf("build initialize request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearerToken)

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("POST %s (initialize): %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return "", fmt.Errorf("initialize returned HTTP %d", resp.StatusCode)
	}

	sessionID := resp.Header.Get("Mcp-Session-Id")
	if sessionID == "" {
		_, _ = io.Copy(io.Discard, resp.Body)
		return "", errors.New("server did not return Mcp-Session-Id header")
	}

	_, _ = io.Copy(io.Discard, resp.Body)
	return sessionID, nil
}

// jsonRPCResponse is used to decode the MCP endpoint response.
type jsonRPCResponse struct {
	JSONRPC string         `json:"jsonrpc"`
	ID      int            `json:"id"`
	Error   *jsonRPCError  `json:"error,omitempty"`
	Result  *mcpToolResult `json:"result,omitempty"`
}

// jsonRPCError represents a JSON-RPC 2.0 error object.
type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// mcpToolResult represents the result field of a successful tools/call response.
type mcpToolResult struct {
	Content []map[string]any `json:"content"`
	IsError bool             `json:"isError"`
}

// probeMCPToolResult is returned by probeMCPTool.
type probeMCPToolResult struct {
	floodWait bool
}

// probeMCPTool calls the MCP endpoint with a tools/call JSON-RPC request for
// the given tool name. sessionID must be the value obtained from initMCPSession.
// It returns a non-nil error on any failure, and sets floodWait=true when a
// Telegram FLOOD_WAIT condition is detected.
func probeMCPTool(ctx context.Context, client *http.Client, baseURL, mcpPath, bearerToken, sessionID, toolName string, args map[string]any) (*probeMCPToolResult, error) {
	url := baseURL + mcpPath

	reqBody := jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params: mcpCallParams{
			Name:      toolName,
			Arguments: args,
		},
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearerToken)
	req.Header.Set("Mcp-Session-Id", sessionID)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("POST %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("POST %s returned HTTP %d", url, resp.StatusCode)
	}

	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	var rpcResp jsonRPCResponse
	if err := json.Unmarshal(respBytes, &rpcResp); err != nil {
		return nil, fmt.Errorf("parse JSON-RPC response: %w", err)
	}

	if rpcResp.Error != nil {
		if isFloodWaitMsg(rpcResp.Error.Message) {
			return &probeMCPToolResult{floodWait: true},
				fmt.Errorf("MCP JSON-RPC error (flood_wait): code=%d message=%s", rpcResp.Error.Code, rpcResp.Error.Message)
		}
		return nil, fmt.Errorf("MCP JSON-RPC error: code=%d message=%s", rpcResp.Error.Code, rpcResp.Error.Message)
	}

	if rpcResp.Result == nil {
		return nil, errors.New("MCP response has no result field")
	}

	if rpcResp.Result.IsError {
		if isFloodWaitContent(rpcResp.Result.Content) {
			return &probeMCPToolResult{floodWait: true},
				errors.New("MCP tool returned isError=true (flood_wait)")
		}
		return nil, errors.New("MCP tool returned isError=true")
	}

	if rpcResp.Result.Content == nil {
		return nil, errors.New("MCP tool result has nil content")
	}

	return &probeMCPToolResult{floodWait: false}, nil
}

// run executes the full canary probe sequence, records metrics, and returns
// true when all probes succeeded. It is a separate function to allow testing
// without starting a real HTTP server or touching os.Exit.
func run(ctx context.Context, cfg *config, met *canaryMetrics) bool {
	log := slog.Default()
	start := time.Now()
	ok := true

	// Report how much life the bearer token has left. Since mctl-telegram#412
	// the token is deliberately bounded (30d default, 90d ceiling), which turns
	// expiry from a distant problem into a scheduled one: the canary cannot
	// renew itself yet (#421), so without this gauge the first symptom would be
	// a permanently red canary on the expiry date.
	if exp, okExp := tokenExpiry(cfg.bearerToken); okExp {
		// Register, not MustRegister: registration happens here rather than at
		// construction, so a second run() against the same registry — a daemon
		// loop, or simply two calls in one test — would otherwise panic on
		// duplicate registration. An already-registered gauge is the expected
		// steady state, not an error.
		if regErr := met.registry.Register(met.tokenExpiresIn); regErr != nil {
			if _, dup := regErr.(prometheus.AlreadyRegisteredError); !dup {
				log.Error("token expiry metric registration failed", "err", regErr)
			}
		}
		met.tokenExpiresIn.Set(time.Until(exp).Seconds())
		log.Info("token lifetime", "expires_at", exp.Format(time.RFC3339))
	} else {
		log.Warn("token lifetime unknown, expiry metric omitted")
	}

	client := &http.Client{Timeout: cfg.timeout}

	// Step 1: oauth_metadata
	log.Info("probe start", "step", "oauth_metadata", "tg_user_id", cfg.tgUserID)
	stepCtx, cancel := context.WithTimeout(ctx, cfg.timeout)
	err := probeOAuthMetadata(stepCtx, client, cfg.baseURL)
	cancel()

	if err != nil {
		log.Error("probe failed", "step", "oauth_metadata", "err", err)
		met.stepFailures.WithLabelValues("oauth_metadata").Inc()
		ok = false
		// Abort: cannot continue without OAuth metadata.
		met.success.Set(0)
		met.duration.Observe(time.Since(start).Seconds())
		return false
	}
	log.Info("probe ok", "step", "oauth_metadata")

	// Step 2: initialize MCP session (required by the Streamable HTTP transport).
	log.Info("probe start", "step", "mcp_init", "tg_user_id", cfg.tgUserID)
	stepCtx, cancel = context.WithTimeout(ctx, cfg.timeout)
	sessionID, err := initMCPSession(stepCtx, client, cfg.baseURL, cfg.mcpPath, cfg.bearerToken)
	cancel()

	if err != nil {
		log.Error("probe failed", "step", "mcp_init", "err", err)
		met.stepFailures.WithLabelValues("mcp_init").Inc()
		ok = false
		met.success.Set(0)
		met.duration.Observe(time.Since(start).Seconds())
		return false
	}
	log.Info("probe ok", "step", "mcp_init")

	// Step 3: list_dialogs
	log.Info("probe start", "step", "list_dialogs", "tg_user_id", cfg.tgUserID)
	stepCtx, cancel = context.WithTimeout(ctx, cfg.timeout)
	result, err := probeMCPTool(stepCtx, client, cfg.baseURL, cfg.mcpPath, cfg.bearerToken, sessionID, "list_dialogs", map[string]any{"limit": 5})
	cancel()

	if err != nil {
		floodWait := result != nil && result.floodWait
		log.Error("probe failed", "step", "list_dialogs", "err", err, "flood_wait", floodWait)
		met.stepFailures.WithLabelValues("list_dialogs").Inc()
		ok = false
	} else {
		log.Info("probe ok", "step", "list_dialogs")
	}

	// Step 4: get_unread_messages (optional)
	if cfg.probeUnread {
		log.Info("probe start", "step", "get_unread_messages", "tg_user_id", cfg.tgUserID)
		stepCtx, cancel = context.WithTimeout(ctx, cfg.timeout)
		result, err = probeMCPTool(stepCtx, client, cfg.baseURL, cfg.mcpPath, cfg.bearerToken, sessionID, "get_unread_messages", map[string]any{"limit": 1})
		cancel()

		if err != nil {
			floodWait := result != nil && result.floodWait
			log.Error("probe failed", "step", "get_unread_messages", "err", err, "flood_wait", floodWait)
			met.stepFailures.WithLabelValues("get_unread_messages").Inc()
			ok = false
		} else {
			log.Info("probe ok", "step", "get_unread_messages")
		}
	}

	elapsed := time.Since(start).Seconds()
	met.duration.Observe(elapsed)

	if ok {
		met.success.Set(1)
	} else {
		met.success.Set(0)
	}

	log.Info("canary run complete",
		"ok", ok,
		"duration_seconds", elapsed,
		"tg_user_id", cfg.tgUserID,
		"version", version,
	)

	return ok
}

func main() {
	inner := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})
	slog.SetDefault(slog.New(inner))

	cfg, err := loadConfig()
	if err != nil {
		slog.Error("config error", "err", err)
		os.Exit(1)
	}

	met := newCanaryMetrics()
	ctx := context.Background()

	ok := run(ctx, cfg, met)

	if cfg.pushgateway != "" {
		pusher := push.New(cfg.pushgateway, "mctl_telegram_canary").Gatherer(met.registry)
		if pushErr := pusher.Push(); pushErr != nil {
			slog.Error("pushgateway push failed", "err", pushErr)
			os.Exit(1)
		}
		slog.Info("metrics pushed to pushgateway", "url", cfg.pushgateway)
		if !ok {
			os.Exit(1)
		}
		return
	}

	// Daemon mode: serve metrics locally for Prometheus scraping.
	// Intended for local smoke runs only; production uses the CronJob
	// with PUSHGATEWAY_URL set. Metrics are frozen to the single probe
	// result and do not refresh while the server is running.
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(met.registry, promhttp.HandlerOpts{}))
	slog.Info("serving metrics", "addr", cfg.metricsAddr)
	if serveErr := http.ListenAndServe(cfg.metricsAddr, mux); serveErr != nil {
		slog.Error("metrics server failed", "err", serveErr)
		os.Exit(1)
	}
}
