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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/client_golang/prometheus/push"
)

var version = "dev"

// config holds all runtime configuration sourced from environment variables.
type config struct {
	baseURL      string
	bearerToken  string
	tgUserID     string
	timeout      time.Duration
	mcpPath      string
	probeUnread  bool
	pushgateway  string
	metricsAddr  string
}

// canaryMetrics holds the three Prometheus metric families for the canary.
type canaryMetrics struct {
	success      prometheus.Gauge
	duration     prometheus.Histogram
	stepFailures *prometheus.CounterVec
	registry     *prometheus.Registry
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
		Help: "Number of canary probe step failures by step name.",
	}, []string{"step"})

	reg.MustRegister(success, duration, stepFailures)

	return &canaryMetrics{
		success:      success,
		duration:     duration,
		stepFailures: stepFailures,
		registry:     reg,
	}
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

	if meta.Issuer == "" {
		return errors.New("oauth metadata missing required field: issuer")
	}
	if meta.AuthorizationEndpoint == "" {
		return errors.New("oauth metadata missing required field: authorization_endpoint")
	}
	if meta.TokenEndpoint == "" {
		return errors.New("oauth metadata missing required field: token_endpoint")
	}

	return nil
}

// jsonRPCRequest is the JSON-RPC 2.0 request body sent to the MCP endpoint.
type jsonRPCRequest struct {
	JSONRPC string         `json:"jsonrpc"`
	ID      int            `json:"id"`
	Method  string         `json:"method"`
	Params  mcpCallParams  `json:"params"`
}

// mcpCallParams holds the MCP tools/call parameters.
type mcpCallParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

// jsonRPCResponse is used to decode the MCP endpoint response.
type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Error   *jsonRPCError   `json:"error,omitempty"`
	Result  *mcpToolResult  `json:"result,omitempty"`
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
// the given tool name. It returns a non-nil error on any failure, and sets
// floodWait=true when a Telegram FLOOD_WAIT condition is detected.
func probeMCPTool(ctx context.Context, client *http.Client, baseURL, mcpPath, bearerToken, toolName string, args map[string]any) (*probeMCPToolResult, error) {
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

	// Check for flood-wait before parsing, since the substring may appear
	// anywhere in the response text including inside error messages.
	floodWait := bytes.Contains(respBytes, []byte("FLOOD_WAIT_")) ||
		bytes.Contains(respBytes, []byte("FLOOD_PREMIUM_WAIT_"))

	var rpcResp jsonRPCResponse
	if err := json.Unmarshal(respBytes, &rpcResp); err != nil {
		return nil, fmt.Errorf("parse JSON-RPC response: %w", err)
	}

	if rpcResp.Error != nil {
		if floodWait {
			return &probeMCPToolResult{floodWait: true},
				fmt.Errorf("MCP JSON-RPC error (flood_wait): code=%d message=%s", rpcResp.Error.Code, rpcResp.Error.Message)
		}
		return nil, fmt.Errorf("MCP JSON-RPC error: code=%d message=%s", rpcResp.Error.Code, rpcResp.Error.Message)
	}

	if rpcResp.Result == nil {
		return nil, errors.New("MCP response has no result field")
	}

	if rpcResp.Result.IsError {
		if floodWait {
			return &probeMCPToolResult{floodWait: true},
				errors.New("MCP tool returned isError=true (flood_wait)")
		}
		return nil, errors.New("MCP tool returned isError=true")
	}

	if rpcResp.Result.Content == nil {
		return nil, errors.New("MCP tool result has nil content")
	}

	if floodWait {
		// Content was non-nil and isError was false, but the response body
		// still mentions a flood-wait condition somewhere; treat as failure.
		return &probeMCPToolResult{floodWait: true},
			errors.New("MCP response contains FLOOD_WAIT signal")
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

	// Step 2: list_dialogs
	log.Info("probe start", "step", "list_dialogs", "tg_user_id", cfg.tgUserID)
	stepCtx, cancel = context.WithTimeout(ctx, cfg.timeout)
	result, err := probeMCPTool(stepCtx, client, cfg.baseURL, cfg.mcpPath, cfg.bearerToken, "list_dialogs", map[string]any{"limit": 5})
	cancel()

	if err != nil {
		floodWait := result != nil && result.floodWait
		log.Error("probe failed", "step", "list_dialogs", "err", err, "flood_wait", floodWait)
		met.stepFailures.WithLabelValues("list_dialogs").Inc()
		ok = false
	} else {
		log.Info("probe ok", "step", "list_dialogs")
	}

	// Step 3: get_unread_messages (optional)
	if cfg.probeUnread {
		log.Info("probe start", "step", "get_unread_messages", "tg_user_id", cfg.tgUserID)
		stepCtx, cancel = context.WithTimeout(ctx, cfg.timeout)
		result, err = probeMCPTool(stepCtx, client, cfg.baseURL, cfg.mcpPath, cfg.bearerToken, "get_unread_messages", map[string]any{"limit": 1})
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
			// Do not override the exit code from the probe result.
		} else {
			slog.Info("metrics pushed to pushgateway", "url", cfg.pushgateway)
		}
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
