// Package main is a load-test binary for mctl-telegram staging deployments.
// Build with: go build ./test/load/
// Run with:   ./load -users N -ramp 2m -hold 10m -target URL -tokens FILE -peer PEER
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// tool names used in the 70/25/5 weighted mix.
const (
	toolListDialogs = "list_dialogs"
	toolGetMessages = "get_messages"
	toolSendMessage = "send_message"
)

var (
	flagUsers     = flag.Int("users", 100, "number of concurrent virtual users")
	flagRamp      = flag.Duration("ramp", 2*time.Minute, "linear ramp duration")
	flagHold      = flag.Duration("hold", 10*time.Minute, "sustained-load hold duration")
	flagTarget    = flag.String("target", "", "base URL of the staging deployment (required)")
	flagTokens    = flag.String("tokens", "", "path to newline-delimited bearer token file (required)")
	flagPeer      = flag.String("peer", "", "Telegram peer for get_messages calls (required)")
	flagOut       = flag.String("out", "results.json", "path for JSON results file")
	flagAllowSend = flag.Bool("allow-send", false, "exercise the send_message call path in draft mode (no real message delivered)")
)

// callResult records a single tool-call outcome.
type callResult struct {
	latency time.Duration
	isErr   bool
}

// toolStats accumulates per-tool call outcomes.
type toolStats struct {
	mu        sync.Mutex
	count     int64
	errCount  int64
	latencies []time.Duration
}

func (ts *toolStats) record(r callResult) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.count++
	if r.isErr {
		ts.errCount++
	} else {
		ts.latencies = append(ts.latencies, r.latency)
	}
}

func (ts *toolStats) snapshot() (count, errCount int64, p50, p95, p99 time.Duration) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	count = ts.count
	errCount = ts.errCount
	if len(ts.latencies) == 0 {
		return
	}
	sorted := make([]time.Duration, len(ts.latencies))
	copy(sorted, ts.latencies)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	p50 = percentile(sorted, 0.50)
	p95 = percentile(sorted, 0.95)
	p99 = percentile(sorted, 0.99)
	return
}

func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := p * float64(len(sorted)-1)
	lo := int(idx)
	hi := lo + 1
	if hi >= len(sorted) {
		return sorted[lo]
	}
	frac := idx - float64(lo)
	return sorted[lo] + time.Duration(frac*float64(sorted[hi]-sorted[lo]))
}

// resultStore holds per-tool stats.
type resultStore struct {
	stats map[string]*toolStats
}

func newResultStore() *resultStore {
	return &resultStore{
		stats: map[string]*toolStats{
			toolListDialogs: {},
			toolGetMessages: {},
			toolSendMessage: {},
		},
	}
}

// peakMetrics tracks running peak values scraped from /metrics.
type peakMetrics struct {
	mu              sync.Mutex
	poolSize        float64
	sessionsActive  float64
	rssBytes        float64
	goroutines      float64
	floodWaitByTool map[string]float64
	// floodWaitBaseline records the counter value on the first scrape per
	// tool so buildReport can report the run-local delta rather than the
	// server-lifetime cumulative total (the metric is a monotonic counter).
	floodWaitBaseline map[string]float64
}

func newPeakMetrics() *peakMetrics {
	return &peakMetrics{
		floodWaitByTool:   map[string]float64{},
		floodWaitBaseline: map[string]float64{},
	}
}

func (pm *peakMetrics) update(name string, labels map[string]string, value float64) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	switch name {
	case "mctl_telegram_client_pool_size":
		if value > pm.poolSize {
			pm.poolSize = value
		}
	case "mctl_sessions_active":
		if value > pm.sessionsActive {
			pm.sessionsActive = value
		}
	case "process_resident_memory_bytes":
		if value > pm.rssBytes {
			pm.rssBytes = value
		}
	case "go_goroutines":
		if value > pm.goroutines {
			pm.goroutines = value
		}
	case "mctl_telegram_flood_wait_events_total":
		if tool := labels["tool"]; tool != "" {
			if _, seen := pm.floodWaitBaseline[tool]; !seen {
				pm.floodWaitBaseline[tool] = value
			}
			if value > pm.floodWaitByTool[tool] {
				pm.floodWaitByTool[tool] = value
			}
		}
	}
}

// jsonrpcRequest is a minimal JSON-RPC 2.0 request.
type jsonrpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Method  string `json:"method"`
	Params  any    `json:"params"`
}

// toolCallParams matches the MCP tools/call params structure.
type toolCallParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

// jsonrpcResponse holds the fields we read from an MCP JSON-RPC response.
type jsonrpcResponse struct {
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Message string `json:"message"`
	} `json:"error"`
}

// mcpToolResult is the content wrapper returned by tools/call.
type mcpToolResult struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	IsError bool `json:"isError"`
}

// mcpInitParams / mcpClientInfo model the MCP initialize handshake.
type mcpInitParams struct {
	ProtocolVersion string         `json:"protocolVersion"`
	Capabilities    map[string]any `json:"capabilities"`
	ClientInfo      mcpClientInfo  `json:"clientInfo"`
}

type mcpClientInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// initMCPSession performs the MCP initialize handshake and returns the
// Mcp-Session-Id that must accompany every subsequent tools/call. The MCP
// Streamable HTTP transport requires session init before any tool call
// (see cmd/canary/main.go).
func initMCPSession(ctx context.Context, client *http.Client, target, token string) (string, error) {
	body, err := json.Marshal(jsonrpcRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
		Params: mcpInitParams{
			ProtocolVersion: "2024-11-05",
			Capabilities:    map[string]any{},
			ClientInfo:      mcpClientInfo{Name: "mctl-telegram-loadtest", Version: "1"},
		},
	})
	if err != nil {
		return "", fmt.Errorf("marshal initialize: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target+"/mcp", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("new initialize request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("initialize http: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("initialize returned HTTP %d", resp.StatusCode)
	}
	sessionID := resp.Header.Get("Mcp-Session-Id")
	if sessionID == "" {
		return "", fmt.Errorf("server did not return Mcp-Session-Id")
	}
	return sessionID, nil
}

// callTool sends one MCP tools/call request and returns the raw result payload.
// sessionID must be the value returned by initMCPSession; the Streamable HTTP
// transport rejects tools/call without a valid Mcp-Session-Id.
func callTool(ctx context.Context, client *http.Client, target, token, sessionID string, reqID int, toolName string, args map[string]any) (json.RawMessage, time.Duration, error) {
	body, err := json.Marshal(jsonrpcRequest{
		JSONRPC: "2.0",
		ID:      reqID,
		Method:  "tools/call",
		Params:  toolCallParams{Name: toolName, Arguments: args},
	})
	if err != nil {
		return nil, 0, fmt.Errorf("marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target+"/mcp", bytes.NewReader(body))
	if err != nil {
		return nil, 0, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Mcp-Session-Id", sessionID)

	start := time.Now()
	resp, err := client.Do(req)
	latency := time.Since(start)
	if err != nil {
		return nil, latency, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, latency, fmt.Errorf("read body: %w", err)
	}

	// If the server returned SSE, extract the data line.
	if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		respBody = extractSSEData(respBody)
	}

	var rpcResp jsonrpcResponse
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return nil, latency, fmt.Errorf("unmarshal (status %d): %w", resp.StatusCode, err)
	}
	if rpcResp.Error != nil {
		return nil, latency, fmt.Errorf("rpc error: %s", rpcResp.Error.Message)
	}
	// MCP tools report application-level failures (FLOOD_WAIT, invalid peer,
	// auth rejection) as a successful JSON-RPC response with isError=true.
	// Treat those as errors so they don't contaminate latency percentiles.
	var toolRes mcpToolResult
	if json.Unmarshal(rpcResp.Result, &toolRes) == nil && toolRes.IsError {
		return nil, latency, fmt.Errorf("tool error (isError=true)")
	}
	return rpcResp.Result, latency, nil
}

// extractSSEData pulls the JSON payload from a text/event-stream body.
// It returns the last non-empty "data: ..." line's payload (the final MCP
// result event), or the original body if no data line is found.
func extractSSEData(body []byte) []byte {
	// MCP over SSE may emit progress/keepalive frames before the final result
	// event, so return the last non-empty data: payload, not the first.
	var last []byte
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "data:") {
			if payload := []byte(strings.TrimSpace(strings.TrimPrefix(line, "data:"))); len(payload) > 0 {
				last = payload
			}
		}
	}
	if last != nil {
		return last
	}
	return body
}

// runVirtualUser is the per-goroutine load-generation loop. It selects a tool
// using the 70/25/5 weighted distribution, sends one MCP call, records the
// outcome, then sleeps for a random 0-500 ms jitter before the next call.
func runVirtualUser(ctx context.Context, client *http.Client, target, token, peer string, s *resultStore, counter *atomic.Int64, allowSend bool) {
	// Use a per-goroutine RNG seeded from the shared counter to avoid
	// correlated selections across goroutines.
	rng := rand.New(rand.NewSource(counter.Add(1)))

	// MCP Streamable HTTP requires an initialize handshake before any
	// tools/call; without a valid Mcp-Session-Id the server rejects calls.
	sessionID, err := initMCPSession(ctx, client, target, token)
	if err != nil {
		fmt.Fprintf(os.Stderr, "virtual user init failed: %v\n", err)
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		id := int(counter.Add(1))
		roll := rng.Intn(100)

		switch {
		case roll < 70: // list_dialogs (70%)
			_, lat, err := callTool(ctx, client, target, token, sessionID, id, toolListDialogs, map[string]any{})
			s.stats[toolListDialogs].record(callResult{latency: lat, isErr: err != nil})

		case roll < 95: // get_messages (25%)
			_, lat, err := callTool(ctx, client, target, token, sessionID, id, toolGetMessages, map[string]any{"peer": peer})
			s.stats[toolGetMessages].record(callResult{latency: lat, isErr: err != nil})

		default: // send_message (5%): direct call, draft mode
			if !allowSend {
				break
			}
			_, lat, err := callTool(ctx, client, target, token, sessionID, id, toolSendMessage, map[string]any{
				"peer": peer,
				"text": "load test dry run",
				"mode": "draft",
			})
			s.stats[toolSendMessage].record(callResult{latency: lat, isErr: err != nil})
		}

		// Inter-call jitter: 0-500 ms uniform random.
		jitter := time.Duration(rng.Intn(500)) * time.Millisecond
		select {
		case <-ctx.Done():
			return
		case <-time.After(jitter):
		}
	}
}


// parsePrometheusLine parses one line of Prometheus text-format exposition.
// Returns ok=false for comments, empty lines, or malformed entries.
func parsePrometheusLine(line string) (name string, labels map[string]string, value float64, ok bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", nil, 0, false
	}
	spaceIdx := strings.LastIndexByte(line, ' ')
	if spaceIdx < 0 {
		return "", nil, 0, false
	}
	nameAndLabels := strings.TrimSpace(line[:spaceIdx])
	valStr := strings.TrimSpace(line[spaceIdx+1:])
	// Strip optional timestamp after the value.
	if idx := strings.IndexByte(valStr, ' '); idx >= 0 {
		valStr = valStr[:idx]
	}
	v, err := strconv.ParseFloat(valStr, 64)
	if err != nil {
		return "", nil, 0, false
	}
	labels = map[string]string{}
	if braceIdx := strings.IndexByte(nameAndLabels, '{'); braceIdx >= 0 {
		name = nameAndLabels[:braceIdx]
		labelStr := strings.TrimSuffix(nameAndLabels[braceIdx+1:], "}")
		for _, pair := range strings.Split(labelStr, ",") {
			pair = strings.TrimSpace(pair)
			eqIdx := strings.IndexByte(pair, '=')
			if eqIdx < 0 {
				continue
			}
			k := strings.TrimSpace(pair[:eqIdx])
			v := strings.Trim(strings.TrimSpace(pair[eqIdx+1:]), `"`)
			labels[k] = v
		}
	} else {
		name = nameAndLabels
	}
	return name, labels, v, true
}

// scrapeMetrics performs one /metrics scrape and updates the peak store.
func scrapeMetrics(ctx context.Context, client *http.Client, target string, pm *peakMetrics) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target+"/metrics", nil)
	if err != nil {
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// e.g. 403 when the load-test host is outside METRICS_ALLOW_CIDR.
		// Warn instead of silently leaving every peak at zero.
		fmt.Fprintf(os.Stderr, "warning: /metrics returned HTTP %d; peak metrics will be incomplete\n", resp.StatusCode)
		return
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(body), "\n") {
		name, labels, value, ok := parsePrometheusLine(line)
		if !ok {
			continue
		}
		pm.update(name, labels, value)
	}
}

// pollMetrics scrapes /metrics every 5 seconds until ctx is cancelled.
func pollMetrics(ctx context.Context, client *http.Client, target string, pm *peakMetrics) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			scrapeMetrics(ctx, client, target, pm)
		}
	}
}

// toolReport is the per-tool section of the JSON results file.
type toolReport struct {
	Tool      string  `json:"tool"`
	Calls     int64   `json:"calls"`
	Errors    int64   `json:"errors"`
	ErrorRate float64 `json:"error_rate"`
	P50Ms     float64 `json:"p50_ms"`
	P95Ms     float64 `json:"p95_ms"`
	P99Ms     float64 `json:"p99_ms"`
}

// loadTestResults is the top-level JSON output.
type loadTestResults struct {
	Target         string             `json:"target"`
	Users          int                `json:"users"`
	RampDuration   string             `json:"ramp_duration"`
	HoldDuration   string             `json:"hold_duration"`
	Peer           string             `json:"peer"`
	Tools          []toolReport       `json:"tools"`
	PeakPoolSize   float64            `json:"peak_pool_size"`
	PeakSessions   float64            `json:"peak_sessions_active"`
	PeakRSSBytes   float64            `json:"peak_rss_bytes"`
	PeakGoroutines float64            `json:"peak_goroutines"`
	FloodWaits     map[string]float64 `json:"flood_wait_events"`
}

func buildReport(s *resultStore, pm *peakMetrics, target string, users int, ramp, hold time.Duration, peer string) loadTestResults {
	pm.mu.Lock()
	// Report the run-local delta: peak observed minus the first-scrape
	// baseline, since the underlying metric is a monotonic counter.
	floodCopy := make(map[string]float64, len(pm.floodWaitByTool))
	for k, v := range pm.floodWaitByTool {
		delta := v - pm.floodWaitBaseline[k]
		if delta < 0 {
			delta = 0
		}
		floodCopy[k] = delta
	}
	peakPoolSize := pm.poolSize
	peakSessions := pm.sessionsActive
	peakRSSBytes := pm.rssBytes
	peakGoroutines := pm.goroutines
	pm.mu.Unlock()

	r := loadTestResults{
		Target:         target,
		Users:          users,
		RampDuration:   ramp.String(),
		HoldDuration:   hold.String(),
		Peer:           peer,
		PeakPoolSize:   peakPoolSize,
		PeakSessions:   peakSessions,
		PeakRSSBytes:   peakRSSBytes,
		PeakGoroutines: peakGoroutines,
		FloodWaits:     floodCopy,
	}

	for _, name := range []string{toolListDialogs, toolGetMessages, toolSendMessage} {
		count, errCount, p50, p95, p99 := s.stats[name].snapshot()
		var rate float64
		if count > 0 {
			rate = float64(errCount) / float64(count)
		}
		r.Tools = append(r.Tools, toolReport{
			Tool:      name,
			Calls:     count,
			Errors:    errCount,
			ErrorRate: rate,
			P50Ms:     float64(p50.Milliseconds()),
			P95Ms:     float64(p95.Milliseconds()),
			P99Ms:     float64(p99.Milliseconds()),
		})
	}
	return r
}

func printMarkdown(r loadTestResults) {
	fmt.Printf("## Load test results\n\n")
	fmt.Printf("- Target: %s\n", r.Target)
	fmt.Printf("- Virtual users: %d\n", r.Users)
	fmt.Printf("- Ramp duration: %s\n", r.RampDuration)
	fmt.Printf("- Hold duration: %s\n", r.HoldDuration)
	fmt.Printf("- Peer: %s\n\n", r.Peer)

	fmt.Printf("### Per-tool throughput and latency\n\n")
	fmt.Printf("| Tool | Calls | Errors | Error rate | p50 (ms) | p95 (ms) | p99 (ms) |\n")
	fmt.Printf("|------|-------|--------|------------|----------|----------|----------|\n")
	for _, t := range r.Tools {
		fmt.Printf("| %s | %d | %d | %.2f%% | %.0f | %.0f | %.0f |\n",
			t.Tool, t.Calls, t.Errors, t.ErrorRate*100, t.P50Ms, t.P95Ms, t.P99Ms)
	}

	fmt.Printf("\n### Peak server metrics\n\n")
	fmt.Printf("| Metric | Peak value |\n")
	fmt.Printf("|--------|------------|\n")
	fmt.Printf("| mctl_telegram_client_pool_size | %.0f |\n", r.PeakPoolSize)
	fmt.Printf("| mctl_sessions_active | %.0f |\n", r.PeakSessions)
	fmt.Printf("| process_resident_memory_bytes | %.0f |\n", r.PeakRSSBytes)
	fmt.Printf("| go_goroutines | %.0f |\n", r.PeakGoroutines)

	if len(r.FloodWaits) > 0 {
		fmt.Printf("\n### FLOOD_WAIT events\n\n")
		fmt.Printf("| Tool | Events |\n")
		fmt.Printf("|------|--------|\n")
		for tool, count := range r.FloodWaits {
			fmt.Printf("| %s | %.0f |\n", tool, count)
		}
	}
	fmt.Println()
}

func main() {
	flag.Parse()
	if *flagTarget == "" {
		fmt.Fprintln(os.Stderr, "error: -target is required")
		flag.Usage()
		os.Exit(1)
	}
	if *flagTokens == "" {
		fmt.Fprintln(os.Stderr, "error: -tokens is required")
		flag.Usage()
		os.Exit(1)
	}
	if *flagPeer == "" {
		fmt.Fprintln(os.Stderr, "error: -peer is required")
		flag.Usage()
		os.Exit(1)
	}

	tokensData, err := os.ReadFile(*flagTokens)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading tokens file: %v\n", err)
		os.Exit(1)
	}
	var tokens []string
	for _, line := range strings.Split(string(tokensData), "\n") {
		if t := strings.TrimSpace(line); t != "" {
			tokens = append(tokens, t)
		}
	}
	if len(tokens) == 0 {
		fmt.Fprintln(os.Stderr, "error: tokens file contains no tokens")
		os.Exit(1)
	}

	numUsers := *flagUsers
	if numUsers < 1 {
		numUsers = 1
	}
	if numUsers > len(tokens) {
		// Reused tokens share the same per-user rate limit across goroutines,
		// which produces artificial 429-style errors and skews the results.
		fmt.Fprintf(os.Stderr, "warning: %d users but only %d token(s); tokens will be reused and per-user rate limits will be shared, skewing results. Provide >= %d tokens for accurate measurement.\n", numUsers, len(tokens), numUsers)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	s := newResultStore()
	pm := newPeakMetrics()
	var counter atomic.Int64

	// holdCtx governs all virtual-user goroutines; cancelled after the hold phase.
	holdCtx, holdCancel := context.WithCancel(context.Background())
	defer holdCancel()

	// Linear ramp: start one goroutine every ramp/N.
	var rampInterval time.Duration
	if numUsers > 0 && *flagRamp > 0 {
		rampInterval = *flagRamp / time.Duration(numUsers)
	}

	fmt.Printf("starting load test: %d users, ramp %s, hold %s, target %s\n",
		numUsers, flagRamp.String(), flagHold.String(), *flagTarget)

	// Start the metrics poller before the ramp loop so ramp-phase peaks
	// (goroutine count, pool size) are captured, not just the hold phase.
	pollerCtx, pollerCancel := context.WithCancel(context.Background())
	go pollMetrics(pollerCtx, client, *flagTarget, pm)

	var wg sync.WaitGroup
	for i := 0; i < numUsers; i++ {
		if i > 0 && rampInterval > 0 {
			time.Sleep(rampInterval)
		}
		token := tokens[i%len(tokens)]
		wg.Add(1)
		go func(tok string) {
			defer wg.Done()
			runVirtualUser(holdCtx, client, *flagTarget, tok, *flagPeer, s, &counter, *flagAllowSend)
		}(token)
	}
	fmt.Printf("all %d users started; holding for %s\n", numUsers, flagHold.String())

	// Wait for the hold phase to complete.
	time.Sleep(*flagHold)

	holdCancel()
	pollerCancel()
	wg.Wait()
	fmt.Println("hold phase complete; generating report")

	report := buildReport(s, pm, *flagTarget, numUsers, *flagRamp, *flagHold, *flagPeer)
	printMarkdown(report)

	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error marshaling results: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*flagOut, jsonData, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "error writing %s: %v\n", *flagOut, err)
		os.Exit(1)
	}
	fmt.Printf("results written to %s\n", *flagOut)
}
