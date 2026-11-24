package main

// pa_mode.go wires AGENT_WORKER_PA=1, the Personal Assistant mode of the
// worker (#1313 slice d2). It is off unless that variable is true; the
// server answers PA claims only when PA_ENABLED is set there.

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/mctlhq/mctl-telegram/internal/agentworker"
)

// openAIClientFromEnv reads the OpenAI-compatible model settings shared by
// the openai runner and the PA mode.
func openAIClientFromEnv() (*agentworker.OpenAIClient, agentworker.Prices, error) {
	model, err := requireEnv("AGENT_MODEL")
	if err != nil {
		return nil, agentworker.Prices{}, err
	}
	baseURL, err := requireEnv("AGENT_OPENAI_BASE_URL")
	if err != nil {
		return nil, agentworker.Prices{}, err
	}
	apiKey, err := requireEnv("AGENT_OPENAI_API_KEY")
	if err != nil {
		return nil, agentworker.Prices{}, err
	}
	inputPrice, err := requiredEnvFloat("MODEL_INPUT_USD_PER_MTOK")
	if err != nil {
		return nil, agentworker.Prices{}, err
	}
	outputPrice, err := requiredEnvFloat("MODEL_OUTPUT_USD_PER_MTOK")
	if err != nil {
		return nil, agentworker.Prices{}, err
	}
	maxOutputTokens, err := envPositiveInt("AGENT_OPENAI_MAX_OUTPUT_TOKENS", 0)
	if err != nil {
		return nil, agentworker.Prices{}, err
	}
	return &agentworker.OpenAIClient{
		BaseURL:         baseURL,
		APIKey:          apiKey,
		GatewayToken:    os.Getenv("AGENT_GATEWAY_TOKEN"),
		Model:           model,
		UserAgent:       "mctl-telegram-agent-worker/" + version,
		MaxOutputTokens: maxOutputTokens,
	}, agentworker.Prices{
		InputUSDPerMTok: inputPrice, OutputUSDPerMTok: outputPrice,
	}, nil
}

// paWorkerFromEnv builds the PA worker. The PA mode runs the model
// in-process with no tools, so it needs the openai runner; the claude
// runner's subprocess and MCP tool surface are not part of it.
func paWorkerFromEnv(runnerName, poolToken string) (*agentworker.PAWorker, error) {
	if runnerName != "openai" {
		return nil, fmt.Errorf("AGENT_WORKER_PA requires AGENT_RUNNER=openai, got %q", runnerName)
	}
	base, err := requireEnv("AGENT_PA_BASE_URL")
	if err != nil {
		return nil, err
	}
	if err := validatePABaseURL(base); err != nil {
		return nil, err
	}
	oc, prices, err := openAIClientFromEnv()
	if err != nil {
		return nil, err
	}
	if !(prices.InputUSDPerMTok > 0) || !(prices.OutputUSDPerMTok > 0) {
		// A zero price would report every run as free and defeat the
		// worker's own job-cost check.
		return nil, errors.New("AGENT_WORKER_PA requires positive MODEL_INPUT_USD_PER_MTOK and MODEL_OUTPUT_USD_PER_MTOK")
	}
	if oc.MaxOutputTokens <= 0 {
		// The worker checks the job's cost limit between model calls; the
		// output cap bounds what one call can add past it.
		return nil, errors.New("AGENT_WORKER_PA requires AGENT_OPENAI_MAX_OUTPUT_TOKENS")
	}
	concurrency, err := envConcurrency("AGENT_WORKER_CONCURRENCY")
	if err != nil {
		return nil, err
	}
	streaming, err := envBoolStrict("AGENT_PA_STREAMING")
	if err != nil {
		return nil, err
	}
	return &agentworker.PAWorker{
		BaseURL: base, PoolToken: poolToken, Model: oc, Prices: prices,
		Health: &agentworker.Health{}, Concurrency: concurrency, Streaming: streaming,
	}, nil
}

// validatePABaseURL accepts an http(s) origin: the PA routes are absolute
// paths on it. No userinfo, path, query or fragment.
func validatePABaseURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("AGENT_PA_BASE_URL: not a url")
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return errors.New("AGENT_PA_BASE_URL must be an http(s) origin with no path, query or userinfo")
	}
	// The pool credential and every job token travel to this origin:
	// plain http only inside the cluster or to the loopback.
	if u.Scheme == "http" && !paClusterLocal(u.Hostname()) {
		return errors.New("AGENT_PA_BASE_URL must be https unless the host is cluster-local (*.svc, *.svc.cluster.local) or loopback")
	}
	return nil
}

// paClusterLocal reports a Kubernetes service name or a loopback host.
func paClusterLocal(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "localhost" || strings.HasSuffix(host, ".svc") || strings.HasSuffix(host, ".svc.cluster.local") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
