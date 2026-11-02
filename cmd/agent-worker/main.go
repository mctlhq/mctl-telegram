// Command agent-worker is the production (Option C) headless transport for
// the communication agent: it long-polls mctl-telegram's
// /api/agent/v1/events for due jobs and, for each one, runs the configured
// model runner (AGENT_RUNNER: claude, the default, or openai) with the same
// restricted tool surface: internal/agentworker.NewMCPServer for `claude -p`,
// the shared buildToolSet in-process for OpenAI-compatible models. See
// mctlhq/mctl-telegram#298 and the transport decision in the Communication
// Agent plan for why this replaced the originally-scoped Claude Code Channels
// bridge as the production path.
//
// This binary runs in two modes, selected by --mcp-serve:
//   - default: the poll loop (see run()). With the claude runner it spawns
//     `claude` as a subprocess per job; the openai runner stays in-process.
//   - --mcp-serve: a stdio MCP server exposing the 11 agent tools, scoped to
//     exactly one job via AGENT_JOB_* env vars. `claude` spawns this mode
//     itself (as configured by the default mode's --mcp-config), so an
//     operator never invokes it directly.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	mcpserver "github.com/mark3labs/mcp-go/server"
	"github.com/mctlhq/mctl-telegram/internal/agentworker"
	"github.com/mctlhq/mctl-telegram/internal/audit"
	"github.com/mctlhq/mctl-telegram/internal/metrics"
)

// version is set via -ldflags "-X main.version=..." at build time (see
// Dockerfile), matching every other binary in this repo.
var version = "dev"

func main() {
	configureLogging(os.Stderr)
	if len(os.Args) > 1 && os.Args[1] == "--mcp-serve" {
		if err := runMCPServe(); err != nil {
			slog.Error("agent-worker: mcp-serve failed", "err", err)
			os.Exit(1)
		}
		return
	}
	if err := run(); err != nil {
		slog.Error("agent-worker: fatal", "err", err)
		os.Exit(1)
	}
}

func configureLogging(w io.Writer) {
	inner := slog.NewJSONHandler(w, &slog.HandlerOptions{Level: slog.LevelInfo})
	slog.SetDefault(slog.New(audit.NewRedactingHandler(inner)))
}

// run is the default poll-loop mode.
func run() error {
	apiBaseURL, err := requireEnv("AGENT_API_BASE_URL")
	if err != nil {
		return err
	}
	apiToken, err := requireEnv("AGENT_API_TOKEN")
	if err != nil {
		return err
	}
	// A worker must never run unattributably against an unknown quota pool —
	// this is required (not optional) so a claim of quota isolation between
	// deployments has a machine-checkable counterpart. See docs/agent-worker.md
	// for the rollout ordering this implies (set the value before rolling
	// the image).
	credentialDomainID, err := requireEnv("AGENT_CREDENTIAL_DOMAIN_ID")
	if err != nil {
		return err
	}
	if err := validateDomainID(credentialDomainID); err != nil {
		return err
	}
	maxBudgetUSD, err := envFloat("AGENT_MAX_BUDGET_USD", 0)
	if err != nil {
		return err
	}

	m := metrics.New()
	m.AgentCredentialDomain.WithLabelValues(credentialDomainID).Set(1)
	client := agentworker.NewClient(apiBaseURL, apiToken, nil)

	runnerName := strings.ToLower(strings.TrimSpace(os.Getenv("AGENT_RUNNER")))
	if runnerName == "" {
		runnerName = "claude"
	}
	var runner agentworker.Runner
	switch runnerName {
	case "claude":
		self, err := os.Executable()
		if err != nil {
			return fmt.Errorf("resolve own executable path: %w", err)
		}
		runner = &agentworker.ClaudeInvoker{
			ClaudeBin:    os.Getenv("AGENT_CLAUDE_BIN"),
			Self:         self,
			APIBaseURL:   apiBaseURL,
			APIToken:     apiToken,
			SystemPrompt: os.Getenv("AGENT_SYSTEM_PROMPT"),
			MaxBudgetUSD: maxBudgetUSD,
			Metrics:      m,
		}
	case "openai":
		model, err := requireEnv("AGENT_MODEL")
		if err != nil {
			return err
		}
		openAIBaseURL, err := requireEnv("AGENT_OPENAI_BASE_URL")
		if err != nil {
			return err
		}
		openAIAPIKey, err := requireEnv("AGENT_OPENAI_API_KEY")
		if err != nil {
			return err
		}
		inputPrice, err := requiredEnvFloat("MODEL_INPUT_USD_PER_MTOK")
		if err != nil {
			return err
		}
		outputPrice, err := requiredEnvFloat("MODEL_OUTPUT_USD_PER_MTOK")
		if err != nil {
			return err
		}
		maxTurns, err := envPositiveInt("AGENT_MAX_TURNS", 12)
		if err != nil {
			return err
		}
		minInterval, err := envDuration("AGENT_OPENAI_MIN_INTERVAL", 0)
		if err != nil {
			return err
		}
		runner = &agentworker.OpenAIRunner{
			Client: &agentworker.OpenAIClient{
				BaseURL:      openAIBaseURL,
				APIKey:       openAIAPIKey,
				GatewayToken: os.Getenv("AGENT_GATEWAY_TOKEN"),
				Model:        model,
				UserAgent:    "mctl-telegram-agent-worker/" + version,
			},
			APIBaseURL:   apiBaseURL,
			APIToken:     apiToken,
			SystemPrompt: os.Getenv("AGENT_SYSTEM_PROMPT"),
			MaxTurns:     maxTurns,
			MaxBudgetUSD: maxBudgetUSD,
			Prices: agentworker.Prices{
				InputUSDPerMTok: inputPrice, OutputUSDPerMTok: outputPrice,
			},
			MinInterval: minInterval,
			Metrics:     m,
		}
	default:
		return fmt.Errorf("AGENT_RUNNER must be claude or openai, got %q", runnerName)
	}

	health := &agentworker.Health{}
	concurrency, err := envConcurrency("AGENT_WORKER_CONCURRENCY")
	if err != nil {
		return err
	}
	worker := agentworker.NewWorker(client, runner).WithConcurrency(concurrency).WithHealth(health)

	healthAddr := os.Getenv("AGENT_HEALTH_ADDR")
	if healthAddr == "" {
		healthAddr = ":8080"
	}
	// Listen synchronously so a bind failure (port already in use, malformed
	// AGENT_HEALTH_ADDR, slow DNS on a hostname address) surfaces here,
	// before the poll loop ever starts — a fixed-duration escape (the
	// previous approach) can't distinguish "still binding" from "bound
	// fine," so under load or a slow resolve it would start Loop anyway
	// and leave the pod with no probe socket for its entire lifetime.
	ln, err := net.Listen("tcp", healthAddr)
	if err != nil {
		return fmt.Errorf("start health server: listen on %s: %w", healthAddr, err)
	}
	healthSrv := newHealthServer(healthAddr, health, m, credentialDomainID, os.Getenv("AGENT_METRICS_ALLOW_CIDR"))
	healthErrCh := make(chan error, 1)
	go func() {
		if err := healthSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			healthErrCh <- err
			return
		}
		healthErrCh <- nil
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	slog.Info("agent-worker: starting poll loop", "version", version, "runner", runnerName, "api_base_url", apiBaseURL, "health_addr", healthAddr)
	loopErr := worker.Loop(ctx)
	slog.Info("agent-worker: stopped")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := healthSrv.Shutdown(shutdownCtx); err != nil {
		slog.Warn("agent-worker: health server shutdown", "err", err)
	}
	if err := <-healthErrCh; err != nil {
		// The health server is only load-bearing for probes, not for the
		// poll loop's own correctness — a failure here shouldn't mask
		// loopErr (the actually meaningful exit reason), just get logged
		// alongside it.
		slog.Warn("agent-worker: health server failed", "err", err)
	}
	// A fatal-auth stop must reach main() as a nonzero exit — otherwise a
	// process supervisor watching for failures sees the same clean return as
	// an ordinary SIGTERM shutdown and never restarts or alerts on an
	// expired/revoked token, even though Loop already logged the error.
	return loopErr
}

// runMCPServe is the stdio MCP server mode. It reads its job-scoped identity
// entirely from env vars set by the ClaudeInvoker that spawned it (see
// claudeinvoker.go's mcpServerConfig.Env) — never from argv or the model,
// matching JobContext's doc comment on why job identity can't be
// model-supplied.
func runMCPServe() error {
	apiBaseURL, err := requireEnv("AGENT_API_BASE_URL")
	if err != nil {
		return err
	}
	apiToken, err := requireEnv("AGENT_API_TOKEN")
	if err != nil {
		return err
	}
	rawJobID, err := requireEnv("AGENT_JOB_ID")
	if err != nil {
		return err
	}
	jobID, err := strconv.ParseInt(rawJobID, 10, 64)
	if err != nil {
		return fmt.Errorf("parse AGENT_JOB_ID: %w", err)
	}
	rawAttempt, err := requireEnv("AGENT_JOB_ATTEMPT")
	if err != nil {
		return err
	}
	attempt, err := strconv.Atoi(rawAttempt)
	if err != nil {
		return fmt.Errorf("parse AGENT_JOB_ATTEMPT: %w", err)
	}
	var conversationID int64
	if raw := os.Getenv("AGENT_JOB_CONV_ID"); raw != "" {
		conversationID, err = strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return fmt.Errorf("parse AGENT_JOB_CONV_ID: %w", err)
		}
	}

	client := agentworker.NewClient(apiBaseURL, apiToken, nil)
	job := agentworker.JobContext{
		JobID:          jobID,
		Attempt:        attempt,
		EventID:        os.Getenv("AGENT_JOB_EVENT_ID"),
		ConversationID: conversationID,
	}
	if raw := os.Getenv("AGENT_JOB_SOURCE_EVENT_IDS"); raw != "" {
		job.SourceEventIDs = strings.Split(raw, ",")
	}
	if raw := os.Getenv("AGENT_JOB_TOOLS"); raw != "" {
		job.Tools = strings.Split(raw, ",")
	}
	srv, err := agentworker.NewMCPServer(client, job)
	if err != nil {
		return fmt.Errorf("build mcp server: %w", err)
	}
	return mcpserver.ServeStdio(srv)
}

func requireEnv(key string) (string, error) {
	v := os.Getenv(key)
	if v == "" {
		return "", errors.New(key + " is required")
	}
	return v, nil
}

// domainIDPattern bounds AGENT_CREDENTIAL_DOMAIN_ID to a shape safe for use
// as a Prometheus label value: no whitespace, no quotes, nothing a pasted
// credential or a free-text blob would accidentally satisfy.
var domainIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:/-]{1,128}$`)

// validateDomainID rejects a credential-domain identifier containing
// characters outside [A-Za-z0-9._:/-] or exceeding 128 characters. This is a
// non-secret operator-chosen label (e.g. a Vault path or account label),
// never the credential itself.
func validateDomainID(id string) error {
	if !domainIDPattern.MatchString(id) {
		return errors.New("AGENT_CREDENTIAL_DOMAIN_ID must match [A-Za-z0-9._:/-]{1,128}")
	}
	return nil
}

// envConcurrency reads the worker concurrency: unset gives 1, anything other
// than an integer in 1..agentworker.MaxConcurrency is refused rather than
// silently clamped.
func envConcurrency(key string) (int, error) {
	raw := os.Getenv(key)
	if raw == "" {
		return 1, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > agentworker.MaxConcurrency {
		return 0, fmt.Errorf("%s must be an integer in 1..%d, got %q", key, agentworker.MaxConcurrency, raw)
	}
	return n, nil
}

func envPositiveInt(key string, def int) (int, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer, got %q", key, raw)
	}
	return n, nil
}

func envDuration(key string, def time.Duration) (time.Duration, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d < 0 {
		return 0, fmt.Errorf("%s must be a non-negative duration, got %q", key, raw)
	}
	return d, nil
}

func requiredEnvFloat(key string) (float64, error) {
	raw, err := requireEnv(key)
	if err != nil {
		return 0, err
	}
	f, err := strconv.ParseFloat(raw, 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) || f < 0 {
		return 0, fmt.Errorf("parse %s: %q must be a finite non-negative number", key, raw)
	}
	return f, nil
}

// envFloat fails loudly on a set-but-unparseable value rather than silently
// falling back to def — an operator who set AGENT_MAX_BUDGET_USD to enforce
// a spending cap and mistyped it would otherwise get an uncapped worker with
// no indication anything was wrong.
func envFloat(key string, def float64) (float64, error) {
	raw := os.Getenv(key)
	if raw == "" {
		return def, nil
	}
	f, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", key, err)
	}
	// strconv.ParseFloat accepts "NaN"/"Inf" as valid IEEE754 values — none
	// of which mean anything as a dollar budget.
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, fmt.Errorf("parse %s: %q is not a finite number", key, raw)
	}
	// A negative value would silently behave like "unset" — ClaudeInvoker.Run
	// only adds --max-budget-usd when MaxBudgetUSD > 0 — turning what an
	// operator intended as a spending cap into an uncapped invocation with
	// no indication anything was wrong.
	if f < 0 {
		return 0, fmt.Errorf("parse %s: %q must not be negative", key, raw)
	}
	return f, nil
}
