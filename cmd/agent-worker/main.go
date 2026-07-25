// Command agent-worker is the production (Option C) headless transport for
// the communication agent: it long-polls mctl-telegram's
// /api/agent/v1/events for due jobs and, for each one, invokes `claude -p`
// with a restricted MCP tool surface (internal/agentworker.NewMCPServer)
// that proxies 1:1 onto the same API. See mctlhq/mctl-telegram#298 and the
// transport decision in the Communication Agent plan for why this replaced
// the originally-scoped Claude Code Channels bridge as the production path.
//
// This binary runs in two modes, selected by --mcp-serve:
//   - default: the poll loop (see run()). Spawns `claude` as a subprocess
//     per job.
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
	"strconv"
	"syscall"
	"time"

	mcpserver "github.com/mark3labs/mcp-go/server"
	"github.com/mctlhq/mctl-telegram/internal/agentworker"
	"github.com/mctlhq/mctl-telegram/internal/audit"
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

// run is the default (poll-loop) mode.
func run() error {
	apiBaseURL, err := requireEnv("AGENT_API_BASE_URL")
	if err != nil {
		return err
	}
	apiToken, err := requireEnv("AGENT_API_TOKEN")
	if err != nil {
		return err
	}

	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve own executable path: %w", err)
	}

	maxBudgetUSD, err := envFloat("AGENT_MAX_BUDGET_USD", 0)
	if err != nil {
		return err
	}

	client := agentworker.NewClient(apiBaseURL, apiToken, nil)
	invoker := &agentworker.ClaudeInvoker{
		ClaudeBin:    os.Getenv("AGENT_CLAUDE_BIN"),
		Self:         self,
		APIBaseURL:   apiBaseURL,
		APIToken:     apiToken,
		SystemPrompt: os.Getenv("AGENT_SYSTEM_PROMPT"),
		MaxBudgetUSD: maxBudgetUSD,
	}
	health := &agentworker.Health{}
	worker := agentworker.NewWorker(client, invoker).WithHealth(health)

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
	healthSrv := newHealthServer(healthAddr, health)
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
	slog.Info("agent-worker: starting poll loop", "version", version, "api_base_url", apiBaseURL, "health_addr", healthAddr)
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
	srv := agentworker.NewMCPServer(client, job)
	return mcpserver.ServeStdio(srv)
}

func requireEnv(key string) (string, error) {
	v := os.Getenv(key)
	if v == "" {
		return "", errors.New(key + " is required")
	}
	return v, nil
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
