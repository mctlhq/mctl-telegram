// Command glovo-provider-worker is the private, fake-provider-only worker of
// the Glovo provider boundary. Its only control-plane I/O is an HTTP client
// for the mctl-api command bridge: it claims commands, asks for a write permit
// before each mutation, runs the effect against an in-process fake store and
// posts one result. It holds no Temporal credential and no real adapter.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/bridgeclient"
	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/executor"
	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/fairness"
	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/fakeonly"
	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/fakestore"
	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/health"
	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/obs"
	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/poller"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		fmt.Println(version)
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if err := run(ctx, os.Environ()); err != nil {
		// Names only; run never puts values in errors.
		fmt.Fprintln(os.Stderr, "glovo-provider-worker:", err)
		os.Exit(1)
	}
}

// run validates the gates, starts the poller and probes, and blocks until ctx
// is cancelled. It returns nil on a clean shutdown.
func run(ctx context.Context, env []string) error {
	if err := fakeonly.Check(env); err != nil {
		return err
	}
	cfg, err := LoadConfig(env)
	if err != nil {
		return err
	}
	cred := bridgeclient.FileCredential{Path: cfg.CredentialFile}
	if _, err := cred.Get(); err != nil {
		return err
	}
	log := slog.New(obs.NewRedactingHandler(slog.NewJSONHandler(os.Stdout, nil)))
	metrics := obs.NewMetrics()
	if cfg.Disabled {
		metrics.KillSwitch.Set(1)
	}
	breaker := fairness.NewBreaker(5)
	disabled := func() bool { return cfg.Disabled }
	ex := &executor.Executor{Store: fakestore.New(), Breaker: breaker, Disabled: disabled, Metrics: metrics, WorkerIdentity: cfg.WorkerIdentity}
	hs := &health.State{Disabled: disabled, BreakerOpen: breaker.IsOpen, Window: max(3*cfg.PollInterval, 30*time.Second)}
	p := &poller.Poller{
		Client: bridgeclient.New(cfg.BaseURL, cred, nil), Exec: ex, Limiter: fairness.NewLimiter(4), Health: hs,
		Metrics: metrics, Log: log,
		Cfg: poller.Config{WorkerIdentity: cfg.WorkerIdentity, ClaimMax: cfg.ClaimMax, PollInterval: cfg.PollInterval, StopTimeout: cfg.StopTimeout},
	}
	srv := health.NewServer(cfg.HealthAddr, hs, metrics.Registry)
	srvErr := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			srvErr <- err
		}
	}()
	log.Info("worker started", "version", version, "identity", cfg.WorkerIdentity, "kill_switch", cfg.Disabled)

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	pollDone := make(chan struct{})
	go func() { _ = p.Run(runCtx); close(pollDone) }()

	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-srvErr:
	}
	log.Info("shutting down")
	hs.SetShuttingDown()
	cancel()
	<-pollDone // bounded by StopTimeout inside Run
	shutdownHTTP(srv)
	return runErr
}

func shutdownHTTP(srv *http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}
