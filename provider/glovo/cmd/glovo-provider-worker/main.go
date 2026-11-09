// Command glovo-provider-worker is the private, fake-provider-only Temporal
// worker for the Glovo provider boundary. It holds exactly one Temporal
// client handle, used only by its own poller, and no real provider adapter.
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

	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/interceptor"
	"go.temporal.io/sdk/worker"

	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/activities"
	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/basket"
	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/bridge"
	bridgefake "github.com/mctlhq/mctl-telegram/provider/glovo/internal/bridge/fake"
	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/fairness"
	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/fakeonly"
	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/fakestore"
	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/health"
	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/obs"
	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/workflows"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

// poller is the worker's own task poller; it is the only Temporal handle.
type poller interface {
	Start() error
	Stop()
}

// dialer connects to Temporal and returns the poller plus a close function.
type dialer func(cfg Config, w workerParts) (poller, func(), error)

// workerParts is what gets registered on the worker.
type workerParts struct {
	Acts         *activities.Activities
	Interceptors []interceptor.WorkerInterceptor
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		fmt.Println(version)
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if err := run(ctx, os.Environ(), dialTemporal); err != nil {
		// Names only; run never puts values in errors.
		fmt.Fprintln(os.Stderr, "glovo-provider-worker:", err)
		os.Exit(1)
	}
}

// run validates the gates, starts the poller and probes, and blocks until ctx
// is cancelled. It returns nil on a clean shutdown.
func run(ctx context.Context, env []string, dial dialer) error {
	if err := fakeonly.Check(env); err != nil {
		return err
	}
	cfg, err := LoadConfig(env)
	if err != nil {
		return err
	}
	log := slog.New(obs.NewRedactingHandler(slog.NewJSONHandler(os.Stdout, nil)))
	metrics := obs.NewMetrics()
	if cfg.Disabled {
		metrics.KillSwitch.Set(1)
	}
	breaker := fairness.NewBreaker(5)

	// The only bridge compiled in is the deterministic fake, empty here: it
	// resolves no tenant, so every request is refused until a production
	// bridge exists (mctl-agents#1043, mctl-api#953/#954).
	var cb bridge.ControlBridge = bridge.FailClosed(bridgefake.New(time.Now), bridge.DefaultTimeout)

	acts := &activities.Activities{
		Bridge: cb, Store: fakestore.New(), Ledger: basket.NewLedger(), Drafts: activities.NewDraftStore(),
		Breaker: breaker, Limiter: fairness.NewLimiter(4),
		Disabled: func() bool { return cfg.Disabled }, Log: log, Metrics: metrics,
	}
	hs := &health.State{Disabled: acts.Disabled, BreakerOpen: func() bool { return !breaker.Allow() }}
	srv := health.NewServer(cfg.HealthAddr, hs, metrics.Registry)
	srvErr := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			srvErr <- err
		}
	}()

	p, closeFn, err := dial(cfg, workerParts{Acts: acts, Interceptors: []interceptor.WorkerInterceptor{metrics.Interceptor()}})
	if err != nil {
		shutdownHTTP(srv)
		return fmt.Errorf("connect temporal: %w", err)
	}
	if err := p.Start(); err != nil {
		closeFn()
		shutdownHTTP(srv)
		return fmt.Errorf("start worker: %w", err)
	}
	hs.SetPollerRunning(true)
	log.Info("worker started", "version", version, "namespace", cfg.Namespace, "task_queue", cfg.TaskQueue, "kill_switch", cfg.Disabled)

	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-srvErr:
	}
	log.Info("shutting down")
	hs.SetShuttingDown()
	p.Stop() // bounded by WorkerStopTimeout
	closeFn()
	shutdownHTTP(srv)
	return runErr
}

func shutdownHTTP(srv *http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}

// dialTemporal is the real dialer. The client it creates is handed to
// worker.New and nowhere else.
func dialTemporal(cfg Config, w workerParts) (poller, func(), error) {
	opts := client.Options{HostPort: cfg.HostPort, Namespace: cfg.Namespace}
	tlsCfg, err := cfg.TLSConfig()
	if err != nil {
		return nil, nil, err
	}
	if tlsCfg != nil {
		opts.ConnectionOptions = client.ConnectionOptions{TLS: tlsCfg}
	}
	c, err := client.Dial(opts)
	if err != nil {
		return nil, nil, err
	}
	wk := worker.New(c, cfg.TaskQueue, worker.Options{
		WorkerStopTimeout: cfg.StopTimeout,
		Interceptors:      w.Interceptors,
	})
	wk.RegisterWorkflow(workflows.GlovoOrderWorkflow)
	wk.RegisterActivity(w.Acts)
	return wk, c.Close, nil
}
