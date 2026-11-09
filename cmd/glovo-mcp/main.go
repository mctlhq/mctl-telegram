// Command glovo-mcp is the Glovo MCP facade: an OAuth-protected Streamable
// HTTP MCP resource that hands every tool to mctl-api. It holds no secrets,
// no Temporal client and no Glovo access. See docs/glovo-mcp.md.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"

	"github.com/mctlhq/mctl-telegram/internal/audit"
	"github.com/mctlhq/mctl-telegram/internal/glovo/authn"
	"github.com/mctlhq/mctl-telegram/internal/glovo/config"
	"github.com/mctlhq/mctl-telegram/internal/glovo/contract"
	"github.com/mctlhq/mctl-telegram/internal/glovo/facade"
	"github.com/mctlhq/mctl-telegram/internal/glovo/mctlapi"
)

// version is set with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "glovo-mcp:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	logger := slog.New(audit.NewRedactingHandler(slog.NewJSONHandler(os.Stdout, nil)))
	c, err := contract.Load()
	if err != nil {
		return fmt.Errorf("contract: %w", err)
	}
	otel.SetTextMapPropagator(propagation.TraceContext{})

	opt := facade.Options{Config: cfg, Contract: c, Logger: logger, Version: version}
	if cfg.Enabled {
		opt.Verifier = authn.New(authn.Config{
			Issuer: cfg.Issuer, Resource: cfg.Resource, JWKSURL: cfg.JWKSURL, GlovoScopes: c.Scopes,
		})
		opt.API = mctlapi.NewHTTPClient(cfg.APIBaseURL, mctlapi.FileCredential(cfg.APICredentialFile), nil)
	}
	f, err := facade.New(opt)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	if cfg.Enabled {
		opt.API.(*mctlapi.HTTPClient).OnCall = f.ObserveUpstream
		go loadJWKS(ctx, opt.Verifier, logger)
	}
	ln, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: f.Handler(), ReadHeaderTimeout: 10 * time.Second}
	logger.Info("glovo-mcp listening", slog.String("addr", ln.Addr().String()),
		slog.Bool("enabled", cfg.Enabled), slog.String("version", version))
	return facade.Serve(ctx, srv, ln, f, cfg.DrainTimeout)
}

// loadJWKS fetches the JWKS until it succeeds; readiness stays false meanwhile.
func loadJWKS(ctx context.Context, v *authn.Verifier, logger *slog.Logger) {
	for !v.JWKSLoaded() {
		if err := v.Refresh(ctx); err != nil {
			logger.Warn("jwks fetch failed", slog.String("error", err.Error()))
			select {
			case <-ctx.Done():
				return
			case <-time.After(10 * time.Second):
			}
		}
	}
}
