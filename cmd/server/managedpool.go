package main

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/mctlhq/mctl-telegram/internal/agentapi"
	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/auth/localjwt"
	"github.com/mctlhq/mctl-telegram/internal/config"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

// managedPoolEnabled reports whether the managed-runtime pool credential
// (ADR 0008) is wired: MANAGED_RUNTIME_ENABLED on and a signing secret set.
func managedPoolEnabled(cfg *config.Config) bool {
	return cfg.ManagedRuntimeEnabled && cfg.OAUTHJWTSecret != ""
}

// wireManagedPool is the whole managed-runtime pool wiring main uses, kept in
// one function so a test drives exactly what the server runs. With the pool
// enabled it mounts POST /api/agent/pool-token on mux behind adminMW, chains
// the claim-only pool provider after agentProvider (whose agent and job
// providers both refuse aud=agent-pool) and turns on the pool claim branch of
// agentSrv. With it disabled it changes nothing: the mint route is 404 and a
// pool token is refused by every provider on the agent surface. Returns the
// provider to mount the agent surface under.
func wireManagedPool(cfg *config.Config, mux chi.Router, adminMW func(http.Handler) http.Handler,
	agentProvider auth.Provider, agentSrv *agentapi.Server, revocations *localjwt.RevocationCache) auth.Provider {
	if !managedPoolEnabled(cfg) {
		return agentProvider
	}
	issuer := strings.TrimRight(cfg.PublicBaseURL, "/")
	mux.With(adminMW).Post("/api/agent/pool-token",
		agentapi.NewPoolTokenHandler([]byte(cfg.OAUTHJWTSecret), issuer))
	if poolProvider := selectAgentPoolProvider(cfg, revocations); poolProvider != nil {
		agentProvider = chainProvider{agentProvider, poolProvider}
	}
	agentSrv.WithManagedClaims(agentapi.ManagedClaimConfig{
		MaxInflightPerAccount: cfg.ManagedMaxInflightPerAccount,
		MaxJobCostUSD:         cfg.ManagedMaxJobCostUSD,
		Revocations:           revocations,
	})
	// The spend caps are enforced inside the claim transaction. They are wired
	// with the pool and only then: without the flag nothing reserves budget.
	if agentSrv.Store != nil && cfg.ManagedMaxJobCostUSD > 0 {
		agentSrv.Store.WithManagedBudget(db.ManagedBudget{
			PerJobUSD:       cfg.ManagedMaxJobCostUSD,
			AccountDayUSD:   cfg.ManagedBudgetUSDPerAccountDay,
			AccountMonthUSD: cfg.ManagedBudgetUSDPerAccountMonth,
			GlobalDayUSD:    cfg.ManagedBudgetUSDGlobalDay,
		})
	}
	slog.Info("managed runtime pool credential enabled", "max_inflight_per_account", cfg.ManagedMaxInflightPerAccount)
	return agentProvider
}

// warnManagedJobsPaused surfaces the flag-off state of the managed runtime.
// A managed account's jobs are claimable only by the pool, which exists only
// while MANAGED_RUNTIME_ENABLED is on; with it off they are paused (and, with
// operator routing on, routed to the operator once unclaimed past the
// threshold) until the account moves back to runtime own. The count is logged
// so turning the flag off is never silent. A failed count is logged as such,
// never as zero.
func warnManagedJobsPaused(ctx context.Context, cfg *config.Config, store *db.Store) {
	if managedPoolEnabled(cfg) {
		return
	}
	n, err := store.CountManagedAccountsWithPendingJobs(ctx)
	if err != nil {
		slog.Warn("managed runtime disabled; could not count managed accounts with pending jobs", "err", err)
		return
	}
	if n > 0 {
		slog.Warn("managed runtime disabled: jobs of managed accounts are paused until the account switches back to runtime own",
			"managed_accounts_with_pending_jobs", n)
	}
}
