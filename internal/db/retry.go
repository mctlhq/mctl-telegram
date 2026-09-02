package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// OpenWithRetry opens a database connection like Open, but for Postgres DSNs
// polls with a bounded retry loop instead of giving up on the first failed
// attempt. This absorbs a known cluster failure mode (mctl-gitops#866): a
// freshly scheduled pod's first outbound TCP dial to Postgres can leave the
// node before the CNI has programmed that pod's NetworkPolicy rules, so the
// very first ping gets "connection refused" even though a retry a few
// hundred milliseconds later succeeds. Absorbing that here means the process
// no longer pays for a container restart on a condition nobody needs to act
// on.
//
// interval is the wait between attempts; timeout bounds the total time spent
// retrying before giving up, at which point the last observed error is
// returned (wrapped with the elapsed bound) and the caller should treat this
// exactly like a failed Open call today.
//
// SQLite DSNs (driverFor reports isPg=false) are never retried: a `file:`
// DSN makes no network call, so there is no netpol race to absorb, and
// looping here would turn an instant, obvious local-dev error (e.g. a typo
// in the database path) into a wait until the deadline. See "Decided: SQLite
// is not retried" in the issue-466 proposal.
func OpenWithRetry(ctx context.Context, dsn string, maxOpenConns, maxIdleConns int, interval, timeout time.Duration) (*sql.DB, error) {
	return openWithRetry(ctx, dsn, maxOpenConns, maxIdleConns, interval, timeout, slog.Default(), Open)
}

// openWithRetry holds the actual loop. The per-attempt call and the logger
// are passed in as parameters (not package-level variables) so tests can
// drive deterministic attempt outcomes and capture log output without
// mutating shared state — important the moment any test in this package
// runs with t.Parallel().
func openWithRetry(
	ctx context.Context,
	dsn string,
	maxOpenConns, maxIdleConns int,
	interval, timeout time.Duration,
	logger *slog.Logger,
	open func(ctx context.Context, dsn string, maxOpenConns, maxIdleConns int) (*sql.DB, error),
) (*sql.DB, error) {
	if _, isPg := driverFor(dsn); !isPg {
		// No network call, no race to retry: single attempt, error as-is.
		return open(ctx, dsn, maxOpenConns, maxIdleConns)
	}

	deadlineCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var lastErr error
	for attempt := 0; ; attempt++ {
		// The attempt itself runs on deadlineCtx, not ctx. Open's only use of
		// the context is PingContext, and a dial into a host that blackholes
		// packets (no RST) blocks for the OS-level TCP connect timeout — on
		// the order of a minute. With the parent ctx the select below cannot
		// fire until that returns, so a single attempt overruns the whole
		// bound: measured at 3x the budget with one slow attempt. Bounding
		// the attempt keeps `timeout` an actual ceiling. Open does not retain
		// the context past the ping, so the returned *sql.DB is unaffected by
		// the cancel on the way out.
		dbConn, err := open(deadlineCtx, dsn, maxOpenConns, maxIdleConns)
		if err == nil {
			logger.Info("db reachable", "attempts", attempt)
			return dbConn, nil
		}
		// Keep the last error that says something about the database. Once
		// deadlineCtx expires mid-attempt the driver reports the expiry
		// itself, and recording that would collapse the give-up error back
		// into context.DeadlineExceeded — the exact loss this loop avoids.
		if !errors.Is(err, context.DeadlineExceeded) {
			lastErr = err
		}
		logger.Warn("db not reachable yet, retrying", "err", err, "attempt", attempt, "wait", interval)

		select {
		case <-time.After(interval):
			// Next attempt.
		case <-deadlineCtx.Done():
			if errors.Is(deadlineCtx.Err(), context.DeadlineExceeded) {
				// Give-up case: preserve the real cause (e.g. "connection
				// refused", "password authentication failed") instead of
				// collapsing it into context.DeadlineExceeded, which would
				// discard exactly the diagnostic this change exists to
				// produce.
				if lastErr == nil {
					// Every attempt was cut short by the deadline before the
					// driver could report anything of its own.
					return nil, fmt.Errorf("db not reachable after %s: %w", timeout, deadlineCtx.Err())
				}
				return nil, fmt.Errorf("db not reachable after %s: %w", timeout, lastErr)
			}
			// Shutdown (SIGINT/SIGTERM) canceled the parent ctx: return
			// promptly rather than finishing out the poll window.
			return nil, ctx.Err()
		}
	}
}
