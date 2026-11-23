package sweeper

import (
	"context"
	"log/slog"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/pa"
	"github.com/mctlhq/mctl-telegram/internal/pa/convo"
	"github.com/mctlhq/mctl-telegram/internal/pa/linking"
)

// PAStateSweeperInterval is how often PAState() wakes up. Conversations live
// at most 24 hours from creation, so an hourly sweep keeps the real lifetime
// within TTL + 1h. Loading an expired conversation is refused on the request
// path regardless (LoadPAFragments checks expires_at), so the sweep is the
// hard delete, not the gate.
const PAStateSweeperInterval = time.Hour

// PAState hard-deletes Personal Assistant state past its lifetime until ctx
// is cancelled: expired or closed conversations with their fragments,
// expired callback ids, pa_updates dedup rows older than
// pa.UpdatesRetention (issue #1313, owner decision 2026-11-18), and linking
// secrets past db.PALinkSecretRetention after their expiry (#1338). It is
// started only when PA_ENABLED is true. Principal lock rows are not its
// job: PALocks sweeps them, with the PA on or off.
func PAState(ctx context.Context, store convo.Store) {
	ticker := time.NewTicker(PAStateSweeperInterval)
	defer ticker.Stop()
	PAStateSweepOnce(ctx, store, time.Now())
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			PAStateSweepOnce(ctx, store, time.Now())
		}
	}
}

// PAStateSweepOnce runs one pass at now. Exported for the server's tests.
func PAStateSweepOnce(ctx context.Context, store convo.Store, now time.Time) {
	r, err := store.SweepPAState(ctx, now, now.Add(-pa.UpdatesRetention))
	if err != nil {
		slog.Warn("pa state sweep failed", "err", err)
		return
	}
	if r != (convo.SweepResult{}) {
		slog.Info("pa state sweep", "conversations", r.Conversations, "fragments", r.Fragments,
			"callbacks", r.Callbacks, "updates", r.Updates, "link_secrets", r.LinkSecrets)
	}
}

// PALockSweeperInterval is how often PALocks wakes up: the PAState
// interval, so a lock row lives at most pa.UpdatesRetention plus one hour
// unused, as it did while PAState swept it.
const PALockSweeperInterval = PAStateSweeperInterval

// PALockSweeper is the principal lock sweep: (*db.Store).SweepPAPrincipalLocks.
type PALockSweeper interface {
	SweepPAPrincipalLocks(ctx context.Context, before time.Time) (int64, error)
}

// PALocks deletes principal lock rows unused for pa.UpdatesRetention until
// ctx is cancelled (#1318). The server starts it whatever PA_ENABLED says:
// an account deletion keeps an admitted principal's lock row as the
// deletion fence (db.purgePAPrincipals), and a PA turned off before the
// row aged out must still delete it, since it carries the principal's
// Telegram id. It is the only sweep of the table; PAState leaves it alone.
func PALocks(ctx context.Context, s PALockSweeper) {
	ticker := time.NewTicker(PALockSweeperInterval)
	defer ticker.Stop()
	PALocksSweepOnce(ctx, s, time.Now())
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			PALocksSweepOnce(ctx, s, time.Now())
		}
	}
}

// PALocksSweepOnce runs one pass at now: rows unused since now minus
// pa.UpdatesRetention go. A failed pass is logged and retried at the next
// interval; it never reads as "nothing to delete".
func PALocksSweepOnce(ctx context.Context, s PALockSweeper, now time.Time) {
	n, err := s.SweepPAPrincipalLocks(ctx, now.Add(-pa.UpdatesRetention))
	if err != nil {
		slog.Warn("pa lock sweep failed", "err", err)
		return
	}
	if n > 0 {
		slog.Info("pa lock sweep", "locks", n)
	}
}

// PALinkSweeperInterval is how often PALinks wakes up. It is well under
// linking.PendingMaxAge, so a connection the linking flow abandoned is
// failed, and any tokens it holds revoked, within PendingMaxAge plus one
// interval of its last transition.
const PALinkSweeperInterval = 5 * time.Minute

// PALinkSweepLimit bounds each listing of one ExpireStale pass. A pass that
// fills it leaves the rest for the next interval.
const PALinkSweepLimit = 200

// PALinkExpirer is the linking flow's sweep: (*linking.Service).ExpireStale.
type PALinkExpirer interface {
	ExpireStale(ctx context.Context, limit int) (linking.SweepResult, error)
}

// PALinks runs the linking sweep (#1338) until ctx is cancelled: every
// connection whose link secret expired unused, or that stayed pending past
// linking.PendingMaxAge, is failed and its tokens revoked. It is started
// only when PA_ENABLED is true and the server runs the linking flow.
func PALinks(ctx context.Context, e PALinkExpirer) {
	ticker := time.NewTicker(PALinkSweeperInterval)
	defer ticker.Stop()
	PALinksSweepOnce(ctx, e)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			PALinksSweepOnce(ctx, e)
		}
	}
}

// PALinksSweepOnce runs one pass. A connection the pass could not observe
// or fail is counted in Errors and left for the next pass; the pass logs
// the joined error and the counts rather than stopping at the first.
func PALinksSweepOnce(ctx context.Context, e PALinkExpirer) linking.SweepResult {
	r, err := e.ExpireStale(ctx, PALinkSweepLimit)
	if err != nil {
		slog.Warn("pa link sweep: incomplete", "failed", r.Failed, "skipped", r.Skipped, "errors", r.Errors, "err", err)
		return r
	}
	if r != (linking.SweepResult{}) {
		slog.Info("pa link sweep", "failed", r.Failed, "skipped", r.Skipped, "errors", r.Errors)
	}
	return r
}
