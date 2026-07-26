package listener

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	gotdtelegram "github.com/gotd/td/telegram"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

const supervisorBorrowTimeout = 10 * time.Second

type Pool interface {
	Pin(userID int64)
	Unpin(userID int64)
	Borrow(ctx context.Context, userID int64, fn func(ctx context.Context, c *gotdtelegram.Client) error) error
}

type AccountResolver interface {
	ListListenerEnabledProfiles(ctx context.Context) ([]db.AgentProfile, error)
	GetTelegramID(ctx context.Context, userID int64) (int64, error)
}

// StoreResolver adapts the shared db.Store to the supervisor without adding
// listener-specific methods to the core store API. Only active hosted Telegram
// accounts with a known Telegram user id are eligible for a live listener.
type StoreResolver struct{ Store *db.Store }

func (r StoreResolver) ListListenerEnabledProfiles(ctx context.Context) ([]db.AgentProfile, error) {
	return r.Store.ListListenerEnabledProfiles(ctx)
}

func (r StoreResolver) GetTelegramID(ctx context.Context, userID int64) (int64, error) {
	var tgID sql.NullInt64
	err := r.Store.DB.QueryRowContext(ctx,
		`SELECT telegram_user_id
		   FROM telegram_accounts
		  WHERE user_id = $1 AND revoked_at IS NULL AND mode = 'hosted'
		  ORDER BY connected_at DESC
		  LIMIT 1`,
		userID,
	).Scan(&tgID)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("resolve Telegram id for user %d: %w", userID, err)
	}
	if !tgID.Valid || tgID.Int64 == 0 {
		return 0, nil
	}
	return tgID.Int64, nil
}

func RunSupervisor(ctx context.Context, l *Listener, pool Pool, res AccountResolver, interval time.Duration) {
	if interval <= 0 {
		interval = 15 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	reconcile(ctx, l, pool, res)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			reconcile(ctx, l, pool, res)
		}
	}
}

func reconcile(ctx context.Context, l *Listener, pool Pool, res AccountResolver) {
	profiles, err := res.ListListenerEnabledProfiles(ctx)
	if err != nil {
		slog.Warn("agent supervisor: list profiles failed", "err", err)
		return
	}

	enabled := make(map[int64]struct{}, len(profiles))
	for _, p := range profiles {
		enabled[p.UserID] = struct{}{}
	}
	// Reconcile removals as well as additions. Otherwise disabling a profile
	// leaves its pool entry pinned forever and exempt from idle collection.
	for _, userID := range l.ActiveUserIDs() {
		if _, ok := enabled[userID]; ok {
			continue
		}
		pool.Unpin(userID)
		l.RemoveAccount(userID)
	}

	for _, p := range profiles {
		tgID, err := res.GetTelegramID(ctx, p.UserID)
		if err != nil {
			// Resolver failures can be transient database or context errors.
			// Preserve an already-running listener and retry next tick.
			slog.Warn("agent supervisor: resolve tg id failed", "user_id", p.UserID, "err", err)
			continue
		}
		if tgID == 0 {
			// A profile can stay listener_enabled while its hosted MTProto
			// session is revoked (for example AUTH_KEY_DUPLICATED). Remove its
			// handler and pin until OAuth creates a fresh active session; the
			// next reconciliation automatically installs it again.
			if _, active := l.get(p.UserID); active {
				pool.Unpin(p.UserID)
				l.RemoveAccount(p.UserID)
			}
			continue
		}
		if !l.SetAccountProfile(p.UserID, tgID, p.SenderAllowlist) {
			continue
		}
		pool.Pin(p.UserID)
		// A broken Telegram connection must not block reconciliation for every
		// later account. Bound each liveness probe independently; the next tick
		// retries the account while the loop continues serving the rest.
		borrowCtx, cancel := context.WithTimeout(ctx, supervisorBorrowTimeout)
		err = pool.Borrow(borrowCtx, p.UserID, func(context.Context, *gotdtelegram.Client) error { return nil })
		cancel()
		if err != nil {
			slog.Warn("agent supervisor: borrow failed", "user_id", p.UserID, "err", err)
		}
	}
}
