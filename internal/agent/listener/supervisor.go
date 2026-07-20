package listener

import (
	"context"
	"log/slog"
	"time"

	gotdtelegram "github.com/gotd/td/telegram"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

type Pool interface {
	Pin(userID int64)
	Unpin(userID int64)
	Borrow(ctx context.Context, userID int64, fn func(ctx context.Context, c *gotdtelegram.Client) error) error
}

type AccountResolver interface {
	ListListenerEnabledProfiles(ctx context.Context) ([]db.AgentProfile, error)
	GetTelegramID(ctx context.Context, userID int64) (int64, error)
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
			slog.Warn("agent supervisor: resolve tg id failed", "user_id", p.UserID, "err", err)
			continue
		}
		if !l.SetAccount(p.UserID, tgID) {
			continue
		}
		pool.Pin(p.UserID)
		if err := pool.Borrow(ctx, p.UserID, func(context.Context, *gotdtelegram.Client) error { return nil }); err != nil {
			slog.Warn("agent supervisor: borrow failed", "user_id", p.UserID, "err", err)
		}
	}
}
