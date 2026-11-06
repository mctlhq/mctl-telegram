package sweeper

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/telegram"
)

const (
	// RevokedSessionPause spaces the Telegram logouts of the cleanup.
	RevokedSessionPause = 3 * time.Second
	// RevokedSessionInterval is how often the cleanup retries what is left.
	RevokedSessionInterval = time.Hour
	// LogOutReasonRevokedCleanup labels mctl_login_logout_total for the cleanup.
	LogOutReasonRevokedCleanup = "revoked_cleanup"

	revokedSessionBatch = 50
)

// RevokedSessionDeps are the Telegram side of the cleanup.
type RevokedSessionDeps struct {
	LogOut         func(ctx context.Context, data []byte) error
	KeyID          func(data []byte) (string, error)
	AlreadyEnded   func(err error) bool
	CountLogOut    func(outcome string)
	PauseBetween   time.Duration
	RepeatInterval time.Duration
}

// RevokedSessionResult counts one cleanup pass.
type RevokedSessionResult struct {
	Erased, LoggedOut, SharedKey, Failed int
}

// sessionReasonNeedsLogOut says which revoked rows may still hold a working
// authorization a person expects to be gone: an explicit disconnect, a
// replaced login, and rows with no reason. Those are mostly from before reasons
// were recorded; the deprecated SweepExpiredSessions also leaves none, and for
// a session that already ended the logout gets a 401 and the row is erased. The
// rest are only erased: Telegram rejected the key (unauthorized), the sign-in
// never finished (login_incomplete), or the session ran out by age and is left
// to expire at Telegram.
func sessionReasonNeedsLogOut(reason string) bool {
	switch reason {
	case "", "disconnect", "superseded":
		return true
	}
	return false
}

// RevokedSessions runs the cleanup until ctx ends, and again each interval so
// that a logout which failed is retried.
func RevokedSessions(ctx context.Context, store *db.Store, deps RevokedSessionDeps) {
	ticker := time.NewTicker(deps.RepeatInterval)
	defer ticker.Stop()
	for {
		res, err := CleanRevokedSessions(ctx, store, deps)
		if err != nil && ctx.Err() == nil {
			slog.Warn("revoked session cleanup failed", "err", err)
		}
		if res != (RevokedSessionResult{}) {
			slog.Info("revoked session cleanup", "erased", res.Erased, "logged_out", res.LoggedOut,
				"shared_key", res.SharedKey, "failed", res.Failed)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// CleanRevokedSessions makes one pass over the revoked rows that still hold a
// session. A row that could not be handled safely keeps its session and counts
// as failed, for the next pass to retry: erasing it would lose the only way to
// end that authorization.
func CleanRevokedSessions(ctx context.Context, store *db.Store, deps RevokedSessionDeps) (RevokedSessionResult, error) {
	var res RevokedSessionResult
	var after int64
	for {
		batch, err := store.RevokedSessionsWithBlob(ctx, after, revokedSessionBatch)
		if err != nil {
			return res, err
		}
		if len(batch) == 0 {
			return res, nil
		}
		for _, row := range batch {
			after = row.ID
			if err := ctx.Err(); err != nil {
				return res, err
			}
			if err := cleanRevokedSession(ctx, store, deps, row, &res); err != nil {
				res.Failed++
				slog.Warn("revoked session not cleaned", "row", row.ID, "err", err)
			}
		}
	}
}

func cleanRevokedSession(ctx context.Context, store *db.Store, deps RevokedSessionDeps, row db.RevokedSessionBlob, res *RevokedSessionResult) error {
	if !sessionReasonNeedsLogOut(row.Reason) {
		return erase(ctx, store, row, res)
	}
	data, err := store.OpenRevokedSession(row)
	if err != nil {
		return err
	}
	key, err := deps.KeyID(data)
	if errors.Is(err, telegram.ErrNoAuthKey) {
		return erase(ctx, store, row, res)
	}
	if err != nil {
		return err
	}
	shared, err := keyInUse(ctx, store, deps, row, key)
	if err != nil {
		return err
	}
	if shared {
		res.SharedKey++
		return erase(ctx, store, row, res)
	}
	if err := logOut(ctx, deps, data); err != nil {
		return err
	}
	res.LoggedOut++
	return erase(ctx, store, row, res)
}

// keyInUse reports whether an active session holds the same auth key. Logging
// such a row out would end a session someone is using.
func keyInUse(ctx context.Context, store *db.Store, deps RevokedSessionDeps, row db.RevokedSessionBlob, key string) (bool, error) {
	active, err := store.ActiveSessionsSharingAccount(ctx, row.UserID, row.TelegramUserID)
	if err != nil {
		return false, err
	}
	for _, data := range active {
		id, err := deps.KeyID(data)
		if errors.Is(err, telegram.ErrNoAuthKey) {
			continue
		}
		if err != nil {
			return false, err
		}
		if id == key {
			return true, nil
		}
	}
	return false, nil
}

func logOut(ctx context.Context, deps RevokedSessionDeps, data []byte) error {
	err := deps.LogOut(ctx, data)
	outcome := "ok"
	if err != nil && !deps.AlreadyEnded(err) {
		outcome = "error"
	}
	if deps.CountLogOut != nil {
		deps.CountLogOut(outcome)
	}
	select {
	case <-ctx.Done():
	case <-time.After(deps.PauseBetween):
	}
	if outcome == "error" {
		return err
	}
	return nil
}

func erase(ctx context.Context, store *db.Store, row db.RevokedSessionBlob, res *RevokedSessionResult) error {
	if err := store.EraseRevokedSession(ctx, row.ID); err != nil {
		return err
	}
	res.Erased++
	return nil
}
