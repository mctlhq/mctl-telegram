// Package actor holds the single rule for deriving the Telegram user id sent
// as X-MCTL-Surface-Actor on mctl-api relay calls, shared by the work-context
// adapter and the human-input adapter.
package actor

import (
	"context"
	"fmt"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

// Resolve derives the relay actor. It is deliberately the ONLY source: the
// Saved Messages self-peer id the listener already authenticated (selfTGID),
// cross-checked against Store.TelegramIDByUserID for the same internal user.
// A mismatch or an unresolved id fails closed — ok=false, err=nil, no
// mctl-api call made — never falling back to a deployment allowlist.
func Resolve(ctx context.Context, store *db.Store, userID, selfTGID int64) (actorTGID int64, ok bool, err error) {
	if selfTGID <= 0 {
		return 0, false, nil
	}
	stored, found, err := store.TelegramIDByUserID(ctx, userID)
	if err != nil {
		return 0, false, fmt.Errorf("resolve work-context actor: %w", err)
	}
	if !found || stored != selfTGID {
		return 0, false, nil
	}
	return selfTGID, true, nil
}
