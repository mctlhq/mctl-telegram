package telegram

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/gotd/td/tg"
	"golang.org/x/sync/singleflight"
)

// recentDialogsLimit is the dialog-list page every peer lookup scans.
const recentDialogsLimit = 200

// defaultDialogsSnapshotTTL bounds how long one messages.getDialogs answer
// serves peer lookups for an account. A burst of parallel get_messages calls
// used to send one getDialogs each, and Telegram answers that with
// FLOOD_WAIT_30 (issue #995); 45 seconds covers such a burst while keeping
// the list close to live.
const defaultDialogsSnapshotTTL = 45 * time.Second

// maxDialogsFetchAttempts bounds how often a caller re-joins the group after
// the fetch it was waiting on was cancelled by the call that started it.
const maxDialogsFetchAttempts = 3

// dialogsSnapshots holds one recent getDialogs answer per account and
// collapses concurrent fetches for the same account into a single call.
// Snapshots are used only to find a peer and its access hash; anything that
// reports dialog state to the caller (unread counts, list_dialogs) still
// fetches live.
type dialogsSnapshots struct {
	mu    sync.Mutex
	m     map[int64]*dialogsSnapshot
	group singleflight.Group
}

type dialogsSnapshot struct {
	res       tg.MessagesDialogsClass
	fetchedAt time.Time
}

func fetchRecentDialogs(ctx context.Context, api *tg.Client) (tg.MessagesDialogsClass, error) {
	res, err := api.MessagesGetDialogs(ctx, &tg.MessagesGetDialogsRequest{
		Limit:      recentDialogsLimit,
		OffsetPeer: &tg.InputPeerEmpty{},
	})
	if err != nil {
		return nil, fmt.Errorf("MessagesGetDialogs: %w", err)
	}
	return res, nil
}

// recentDialogs returns the account's recent dialog list. cached reports
// whether the answer came from a snapshot taken by an earlier call, so a
// caller that misses a peer in it can ask once more with fresh=true before
// falling back. A nil cache or a zero userID always fetches live.
//
// Errors are never cached: a failed fetch leaves no snapshot behind, and the
// next call fetches again.
func (pc *PeerCache) recentDialogs(ctx context.Context, api *tg.Client, userID int64, fresh bool) (res tg.MessagesDialogsClass, cached bool, err error) {
	if pc == nil || userID == 0 {
		res, err = fetchRecentDialogs(ctx, api)
		return res, false, err
	}
	s := &pc.dialogs
	for attempt := 1; ; attempt++ {
		if !fresh {
			s.mu.Lock()
			snap, ok := s.m[userID]
			if ok && pc.now().Sub(snap.fetchedAt) < pc.dialogsTTL {
				s.mu.Unlock()
				return snap.res, true, nil
			}
			s.mu.Unlock()
		}

		ch := s.group.DoChan(strconv.FormatInt(userID, 10), func() (any, error) {
			r, err := fetchRecentDialogs(ctx, api)
			if err != nil {
				return nil, err
			}
			s.mu.Lock()
			if s.m == nil {
				s.m = make(map[int64]*dialogsSnapshot)
			}
			s.m[userID] = &dialogsSnapshot{res: r, fetchedAt: pc.now()}
			s.mu.Unlock()
			return r, nil
		})
		var out singleflight.Result
		select {
		case <-ctx.Done():
			return nil, false, ctx.Err()
		case out = <-ch:
		}
		if out.Err == nil {
			// A fetch joined while in flight is at least as new as any
			// snapshot, so it counts as fresh.
			return out.Val.(tg.MessagesDialogsClass), false, nil
		}
		// The shared fetch ran under the context of whichever call started
		// it. If that call was cancelled while ours is still live, its
		// cancellation is not our failure. Go back through the group rather
		// than fetch alone, so the callers that were waiting on it elect one
		// new fetch between them instead of each sending their own.
		if out.Shared && ctx.Err() == nil && attempt < maxDialogsFetchAttempts &&
			(errors.Is(out.Err, context.Canceled) || errors.Is(out.Err, context.DeadlineExceeded)) {
			continue
		}
		return nil, false, out.Err
	}
}

// sweepDialogs drops snapshots past their TTL.
func (pc *PeerCache) sweepDialogs(now time.Time) {
	s := &pc.dialogs
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, snap := range s.m {
		if now.Sub(snap.fetchedAt) >= pc.dialogsTTL {
			delete(s.m, id)
		}
	}
}
