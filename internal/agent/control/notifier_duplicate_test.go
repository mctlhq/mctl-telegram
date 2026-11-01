package control

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/agent/executor"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

// dupSelfSender answers every notification send the way Telegram answers a
// retry whose random_id it already has: RANDOM_ID_DUPLICATE, mapped to
// executor.ErrAlreadyDelivered by the production SelfSender (#1029).
type dupSelfSender struct {
	calls    int
	locateID int64
}

func (f *dupSelfSender) SendToSelf(context.Context, int64, string) (int64, error) {
	return 0, fmt.Errorf("unexpected Reply send")
}

func (f *dupSelfSender) SendToSelfWithRandomID(context.Context, int64, int64, string) (int64, error) {
	f.calls++
	return 0, fmt.Errorf("send to self: %w", executor.ErrAlreadyDelivered)
}

func (f *dupSelfSender) LocateSelfDelivered(context.Context, int64, string, time.Time) (int64, bool, error) {
	return f.locateID, f.locateID != 0, nil
}

func notificationRow(t *testing.T, store *db.Store, id int64) (status string, msgID sql.NullInt64) {
	t.Helper()
	if err := store.DB.QueryRowContext(context.Background(),
		`SELECT status, tg_message_id FROM owner_notifications WHERE id = ?`, id,
	).Scan(&status, &msgID); err != nil {
		t.Fatalf("select notification: %v", err)
	}
	return status, msgID
}

// TestNotifier_DeliverPending_DuplicateRetryIsDelivered: a claimed
// notification whose earlier send landed but was never marked sent is
// retried with the same random_id and refused as a duplicate. That is a
// delivery: the row is marked sent with the located id, and the next sweep
// sends nothing. Before #1029 the row stayed pending and every sweep hit
// the same refusal until MaxPendingAge marked a delivered notification
// failed.
func TestNotifier_DeliverPending_DuplicateRetryIsDelivered(t *testing.T) {
	_, _, _, store, uid := newTestRouter(t)
	ctx := context.Background()
	notifID, err := store.InsertOwnerNotification(ctx, db.OwnerNotification{
		UserID: uid, Kind: db.NotificationSummary, Body: "summary for Alice",
	})
	if err != nil {
		t.Fatalf("seed notification: %v", err)
	}
	sender := &dupSelfSender{locateID: 6060}
	notifier := NewNotifier(store, sender)
	notifier.ClaimLease = time.Millisecond

	delivered, failed, err := notifier.DeliverPending(ctx)
	if err != nil || delivered != 1 || failed != 0 {
		t.Fatalf("deliver: delivered=%d failed=%d err=%v, want 1/0", delivered, failed, err)
	}
	status, msgID := notificationRow(t, store, notifID)
	if status != db.NotificationSent || msgID.Int64 != 6060 {
		t.Fatalf("status=%q id=%v, want sent with the located 6060", status, msgID)
	}
	time.Sleep(5 * time.Millisecond) // past the claim lease
	if _, _, err := notifier.DeliverPending(ctx); err != nil {
		t.Fatalf("second sweep: %v", err)
	}
	if sender.calls != 1 {
		t.Fatalf("send RPCs = %d, want 1", sender.calls)
	}
}

// TestNotifier_DeliverPending_DuplicateWithoutLocatedIDStoresNull: with no
// single match in Saved Messages the notification is still delivered, and
// its id is stored as unknown (NULL), never as a fake 0.
func TestNotifier_DeliverPending_DuplicateWithoutLocatedIDStoresNull(t *testing.T) {
	_, _, _, store, uid := newTestRouter(t)
	ctx := context.Background()
	notifID, err := store.InsertOwnerNotification(ctx, db.OwnerNotification{
		UserID: uid, Kind: db.NotificationSummary, Body: "summary for Bob",
	})
	if err != nil {
		t.Fatalf("seed notification: %v", err)
	}
	notifier := NewNotifier(store, &dupSelfSender{})
	if delivered, _, err := notifier.DeliverPending(ctx); err != nil || delivered != 1 {
		t.Fatalf("deliver: delivered=%d err=%v", delivered, err)
	}
	status, msgID := notificationRow(t, store, notifID)
	if status != db.NotificationSent || msgID.Valid {
		t.Fatalf("status=%q id=%v, want sent with a NULL id", status, msgID)
	}
}
