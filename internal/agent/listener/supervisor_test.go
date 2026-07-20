package listener

import (
	"context"
	"errors"
	"testing"

	gotdtelegram "github.com/gotd/td/telegram"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

type fakePool struct {
	pins    []int64
	unpins  []int64
	borrows []int64
}

func (p *fakePool) Pin(userID int64)   { p.pins = append(p.pins, userID) }
func (p *fakePool) Unpin(userID int64) { p.unpins = append(p.unpins, userID) }
func (p *fakePool) Borrow(ctx context.Context, userID int64, fn func(context.Context, *gotdtelegram.Client) error) error {
	p.borrows = append(p.borrows, userID)
	return fn(ctx, nil)
}

type fakeResolver struct {
	profiles []db.AgentProfile
	tgIDs    map[int64]int64
	listErr  error
}

func (r *fakeResolver) ListListenerEnabledProfiles(context.Context) ([]db.AgentProfile, error) {
	if r.listErr != nil {
		return nil, r.listErr
	}
	return r.profiles, nil
}

func (r *fakeResolver) GetTelegramID(_ context.Context, userID int64) (int64, error) {
	return r.tgIDs[userID], nil
}

func TestReconcile_UnpinsAndRemovesDisabledAccounts(t *testing.T) {
	ctx := context.Background()
	l := New(nil, nil, nil, nil)
	pool := &fakePool{}
	res := &fakeResolver{profiles: []db.AgentProfile{{UserID: 7}}, tgIDs: map[int64]int64{7: 1007}}

	reconcile(ctx, l, pool, res)
	if len(pool.pins) != 1 || pool.pins[0] != 7 || len(pool.borrows) != 1 || pool.borrows[0] != 7 {
		t.Fatalf("pins=%v borrows=%v", pool.pins, pool.borrows)
	}
	if ids := l.ActiveUserIDs(); len(ids) != 1 || ids[0] != 7 {
		t.Fatalf("active after enable = %v", ids)
	}

	res.profiles = nil
	reconcile(ctx, l, pool, res)
	if len(pool.unpins) != 1 || pool.unpins[0] != 7 {
		t.Fatalf("unpins = %v", pool.unpins)
	}
	if ids := l.ActiveUserIDs(); len(ids) != 0 {
		t.Fatalf("active after disable = %v", ids)
	}
	if l.HandlerFor(7) != nil {
		t.Fatal("disabled account still has handler")
	}
}

func TestReconcile_ListFailureKeepsActiveAccounts(t *testing.T) {
	ctx := context.Background()
	l := New(nil, nil, nil, nil)
	if !l.SetAccount(7, 1007) {
		t.Fatal("set account")
	}
	pool := &fakePool{}
	reconcile(ctx, l, pool, &fakeResolver{listErr: errors.New("db unavailable")})
	if len(pool.unpins) != 0 {
		t.Fatalf("transient error unpinned: %v", pool.unpins)
	}
	if ids := l.ActiveUserIDs(); len(ids) != 1 || ids[0] != 7 {
		t.Fatalf("active after error = %v", ids)
	}
}
