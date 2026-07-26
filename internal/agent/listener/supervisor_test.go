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
	tgIDErrs map[int64]error
	listErr  error
}

func (r *fakeResolver) ListListenerEnabledProfiles(context.Context) ([]db.AgentProfile, error) {
	if r.listErr != nil {
		return nil, r.listErr
	}
	return r.profiles, nil
}

func (r *fakeResolver) GetTelegramID(_ context.Context, userID int64) (int64, error) {
	if err := r.tgIDErrs[userID]; err != nil {
		return 0, err
	}
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

func TestReconcile_MissingSessionUnpinsUntilReconnect(t *testing.T) {
	ctx := context.Background()
	l := New(nil, nil, nil, nil)
	if !l.SetAccount(7, 1007) {
		t.Fatal("set account")
	}
	pool := &fakePool{}
	res := &fakeResolver{
		profiles: []db.AgentProfile{{UserID: 7}},
		tgIDs:    map[int64]int64{},
	}

	reconcile(ctx, l, pool, res)
	if len(pool.unpins) != 1 || pool.unpins[0] != 7 {
		t.Fatalf("unpins = %v", pool.unpins)
	}
	if ids := l.ActiveUserIDs(); len(ids) != 0 {
		t.Fatalf("active after session loss = %v", ids)
	}
	if len(pool.borrows) != 0 {
		t.Fatalf("borrows while session missing = %v", pool.borrows)
	}

	res.tgIDs[7] = 1007
	reconcile(ctx, l, pool, res)
	if len(pool.pins) != 1 || pool.pins[0] != 7 {
		t.Fatalf("pins after reconnect = %v", pool.pins)
	}
	if len(pool.borrows) != 1 || pool.borrows[0] != 7 {
		t.Fatalf("borrows after reconnect = %v", pool.borrows)
	}
}

func TestReconcile_ResolverFailureKeepsActiveAccount(t *testing.T) {
	ctx := context.Background()
	l := New(nil, nil, nil, nil)
	if !l.SetAccount(7, 1007) {
		t.Fatal("set account")
	}
	pool := &fakePool{}
	res := &fakeResolver{
		profiles: []db.AgentProfile{{UserID: 7}},
		tgIDs:    map[int64]int64{7: 1007},
		tgIDErrs: map[int64]error{7: errors.New("database temporarily unavailable")},
	}

	reconcile(ctx, l, pool, res)
	if len(pool.unpins) != 0 {
		t.Fatalf("unpins on transient error = %v", pool.unpins)
	}
	if ids := l.ActiveUserIDs(); len(ids) != 1 || ids[0] != 7 {
		t.Fatalf("active after transient error = %v", ids)
	}
}

func TestStoreResolver_MissingHostedSessionIsZero(t *testing.T) {
	ctx := context.Background()
	conn, err := db.Open(ctx, "file::memory:?cache=shared", 0, 0)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := db.Migrate(ctx, conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	store := &db.Store{DB: conn}
	uid, err := store.EnsureUser(ctx, "listener-session-missing", "", "test")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	got, err := (StoreResolver{Store: store}).GetTelegramID(ctx, uid)
	if err != nil || got != 0 {
		t.Fatalf("GetTelegramID = %d, %v; want 0, nil", got, err)
	}
}

func TestReconcile_RefreshesSenderAllowlistOnActiveAccount(t *testing.T) {
	ctx := context.Background()
	l := New(nil, nil, nil, nil)
	pool := &fakePool{}
	res := &fakeResolver{
		profiles: []db.AgentProfile{{UserID: 7, SenderAllowlist: "555"}},
		tgIDs:    map[int64]int64{7: 1007},
	}
	reconcile(ctx, l, pool, res)
	acct, ok := l.get(7)
	if !ok || !l.senderAllowed(acct, 555) || l.senderAllowed(acct, 777) {
		t.Fatalf("initial allowlist was not installed")
	}

	res.profiles[0].SenderAllowlist = "777"
	reconcile(ctx, l, pool, res)
	if l.senderAllowed(acct, 555) || !l.senderAllowed(acct, 777) {
		t.Fatalf("updated allowlist was not refreshed")
	}
}
