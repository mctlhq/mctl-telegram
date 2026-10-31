package telegram

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gotd/td/bin"
	"github.com/gotd/td/tg"
)

// Synthetic account id for the snapshot tests (Dana, see CLAUDE.md).
const snapUserID = 500100303

func countCalls(f *fakeMTProto, name string) int {
	n := 0
	for _, c := range f.calls {
		if c == name {
			n++
		}
	}
	return n
}

func TestGetMessages_DialogsSnapshotServesRepeatReads(t *testing.T) {
	f, api := newFake()
	cache := NewPeerCache()
	spec := fmt.Sprintf("user:%d", bcAliceID)
	for i := 0; i < 3; i++ {
		if _, _, _, _, err := getMessagesWith(context.Background(), api, noResolve, nil, spec, 20, 0, cache, snapUserID, BroadcastContentAllowed); err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
	}
	if got := countCalls(f, "getDialogs"); got != 1 {
		t.Fatalf("getDialogs calls = %d, want 1 for three reads inside the TTL", got)
	}
	if got := countCalls(f, "getHistory"); got != 3 {
		t.Fatalf("getHistory calls = %d, want 3", got)
	}
}

func TestGetMessages_DialogsSnapshotExpires(t *testing.T) {
	f, api := newFake()
	cache := NewPeerCache()
	now := time.Unix(1_700_000_000, 0)
	cache.now = func() time.Time { return now }
	spec := fmt.Sprintf("user:%d", bcAliceID)
	read := func() {
		t.Helper()
		if _, _, _, _, err := getMessagesWith(context.Background(), api, noResolve, nil, spec, 20, 0, cache, snapUserID, BroadcastContentAllowed); err != nil {
			t.Fatal(err)
		}
	}
	read()
	now = now.Add(defaultDialogsSnapshotTTL - time.Second)
	read()
	if got := countCalls(f, "getDialogs"); got != 1 {
		t.Fatalf("getDialogs calls inside TTL = %d, want 1", got)
	}
	now = now.Add(2 * time.Second)
	read()
	if got := countCalls(f, "getDialogs"); got != 2 {
		t.Fatalf("getDialogs calls after TTL = %d, want 2", got)
	}
}

// A peer missing from a cached snapshot may be a dialog opened since it was
// taken: the list is fetched live once more before direct resolution.
func TestGetMessages_SnapshotMissRefetchesLive(t *testing.T) {
	f, api := newFake()
	cache := NewPeerCache()
	alice := fmt.Sprintf("user:%d", bcAliceID)
	if _, _, _, _, err := getMessagesWith(context.Background(), api, noResolve, nil, alice, 20, 0, cache, snapUserID, BroadcastContentAllowed); err != nil {
		t.Fatal(err)
	}

	// Bob opens a dialog after the snapshot was taken.
	const bobID = 8512
	bob := &tg.User{ID: bobID, AccessHash: 4, FirstName: "Bob"}
	f.dialogs.Dialogs = append(f.dialogs.Dialogs, &tg.Dialog{Peer: &tg.PeerUser{UserID: bobID}, NotifySettings: tg.PeerNotifySettings{}})
	f.dialogs.Users = append(f.dialogs.Users, bob)

	if _, _, _, _, err := getMessagesWith(context.Background(), api, noResolve, nil, fmt.Sprintf("user:%d", bobID), 20, 0, cache, snapUserID, BroadcastContentAllowed); err != nil {
		t.Fatalf("peer opened after the snapshot: %v", err)
	}
	if got := countCalls(f, "getDialogs"); got != 2 {
		t.Fatalf("getDialogs calls = %d, want 2 (snapshot, then one live re-fetch)", got)
	}
}

// A peer missing from a list that was just fetched live goes straight to
// direct resolution: no second getDialogs.
func TestGetMessages_LiveMissDoesNotRefetch(t *testing.T) {
	f, api := newFake()
	cache := NewPeerCache()
	resolveErr := errors.New("not resolvable")
	_, _, _, _, err := getMessagesWith(context.Background(), api,
		func(context.Context) (tg.InputPeerClass, error) { return nil, resolveErr },
		nil, "user:8519", 20, 0, cache, snapUserID, BroadcastContentAllowed)
	if !errors.Is(err, resolveErr) {
		t.Fatalf("err = %v, want the direct-resolution error", err)
	}
	if got := countCalls(f, "getDialogs"); got != 1 {
		t.Fatalf("getDialogs calls = %d, want 1", got)
	}
}

func TestGetMessages_NilCacheFetchesEveryTime(t *testing.T) {
	f, api := newFake()
	spec := fmt.Sprintf("user:%d", bcAliceID)
	for i := 0; i < 2; i++ {
		if _, _, _, _, err := getMessagesWith(context.Background(), api, noResolve, nil, spec, 20, 0, nil, 0, BroadcastContentAllowed); err != nil {
			t.Fatal(err)
		}
	}
	if got := countCalls(f, "getDialogs"); got != 2 {
		t.Fatalf("getDialogs calls = %d, want 2 without a cache", got)
	}
}

// gatedDialogs answers messages.getDialogs only, counting calls; each call
// blocks until release is closed. Safe for concurrent use.
type gatedDialogs struct {
	calls   atomic.Int32
	started chan struct{}
	release chan struct{}
	err     error
}

func (g *gatedDialogs) Invoke(ctx context.Context, input bin.Encoder, output bin.Decoder) error {
	if _, ok := input.(*tg.MessagesGetDialogsRequest); !ok {
		return fmt.Errorf("gatedDialogs: unexpected request %T", input)
	}
	g.calls.Add(1)
	select {
	case g.started <- struct{}{}:
	default:
	}
	select {
	case <-g.release:
	case <-ctx.Done():
		return ctx.Err()
	}
	if g.err != nil {
		return g.err
	}
	var b bin.Buffer
	if err := bcDialogs().Encode(&b); err != nil {
		return err
	}
	return output.Decode(&b)
}

func newGated() *gatedDialogs {
	return &gatedDialogs{started: make(chan struct{}, 1), release: make(chan struct{})}
}

func TestRecentDialogs_ConcurrentCallsShareOneFetch(t *testing.T) {
	g := newGated()
	api := tg.NewClient(g)
	cache := NewPeerCache()

	const n = 12
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := cache.recentDialogs(context.Background(), api, snapUserID, false)
			errs <- err
		}()
	}
	<-g.started
	// Let the other callers reach the in-flight fetch before it returns.
	time.Sleep(50 * time.Millisecond)
	close(g.release)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := g.calls.Load(); got != 1 {
		t.Fatalf("getDialogs calls = %d, want 1 for %d concurrent callers", got, n)
	}
}

func TestRecentDialogs_ErrorIsNotCached(t *testing.T) {
	g := newGated()
	close(g.release)
	g.err = errors.New("FLOOD_WAIT_30")
	api := tg.NewClient(g)
	cache := NewPeerCache()
	if _, _, err := cache.recentDialogs(context.Background(), api, snapUserID, false); err == nil {
		t.Fatal("want the fetch error")
	}
	g.err = nil
	res, cached, err := cache.recentDialogs(context.Background(), api, snapUserID, false)
	if err != nil || res == nil || cached {
		t.Fatalf("after a failed fetch: res=%v cached=%v err=%v, want a live fetch", res, cached, err)
	}
	if got := g.calls.Load(); got != 2 {
		t.Fatalf("getDialogs calls = %d, want 2", got)
	}
}

// A caller that joined a fetch started by another call must not inherit
// that call's cancellation.
func TestRecentDialogs_LeaderCancelDoesNotFailFollower(t *testing.T) {
	g := newGated()
	api := tg.NewClient(g)
	cache := NewPeerCache()

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leaderDone := make(chan error, 1)
	go func() {
		_, _, err := cache.recentDialogs(leaderCtx, api, snapUserID, false)
		leaderDone <- err
	}()
	<-g.started

	followerDone := make(chan error, 1)
	go func() {
		_, _, err := cache.recentDialogs(context.Background(), api, snapUserID, false)
		followerDone <- err
	}()
	time.Sleep(50 * time.Millisecond)
	cancelLeader()
	if err := <-leaderDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("leader err = %v, want context.Canceled", err)
	}
	close(g.release)
	if err := <-followerDone; err != nil {
		t.Fatalf("follower err = %v, want its own successful fetch", err)
	}
}

func TestPeerCacheSweep_DropsExpiredDialogSnapshots(t *testing.T) {
	g := newGated()
	close(g.release)
	api := tg.NewClient(g)
	cache := NewPeerCache()
	now := time.Unix(1_700_000_000, 0)
	cache.now = func() time.Time { return now }
	if _, _, err := cache.recentDialogs(context.Background(), api, snapUserID, false); err != nil {
		t.Fatal(err)
	}
	now = now.Add(defaultDialogsSnapshotTTL)
	cache.Sweep()
	cache.dialogs.mu.Lock()
	left := len(cache.dialogs.m)
	cache.dialogs.mu.Unlock()
	if left != 0 {
		t.Fatalf("snapshots after sweep = %d, want 0", left)
	}
}
