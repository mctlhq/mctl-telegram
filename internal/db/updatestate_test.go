package db

import (
	"context"
	"testing"
)

func TestTGUpdateState_RoundTripAndPartialSetters(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedAgentUser(t, s, "owner")

	// No state yet: found=false, and partial setters must error (gotd
	// contract: they fall back to SetState on this error).
	if _, found, err := s.GetTGUpdateState(ctx, uid); err != nil || found {
		t.Fatalf("empty state: found=%v err=%v", found, err)
	}
	if err := s.SetTGPts(ctx, uid, 10); err != ErrTGUpdateStateNotFound {
		t.Fatalf("SetTGPts on missing state err = %v, want ErrTGUpdateStateNotFound", err)
	}

	if err := s.SetTGUpdateState(ctx, uid, TGUpdateState{Pts: 1, Qts: 2, Date: 3, Seq: 4}); err != nil {
		t.Fatalf("set state: %v", err)
	}
	st, found, err := s.GetTGUpdateState(ctx, uid)
	if err != nil || !found {
		t.Fatalf("get state: found=%v err=%v", found, err)
	}
	if st != (TGUpdateState{Pts: 1, Qts: 2, Date: 3, Seq: 4}) {
		t.Fatalf("state = %+v", st)
	}

	// Partial setters.
	if err := s.SetTGPts(ctx, uid, 100); err != nil {
		t.Fatalf("set pts: %v", err)
	}
	if err := s.SetTGQts(ctx, uid, 200); err != nil {
		t.Fatalf("set qts: %v", err)
	}
	if err := s.SetTGDateSeq(ctx, uid, 300, 400); err != nil {
		t.Fatalf("set date/seq: %v", err)
	}
	st, _, _ = s.GetTGUpdateState(ctx, uid)
	if st != (TGUpdateState{Pts: 100, Qts: 200, Date: 300, Seq: 400}) {
		t.Fatalf("state after partial sets = %+v", st)
	}

	// Upsert replaces in place (no duplicate-key error).
	if err := s.SetTGUpdateState(ctx, uid, TGUpdateState{Pts: 5, Qts: 6, Date: 7, Seq: 8}); err != nil {
		t.Fatalf("re-set state: %v", err)
	}
}

func TestTGChannelState_PtsAndAccessHash(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedAgentUser(t, s, "owner")

	if _, found, err := s.GetTGChannelPts(ctx, uid, 777); err != nil || found {
		t.Fatalf("empty channel pts: found=%v err=%v", found, err)
	}

	// Setting ONLY pts must not make GetTGChannelAccessHash report a stored
	// (default-0) hash, and vice versa — the two setters share the row.
	if err := s.SetTGChannelPts(ctx, uid, 888, 42); err != nil {
		t.Fatalf("set channel pts only: %v", err)
	}
	if _, found, err := s.GetTGChannelAccessHash(ctx, uid, 888); err != nil || found {
		t.Fatalf("access hash after pts-only set: found=%v err=%v, want not found", found, err)
	}
	if err := s.SetTGChannelAccessHash(ctx, uid, 889, 555); err != nil {
		t.Fatalf("set access hash only: %v", err)
	}
	if _, found, err := s.GetTGChannelPts(ctx, uid, 889); err != nil || found {
		t.Fatalf("pts after access-hash-only set: found=%v err=%v, want not found", found, err)
	}

	if err := s.SetTGChannelPts(ctx, uid, 777, 42); err != nil {
		t.Fatalf("set channel pts: %v", err)
	}
	// Access hash upsert must not clobber pts, and vice versa.
	if err := s.SetTGChannelAccessHash(ctx, uid, 777, 987654321); err != nil {
		t.Fatalf("set access hash: %v", err)
	}
	if err := s.SetTGChannelPts(ctx, uid, 777, 43); err != nil {
		t.Fatalf("update channel pts: %v", err)
	}

	pts, found, err := s.GetTGChannelPts(ctx, uid, 777)
	if err != nil || !found || pts != 43 {
		t.Fatalf("channel pts = %d found=%v err=%v", pts, found, err)
	}
	hash, found, err := s.GetTGChannelAccessHash(ctx, uid, 777)
	if err != nil || !found || hash != 987654321 {
		t.Fatalf("access hash = %d found=%v err=%v", hash, found, err)
	}

	// ForEachTGChannel yields only channels whose pts was actually initialized:
	// 777 (pts 43) and 888 (pts 42). Channel 889 exists only because an access
	// hash was stored for it (pts still 0), so it must be skipped — reporting
	// it would make gotd start channel-difference recovery from zero.
	seen := map[int64]int{}
	if err := s.ForEachTGChannel(ctx, uid, func(ctx context.Context, channelID int64, pts int) error {
		seen[channelID] = pts
		return nil
	}); err != nil {
		t.Fatalf("foreach: %v", err)
	}
	if seen[777] != 43 || seen[888] != 42 {
		t.Fatalf("iterated pts 777=%d 888=%d, want 43/42", seen[777], seen[888])
	}
	if _, ok := seen[889]; ok {
		t.Fatal("hash-only channel (pts=0) must not be reported as initialized")
	}
	if len(seen) != 2 {
		t.Fatalf("iterated %d channels, want 2", len(seen))
	}
}

func TestSetTGUpdateState_ResetsChannelState(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedAgentUser(t, s, "owner")

	if err := s.SetTGUpdateState(ctx, uid, TGUpdateState{Pts: 1}); err != nil {
		t.Fatalf("set state: %v", err)
	}
	if err := s.SetTGChannelPts(ctx, uid, 777, 42); err != nil {
		t.Fatalf("set channel pts: %v", err)
	}

	// A full state (re)initialization must drop stale channel rows, matching
	// gotd's reference storage, so recovery does not resume from stale pts.
	if err := s.SetTGUpdateState(ctx, uid, TGUpdateState{Pts: 999}); err != nil {
		t.Fatalf("reset state: %v", err)
	}
	if _, found, err := s.GetTGChannelPts(ctx, uid, 777); err != nil || found {
		t.Fatalf("channel state survived reset: found=%v err=%v", found, err)
	}
	st, found, err := s.GetTGUpdateState(ctx, uid)
	if err != nil || !found || st.Pts != 999 {
		t.Fatalf("watermark after reset = %+v found=%v err=%v", st, found, err)
	}
}
