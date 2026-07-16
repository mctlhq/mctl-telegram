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

	var seen int
	if err := s.ForEachTGChannel(ctx, uid, func(ctx context.Context, channelID int64, pts int) error {
		seen++
		if channelID != 777 || pts != 43 {
			t.Fatalf("iterated channel=%d pts=%d", channelID, pts)
		}
		return nil
	}); err != nil {
		t.Fatalf("foreach: %v", err)
	}
	if seen != 1 {
		t.Fatalf("iterated %d channels, want 1", seen)
	}
}
