package db

import (
	"context"
	"sync"
	"testing"
)

func TestEnsureUserByTelegramID_Idempotent(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid1, err := s.EnsureUserByTelegramID(ctx, 12345, "alice", "Alice A.")
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	uid2, err := s.EnsureUserByTelegramID(ctx, 12345, "alice2", "Alice Anna")
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if uid1 != uid2 {
		t.Errorf("uid drift: %d → %d", uid1, uid2)
	}
}

func TestEnsureUserByTelegramID_RefreshesMetadata(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUserByTelegramID(ctx, 67890, "", "")
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	if _, err := s.EnsureUserByTelegramID(ctx, 67890, "bob", "Bob Bobson"); err != nil {
		t.Fatalf("update call: %v", err)
	}
	var username, display string
	if err := s.DB.QueryRowContext(ctx,
		`SELECT COALESCE(telegram_username,''), COALESCE(telegram_display_name,'') FROM users WHERE id = ?`,
		uid,
	).Scan(&username, &display); err != nil {
		t.Fatalf("select: %v", err)
	}
	if username != "bob" {
		t.Errorf("username = %q", username)
	}
	if display != "Bob Bobson" {
		t.Errorf("display = %q", display)
	}
}

// TestEnsureUserByTelegramID_RaceSafe spins up N goroutines that all call
// EnsureUserByTelegramID with the same fresh Telegram id at the same time.
// Before the ON CONFLICT fix, the loser of the unique-index race would
// surface a 500. After: every caller receives the same uid, no errors.
func TestEnsureUserByTelegramID_RaceSafe(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	const N = 8
	var wg sync.WaitGroup
	uids := make([]int64, N)
	errs := make([]error, N)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			uid, err := s.EnsureUserByTelegramID(ctx, 555_000, "race", "Race User")
			uids[idx] = uid
			errs[idx] = err
		}(i)
	}
	wg.Wait()
	for i, e := range errs {
		if e != nil {
			t.Fatalf("goroutine %d: %v", i, e)
		}
	}
	// All callers must observe the same id.
	for i := 1; i < N; i++ {
		if uids[i] != uids[0] {
			t.Errorf("goroutine %d saw uid=%d, first saw uid=%d", i, uids[i], uids[0])
		}
	}
}

func TestEnsureUserByTelegramID_RejectsZero(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	if _, err := s.EnsureUserByTelegramID(ctx, 0, "", ""); err == nil {
		t.Fatal("accepted tg_id=0")
	}
	if _, err := s.EnsureUserByTelegramID(ctx, -1, "", ""); err == nil {
		t.Fatal("accepted tg_id=-1")
	}
}
