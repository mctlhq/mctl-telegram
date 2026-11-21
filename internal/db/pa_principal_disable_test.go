package db

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/pa/convo"
)

// TestPAPrincipalDisable_Store: set, clear, the read inside a transaction
// and outside one, the bounded reason, and survival of the account's
// deletion (#1318, S1-F4). A read that fails is disabled with an error,
// never "not disabled".
func TestPAPrincipalDisable_Store(t *testing.T) {
	deletionDialects(t, func(t *testing.T, s *Store, base int64) {
		ctx := context.Background()
		aliceID, bobID, admin := base+41, base+42, base+43
		now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
		read := func(p int64) bool {
			t.Helper()
			tx, err := s.DB.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback() }()
			inTx, err := s.PAPrincipalDisabled(ctx, tx, p)
			if err != nil {
				t.Fatalf("read in tx: %v", err)
			}
			// SQLite has one connection: end the transaction first.
			_ = tx.Rollback()
			state, err := s.PAPrincipalDisabledState(ctx, p)
			if err != nil || state != inTx {
				t.Fatalf("read outside tx: %v %v, in tx %v", state, err, inTx)
			}
			return inTx
		}
		if read(aliceID) {
			t.Fatal("a principal never disabled reads as disabled")
		}
		if err := s.SetPAPrincipalDisabled(ctx, aliceID, admin, "abuse report", now); err != nil {
			t.Fatal(err)
		}
		if !read(aliceID) || read(bobID) {
			t.Fatal("disable is not per principal")
		}
		// An upsert: disabling again records the new reason.
		if err := s.SetPAPrincipalDisabled(ctx, aliceID, admin, "second report", now.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
		var reason string
		if err := s.DB.QueryRowContext(ctx, `SELECT reason FROM pa_principal_disables WHERE principal = $1`, aliceID).Scan(&reason); err != nil || reason != "second report" {
			t.Fatalf("reason %q %v", reason, err)
		}
		for _, bad := range []string{"", "   ", "two\nlines", strings.Repeat("x", MaxPAPrincipalDisableReason+1)} {
			if err := s.SetPAPrincipalDisabled(ctx, bobID, admin, bad, now); !errors.Is(err, ErrPADisableReason) {
				t.Fatalf("reason %q: %v", bad, err)
			}
		}
		if err := s.SetPAPrincipalDisabled(ctx, bobID, 0, "x", now); !errors.Is(err, convo.ErrInvalid) {
			t.Fatalf("no admin: %v", err)
		}
		if read(bobID) {
			t.Fatal("a refused disable was written")
		}

		// The disable survives the account's deletion, so deleting the
		// account and coming back does not clear it.
		uid, err := s.EnsureUserByTelegramID(ctx, aliceID, "alice", "Alice")
		if err != nil {
			t.Fatal(err)
		}
		seedPAPrincipalState(t, s, aliceID)
		if _, err := s.HardDeleteAccount(ctx, uid); err != nil {
			t.Fatalf("delete alice: %v", err)
		}
		if !read(aliceID) {
			t.Fatal("account deletion cleared the disable")
		}

		if err := s.ClearPAPrincipalDisabled(ctx, aliceID); err != nil {
			t.Fatal(err)
		}
		if read(aliceID) {
			t.Fatal("clear left the principal disabled")
		}
		if err := s.ClearPAPrincipalDisabled(ctx, aliceID); err != nil {
			t.Fatalf("clearing twice: %v", err)
		}
		if _, err := s.PAPrincipalDisabled(ctx, nil, aliceID); !errors.Is(err, convo.ErrInvalid) {
			t.Fatalf("nil tx: %v", err)
		}
	})
}

// TestPAPrincipalDisable_ReadErrorIsDisabled: a row that does not scan is
// unreadable, a store that cannot be read is a store fault; both come with
// true.
func TestPAPrincipalDisable_ReadErrorIsDisabled(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO pa_principal_disables(principal, disabled_at_ms, disabled_by, reason) VALUES(9100051, 'not a number', 1, 'x')`); err != nil {
		t.Fatal(err)
	}
	disabled, err := s.PAPrincipalDisabledState(ctx, 9100051)
	if !disabled || !errors.Is(err, convo.ErrUnreadable) || errors.Is(err, convo.ErrStoreFault) {
		t.Fatalf("bad row: %v %v, want disabled, unreadable, not a store fault", disabled, err)
	}
	closed := newTestStore(t)
	_ = closed.DB.Close()
	disabled, err = closed.PAPrincipalDisabledState(ctx, 9100052)
	if !disabled || !errors.Is(err, convo.ErrStoreFault) {
		t.Fatalf("closed store: %v %v, want disabled with a store fault", disabled, err)
	}
}
