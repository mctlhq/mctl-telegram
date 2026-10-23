package db

import (
	"context"
	"errors"
	"testing"
)

func TestEnsureDCMode_FreshStoreIsStampedWithTheRequestedMode(t *testing.T) {
	ctx := context.Background()
	for _, mode := range []string{DCModeProduction, DCModeTest} {
		t.Run(mode, func(t *testing.T) {
			s := newTestStore(t)
			if err := s.EnsureDCMode(ctx, mode); err != nil {
				t.Fatalf("first EnsureDCMode(%s): %v", mode, err)
			}
			if err := s.EnsureDCMode(ctx, mode); err != nil {
				t.Fatalf("second EnsureDCMode(%s): %v", mode, err)
			}
			other := DCModeTest
			if mode == DCModeTest {
				other = DCModeProduction
			}
			if err := s.EnsureDCMode(ctx, other); !errors.Is(err, ErrDCModeMismatch) {
				t.Fatalf("EnsureDCMode(%s) on a %s store = %v, want ErrDCModeMismatch", other, mode, err)
			}
		})
	}
}

// A store that already holds sessions predates the stamp, and every such
// store ran against the production DCs. Pointing it at the test DCs must
// fail before any client is built, or the pool would revoke those sessions.
func TestEnsureDCMode_UnstampedStoreWithAccountsIsProduction(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUser(ctx, "alice", "", "alice")
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, session_encrypted) VALUES($1, $2)`,
		uid, []byte("blob"),
	); err != nil {
		t.Fatalf("seed account: %v", err)
	}

	if err := s.EnsureDCMode(ctx, DCModeTest); !errors.Is(err, ErrDCModeMismatch) {
		t.Fatalf("EnsureDCMode(test) on a store with sessions = %v, want ErrDCModeMismatch", err)
	}
	if err := s.EnsureDCMode(ctx, DCModeProduction); err != nil {
		t.Fatalf("EnsureDCMode(production) after the refusal: %v", err)
	}
}

func TestEnsureDCMode_UnknownModeIsRejected(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnsureDCMode(context.Background(), "staging"); err == nil {
		t.Fatal("EnsureDCMode(staging) = nil, want an error")
	}
	if _, err := s.dcMode(context.Background()); err == nil {
		t.Fatal("an unknown mode stamped the store")
	}
}

// A read that fails is an error, never a pass.
func TestEnsureDCMode_FailedReadIsAnError(t *testing.T) {
	s := newTestStore(t)
	_ = s.DB.Close()
	if err := s.EnsureDCMode(context.Background(), DCModeProduction); err == nil {
		t.Fatal("EnsureDCMode on a closed DB = nil, want an error")
	}
}

func TestDCModeFor(t *testing.T) {
	if got := DCModeFor(true); got != DCModeTest {
		t.Errorf("DCModeFor(true) = %q", got)
	}
	if got := DCModeFor(false); got != DCModeProduction {
		t.Errorf("DCModeFor(false) = %q", got)
	}
}
