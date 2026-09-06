package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/crypto"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

// newLoginTestStore returns a Store on a per-test in-memory SQLite database
// with a plaintext-at-rest crypto, matching cmd/server/agentsendgate_test.go.
// A distinct cache name per test keeps `cache=shared` from leaking rows
// between them.
func newLoginTestStore(t *testing.T) *db.Store {
	t.Helper()
	ctx := context.Background()
	conn, err := db.Open(ctx, "file:"+t.Name()+"?mode=memory&cache=shared", 0, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := db.Migrate(ctx, conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	crypt, err := crypto.New(nil)
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}
	return db.NewStore(conn, crypt)
}

func seedUser(t *testing.T, store *db.Store) int64 {
	t.Helper()
	uid, err := store.EnsureUserByTelegramID(context.Background(), 500100101, "dana_tg", "Dana")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	return uid
}

// TestRefuseIfLocal_RefusesWhileBridgeActive is the cmd/login half of #492's
// guard: a hosted `mctl-telegram login` while a Local Bridge account is active
// must be refused BEFORE telegram.Login can persist its bytes onto the bridge
// row. The oauth side of the same gate is covered by
// TestEnableAccess_LocalModeConflict_RefusedBeforeLogin; this path had none.
func TestRefuseIfLocal_RefusesWhileBridgeActive(t *testing.T) {
	ctx := context.Background()
	store := newLoginTestStore(t)
	uid := seedUser(t, store)
	if err := store.ProvisionLocalAccount(ctx, uid, 500100101, "Dana", "dana_tg"); err != nil {
		t.Fatalf("ProvisionLocalAccount: %v", err)
	}

	err := refuseIfLocal(ctx, store, uid)
	if !errors.Is(err, db.ErrAccountModeConflict) {
		t.Fatalf("refuseIfLocal err=%v, want db.ErrAccountModeConflict", err)
	}
}

// TestRefuseIfLocal_AllowsHostedAndNoAccount is the other half, and it is not
// optional: the gate is one character from silently inverting, and an
// inversion that only the refusal case pins stays green on every user who has
// no bridge — i.e. on the ordinary hosted login this command exists for.
func TestRefuseIfLocal_AllowsHostedAndNoAccount(t *testing.T) {
	ctx := context.Background()
	store := newLoginTestStore(t)
	uid := seedUser(t, store)

	if err := refuseIfLocal(ctx, store, uid); err != nil {
		t.Fatalf("refused a user with no account at all: %v", err)
	}

	if err := store.SaveSession(ctx, uid, []byte("hosted-session"), 500100101, "Dana", "dana_tg"); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}
	if err := refuseIfLocal(ctx, store, uid); err != nil {
		t.Fatalf("refused a user whose only active row is hosted: %v", err)
	}
}

// TestRepairStraySession_ClearsBytesButKeepsTheRow pins the repair's blast
// radius. The bytes a failed hosted login left on the bridge row must go; the
// row itself must not, because revoking it is the exact destruction #492
// exists to prevent — and RevokeActiveSession is the tempting wrong tool here.
func TestRepairStraySession_ClearsBytesButKeepsTheRow(t *testing.T) {
	ctx := context.Background()
	store := newLoginTestStore(t)
	uid := seedUser(t, store)
	if err := store.ProvisionLocalAccount(ctx, uid, 500100101, "Dana", "dana_tg"); err != nil {
		t.Fatalf("ProvisionLocalAccount: %v", err)
	}
	// What telegram.Login does through the gotd SessionStore with no loaded
	// row id: writes onto every active row of the uid, the bridge one included.
	if err := store.UpdateSessionBlob(ctx, uid, []byte("hosted-login-session")); err != nil {
		t.Fatalf("UpdateSessionBlob: %v", err)
	}

	repairStraySession(ctx, store, uid)

	var blob []byte
	if err := store.DB.QueryRowContext(ctx,
		`SELECT session_encrypted FROM telegram_accounts
		 WHERE user_id = $1 AND revoked_at IS NULL AND mode = $2`,
		uid, db.ModeLocal).Scan(&blob); err != nil {
		// sql.ErrNoRows here means the row was revoked, which is the bug.
		t.Fatalf("the bridge row is no longer active after the repair: %v", err)
	}
	if blob != nil {
		t.Error("the hosted login's session bytes survived on the bridge row")
	}
}

// TestRepairStraySession_SurvivesACancelledParent pins the detach. A login
// that failed because ctx was cancelled is exactly when the repair is needed,
// so running it on that same context would skip the cleanup in its most
// likely case. Nothing else in the tree checks this — the comment asserting it
// is the only thing that did.
func TestRepairStraySession_SurvivesACancelledParent(t *testing.T) {
	base := context.Background()
	store := newLoginTestStore(t)
	uid := seedUser(t, store)
	if err := store.ProvisionLocalAccount(base, uid, 500100101, "Dana", "dana_tg"); err != nil {
		t.Fatalf("ProvisionLocalAccount: %v", err)
	}
	if err := store.UpdateSessionBlob(base, uid, []byte("hosted-login-session")); err != nil {
		t.Fatalf("UpdateSessionBlob: %v", err)
	}

	ctx, cancel := context.WithCancel(base)
	cancel()

	repairStraySession(ctx, store, uid)

	var blob []byte
	if err := store.DB.QueryRowContext(base,
		`SELECT session_encrypted FROM telegram_accounts
		 WHERE user_id = $1 AND revoked_at IS NULL AND mode = $2`,
		uid, db.ModeLocal).Scan(&blob); err != nil {
		t.Fatalf("query bridge row: %v", err)
	}
	if blob != nil {
		t.Error("the repair inherited the cancelled context and left the stray bytes behind")
	}
}

// TestRefuseIfLocal_StoreFailureIsNotARefusal pins the property refuseIfLocal's
// own doc comment states and nothing checked: a store that cannot answer must
// not be reported as a Local Bridge conflict. The operator's two remedies are
// opposite -- a conflict means "stop, this account is bridge-only", a store
// failure means "retry" -- so collapsing the second into the first sends them
// to disconnect a bridge over a database blip.
//
// Closing the pool is the cheapest way to make HasActiveLocalAccount fail for
// real, through the same query path production uses, rather than through a
// stub that could drift from it.
func TestRefuseIfLocal_StoreFailureIsNotARefusal(t *testing.T) {
	ctx := context.Background()
	store := newLoginTestStore(t)
	uid := seedUser(t, store)

	if err := store.DB.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	err := refuseIfLocal(ctx, store, uid)
	if err == nil {
		t.Fatal("refuseIfLocal admitted a login while the store was unreachable")
	}
	if errors.Is(err, db.ErrAccountModeConflict) {
		t.Fatalf("a store failure was reported as a mode conflict: %v", err)
	}
	if !strings.Contains(err.Error(), "check account mode") {
		t.Fatalf("the store's own error reached the operator unwrapped: %v", err)
	}
}

// activeLocalBlob returns the session bytes sitting on the user's active
// bridge row, failing the test if that row is gone -- revoking it is the
// destruction #492 exists to prevent, so it is never an acceptable outcome.
func activeLocalBlob(t *testing.T, store *db.Store, uid int64) []byte {
	t.Helper()
	var blob []byte
	if err := store.DB.QueryRowContext(context.Background(),
		`SELECT session_encrypted FROM telegram_accounts
		 WHERE user_id = $1 AND revoked_at IS NULL AND mode = $2`,
		uid, db.ModeLocal).Scan(&blob); err != nil {
		t.Fatalf("the bridge row is no longer active: %v", err)
	}
	return blob
}

// TestRunLoginOrRepair_RepairsWhenTheLoginFails pins the wiring, which is the
// half the direct repairStraySession tests cannot reach: telegram.Login and
// LoginQR both persist through the gotd SessionStore before they return, and
// both have failure exits after that point -- client.Self, the auth.User type
// assertion, the post-Run session re-read. A login that reports an error can
// therefore still have left live bytes on a bridge row, so the error exit has
// to run the repair rather than only the exits after a successful login.
//
// The closure stands in for that: it writes the blob the way gotd does, with
// no loaded row id, and then fails.
func TestRunLoginOrRepair_RepairsWhenTheLoginFails(t *testing.T) {
	ctx := context.Background()
	store := newLoginTestStore(t)
	uid := seedUser(t, store)
	if err := store.ProvisionLocalAccount(ctx, uid, 500100101, "Dana", "dana_tg"); err != nil {
		t.Fatalf("ProvisionLocalAccount: %v", err)
	}

	sentinel := errors.New("self: RPC error")
	_, _, _, err := runLoginOrRepair(ctx, store, uid, func() (int64, string, string, error) {
		if wErr := store.UpdateSessionBlob(ctx, uid, []byte("post-auth-session")); wErr != nil {
			t.Fatalf("UpdateSessionBlob: %v", wErr)
		}
		return 0, "", "", sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("runLoginOrRepair err=%v, want the login's own error", err)
	}

	if blob := activeLocalBlob(t, store, uid); blob != nil {
		t.Error("a failed login left its session bytes on the bridge row")
	}
}

// TestRunLoginOrRepair_LeavesASuccessfulLoginAlone is the other half and is not
// optional: repairing unconditionally would clear the very bytes SaveSession is
// about to adopt, turning a fix for the failure path into a break of every
// ordinary hosted login. Asserted on the bridge row because that is the only
// row the repair touches.
func TestRunLoginOrRepair_LeavesASuccessfulLoginAlone(t *testing.T) {
	ctx := context.Background()
	store := newLoginTestStore(t)
	uid := seedUser(t, store)
	if err := store.ProvisionLocalAccount(ctx, uid, 500100101, "Dana", "dana_tg"); err != nil {
		t.Fatalf("ProvisionLocalAccount: %v", err)
	}

	tgID, displayName, username, err := runLoginOrRepair(ctx, store, uid,
		func() (int64, string, string, error) {
			if wErr := store.UpdateSessionBlob(ctx, uid, []byte("post-auth-session")); wErr != nil {
				t.Fatalf("UpdateSessionBlob: %v", wErr)
			}
			return 500100101, "Dana", "dana_tg", nil
		})
	if err != nil {
		t.Fatalf("runLoginOrRepair: %v", err)
	}
	if tgID != 500100101 || displayName != "Dana" || username != "dana_tg" {
		t.Fatalf("the login's own results were not passed through: %d %q %q", tgID, displayName, username)
	}

	// Compared by content, not equality: the store adds a version byte at
	// rest, and pinning that framing here would make this test fail on an
	// unrelated storage change.
	if blob := activeLocalBlob(t, store, uid); !bytes.Contains(blob, []byte("post-auth-session")) {
		t.Errorf("a successful login had its session bytes cleared; blob=%q", blob)
	}
}
