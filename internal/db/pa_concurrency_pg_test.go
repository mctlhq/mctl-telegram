package db

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/pa/approval"
	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
	"github.com/mctlhq/mctl-telegram/internal/pa/convo"
	"github.com/mctlhq/mctl-telegram/internal/pa/jobs"
	"github.com/mctlhq/mctl-telegram/internal/pa/permissions"
)

// Postgres tests of two real transactions racing on the rows that order a
// change of authority against a write (#1320 slice P2-S15a): S2-C9, S2-C10
// and S2-A9. SQLite has one writer at a time, so these orderings cannot
// occur there and the tests need TEST_DATABASE_URL. The personas are the
// synthetic Alice and Bob of paConvoDialects.
//
// Each test holds one transaction open, starts the other in a goroutine and
// waits until that one either blocks on a lock or returns. A guard that was
// removed lets it return, and the assertions after the commit then see the
// state the guard prevents: the tests fail on the outcome, not on a timeout.

// paRacePostgres runs body on Postgres with the ledger rows of both
// personas removed before and after.
func paRacePostgres(t *testing.T, body func(t *testing.T, s *Store, alice int64)) {
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	paCancelDialects(t, func(t *testing.T, s *Store, alice, _ int64) {
		pg, err := s.postgresDialect(context.Background())
		must(t, err)
		if !pg {
			t.Skip("one writer at a time on SQLite: no concurrent transaction to race")
		}
		body(t, s, alice)
	})
}

// paRaceStart runs fn in a goroutine and returns a channel that yields its
// error once.
func paRaceStart(fn func() error) <-chan error {
	done := make(chan error, 1)
	go func() { done <- fn() }()
	return done
}

// paRaceBlocked waits until the goroutine behind done is waiting on a lock
// held by holder, the open transaction of the test, and reports true; it
// reports false, with the goroutine's error, when the goroutine returned
// instead. It asks pg_blocking_pids about holder's own backend, so another
// test's lock wait on the same server is never taken for this one.
func paRaceBlocked(t *testing.T, s *Store, holder *sql.Tx, done <-chan error) (blocked bool, err error) {
	t.Helper()
	var pid int
	must(t, holder.QueryRow(`SELECT pg_backend_pid()`).Scan(&pid))
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-done:
			return false, err
		default:
		}
		var n int
		must(t, s.DB.QueryRow(
			`SELECT COUNT(*) FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid))`, pid).Scan(&n))
		if n > 0 {
			return true, nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the concurrent transaction neither blocked on the open one nor returned")
	return false, nil
}

// paRaceWait is the error of the goroutine behind done, which must return
// now that the transaction it waited for has ended.
func paRaceWait(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(15 * time.Second):
		t.Fatal("the concurrent transaction did not return after the open one ended")
		return nil
	}
}

func paRaceApprovalStatus(t *testing.T, s *Store, principal int64, id string) string {
	t.Helper()
	var st string
	err := s.DB.QueryRow(`SELECT status FROM pa_approvals WHERE principal = $1 AND id = $2`, principal, id).Scan(&st)
	if errors.Is(err, sql.ErrNoRows) {
		return "absent"
	}
	must(t, err)
	return st
}

func paRaceNotices(t *testing.T, s *Store, principal int64) int {
	t.Helper()
	var n int
	must(t, s.DB.QueryRow(`SELECT COUNT(*) FROM pa_outbox WHERE principal = $1 AND kind = $2`,
		principal, string(jobs.OutboxActionsCancelled)).Scan(&n))
	return n
}

func paRaceConnState(t *testing.T, s *Store, principal int64, id string) connection.State {
	t.Helper()
	c, err := s.GetPAConnection(context.Background(), principal, id)
	must(t, err)
	return c.State
}

// createPAApprovalIn creates a with its two callbacks in tx, as the card
// does.
func createPAApprovalIn(s *Store, tx *sql.Tx, a approval.Approval) error {
	ctx := context.Background()
	if err := s.CreatePAApproval(ctx, tx, a); err != nil {
		return err
	}
	if err := s.CreatePACallback(ctx, tx, a.Principal, a.ApproveCallbackID, "approve:"+a.ID, a.ExpiresAt); err != nil {
		return err
	}
	return s.CreatePACallback(ctx, tx, a.Principal, a.CancelCallbackID, "cancel:"+a.ID, a.ExpiresAt)
}

// S2-C9. A connection that ends while a transaction is creating an approval
// on it waits for that transaction and cancels the approval, with the
// notice. The revocation here is the refresh flight's, which holds no
// principal lock: only the connection row orders the two.
func TestS2C9_Postgres_ApprovalCreatedDuringARevocationIsCancelled(t *testing.T) {
	paRacePostgres(t, func(t *testing.T, s *Store, alice int64) {
		ctx := context.Background()
		w := seedPAApprovalWorld(t, s, alice)
		a := w.build(t, t0)

		tx, err := s.BeginPAWrite(ctx, alice, false)
		must(t, err)
		defer func() { _ = tx.Rollback() }()
		must(t, createPAApprovalIn(s, tx, a))

		done := paRaceStart(func() error {
			_, err := s.RevokePAConnectionAt(ctx, alice, w.conn, w.rev, 1, "refresh_reuse")
			return err
		})
		blocked, err := paRaceBlocked(t, s, tx, done)
		must(t, err)
		must(t, tx.Commit())
		if blocked {
			must(t, paRaceWait(t, done))
		}

		if st := paRaceConnState(t, s, alice, w.conn); st != connection.StateRevoked {
			t.Fatalf("connection is %s, want revoked", st)
		}
		if st := paRaceApprovalStatus(t, s, alice, a.ID); st != string(approval.StatusCancelled) {
			t.Errorf("approval created while the connection was being revoked is %s, want cancelled (revocation waited: %v)", st, blocked)
		}
		if n := paRaceNotices(t, s, alice); n != 1 {
			t.Errorf("%d cancellation notices, want 1", n)
		}
	})
}

// S2-C9, the other order: an approval created while the transition is still
// open waits for it and is refused, so no approval is bound to the ended
// connection.
func TestS2C9_Postgres_ApprovalCreatedAfterAnOpenRevocationIsRefused(t *testing.T) {
	paRacePostgres(t, func(t *testing.T, s *Store, alice int64) {
		ctx := context.Background()
		w := seedPAApprovalWorld(t, s, alice)
		a := w.build(t, t0)

		tx, err := s.DB.BeginTx(ctx, nil)
		must(t, err)
		defer func() { _ = tx.Rollback() }()
		_, err = transitionPAConnTx(ctx, tx, alice, w.conn, connection.Transition{
			From: connection.StateActive, To: connection.StateRevoked, ExpectRevision: w.rev, Reason: "refresh_reuse", At: t0,
		})
		must(t, err)

		done := paRaceStart(func() error {
			wtx, err := s.BeginPAWrite(ctx, alice, false)
			if err != nil {
				return err
			}
			defer func() { _ = wtx.Rollback() }()
			if err := createPAApprovalIn(s, wtx, a); err != nil {
				return err
			}
			return wtx.Commit()
		})
		blocked, cerr := paRaceBlocked(t, s, tx, done)
		must(t, tx.Commit())
		if blocked {
			cerr = paRaceWait(t, done)
		}

		if !errors.Is(cerr, approval.ErrBinding) {
			t.Errorf("create during an open revocation: %v, want approval.ErrBinding (creation waited: %v)", cerr, blocked)
		}
		if st := paRaceApprovalStatus(t, s, alice, a.ID); st != "absent" {
			t.Errorf("approval on the revoked connection is %s, want no row", st)
		}
	})
}

// S2-C9. An admin disable waits for the transaction that is creating an
// approval and granting a permission under the principal's lock, then
// cancels the one and revokes the other.
func TestS2C9_Postgres_AdminDisableWaitsForAnOpenWrite(t *testing.T) {
	paRacePostgres(t, func(t *testing.T, s *Store, alice int64) {
		ctx := context.Background()
		w := seedPAApprovalWorld(t, s, alice)
		a := w.build(t, t0)
		p := permissions.Permission{
			Principal: alice, ID: "prm_race", ConnectionID: w.conn, AuthorityRevision: w.rev,
			Server: string(connection.ServerAlice), Tool: paPermTool, DeviceIDs: []string{"dev-1"},
			Ceiling: 5, ExpiresAt: t0.Add(24 * time.Hour),
		}

		tx, err := s.BeginPAWrite(ctx, alice, false)
		must(t, err)
		defer func() { _ = tx.Rollback() }()
		must(t, createPAApprovalIn(s, tx, a))
		must(t, s.InsertPAPermission(ctx, tx, p, t0))

		done := paRaceStart(func() error {
			return s.SetPAPrincipalDisabled(ctx, alice, 1, "race test", t0.Add(time.Second))
		})
		blocked, err := paRaceBlocked(t, s, tx, done)
		must(t, err)
		must(t, tx.Commit())
		if blocked {
			must(t, paRaceWait(t, done))
		}

		if off, err := s.PAPrincipalDisabledState(ctx, alice); err != nil || !off {
			t.Fatalf("principal disabled = %v, %v, want true", off, err)
		}
		if st := paRaceApprovalStatus(t, s, alice, a.ID); st != string(approval.StatusCancelled) {
			t.Errorf("approval created while the principal was being disabled is %s, want cancelled (disable waited: %v)", st, blocked)
		}
		if n := paRaceNotices(t, s, alice); n != 1 {
			t.Errorf("%d cancellation notices, want 1", n)
		}
		var revoked int64
		must(t, s.DB.QueryRow(`SELECT revoked_at_ms FROM pa_permissions WHERE principal = $1 AND id = $2`,
			alice, p.ID).Scan(&revoked))
		if revoked == 0 {
			t.Errorf("permission granted while the principal was being disabled is not revoked (disable waited: %v)", blocked)
		}
	})
}

// S2-C10. The executor's pre-dispatch transaction locks the connection row
// (LockPAConnection) before it consumes the receipt. A /disconnect that
// arrives while it is open waits on that row: it lands after the consume,
// where the post-dispatch check sees it, and does not cancel the approval
// the executor is already sending. Both revocations are tried: the
// command's and the refresh flight's.
func TestS2C10_Postgres_DisconnectWaitsForThePreDispatchTransaction(t *testing.T) {
	revocations := map[string]func(s *Store, w paApprovalWorld) error{
		"disconnect": func(s *Store, w paApprovalWorld) error {
			_, _, _, err := s.RevokePAConnection(context.Background(), w.principal, w.conn, "user_disconnect")
			return err
		},
		"refresh flight": func(s *Store, w paApprovalWorld) error {
			_, err := s.RevokePAConnectionAt(context.Background(), w.principal, w.conn, w.rev, 1, "refresh_reuse")
			return err
		},
	}
	for name, revoke := range revocations {
		t.Run(name, func(t *testing.T) {
			paRacePostgres(t, func(t *testing.T, s *Store, alice int64) {
				ctx := context.Background()
				w := seedPAApprovalWorld(t, s, alice)
				must(t, inTx(t, s, func(tx *sql.Tx) error {
					return s.AcceptPAConsent(ctx, tx, alice, convo.ConsentVersion, convo.ConsentTextSHA256(), t0)
				}))
				a := w.approved(t, t0)

				tx, err := s.BeginPAWrite(ctx, alice, true)
				must(t, err)
				defer func() { _ = tx.Rollback() }()
				conn, err := s.LockPAConnection(ctx, tx, alice, w.conn)
				must(t, err)
				if conn.State != connection.StateActive || conn.AuthorityRevision != w.rev {
					t.Fatalf("locked row is %s at %d, want active at %d", conn.State, conn.AuthorityRevision, w.rev)
				}

				done := paRaceStart(func() error { return revoke(s, w) })
				blocked, rerr := paRaceBlocked(t, s, tx, done)
				if !blocked {
					t.Errorf("the revocation returned (%v) while the pre-dispatch transaction held the connection row", rerr)
				}
				_, _, cerr := s.ConsumePAApproval(ctx, tx, approval.ConsumeRequest{
					Principal: alice, ApprovalID: a.ID, DispatchID: approval.NewID(), Now: t0.Add(time.Minute), Lease: time.Minute,
				})
				if cerr != nil {
					t.Errorf("consume in the transaction that locked the row as active: %v", cerr)
				}
				must(t, tx.Commit())
				if blocked {
					must(t, paRaceWait(t, done))
				}

				if st := paRaceConnState(t, s, alice, w.conn); st != connection.StateRevoked {
					t.Fatalf("connection is %s, want revoked", st)
				}
				// On the wire: the revocation that came second leaves the
				// receipt consumed, for the post-dispatch check to end.
				if st := paRaceApprovalStatus(t, s, alice, a.ID); st != string(approval.StatusDispatching) {
					t.Errorf("approval is %s, want dispatching", st)
				}
				if n := paRaceNotices(t, s, alice); n != 0 {
					t.Errorf("%d cancellation notices for a call that was sent, want 0", n)
				}
			})
		})
	}
}

// S2-A9. A transition that races a Grant press waits for the grant's
// transaction and revokes the permission it committed.
func TestS2A9_Postgres_RevocationWaitsForAnOpenGrant(t *testing.T) {
	paRacePostgres(t, func(t *testing.T, s *Store, alice int64) {
		ctx := context.Background()
		w := seedPAApprovalWorld(t, s, alice)
		p := permissions.Permission{
			Principal: alice, ID: "prm_race", ConnectionID: w.conn, AuthorityRevision: w.rev,
			Server: string(connection.ServerAlice), Tool: paPermTool, DeviceIDs: []string{"dev-1"},
			Ceiling: 5, ExpiresAt: t0.Add(24 * time.Hour),
		}

		tx, err := s.DB.BeginTx(ctx, nil)
		must(t, err)
		defer func() { _ = tx.Rollback() }()
		must(t, s.InsertPAPermission(ctx, tx, p, t0))

		done := paRaceStart(func() error {
			_, err := s.RevokePAConnectionAt(ctx, alice, w.conn, w.rev, 1, "refresh_reuse")
			return err
		})
		blocked, err := paRaceBlocked(t, s, tx, done)
		must(t, err)
		must(t, tx.Commit())
		if blocked {
			must(t, paRaceWait(t, done))
		}

		if st := paRaceConnState(t, s, alice, w.conn); st != connection.StateRevoked {
			t.Fatalf("connection is %s, want revoked", st)
		}
		var revoked int64
		must(t, s.DB.QueryRow(`SELECT revoked_at_ms FROM pa_permissions WHERE principal = $1 AND id = $2`,
			alice, p.ID).Scan(&revoked))
		if revoked == 0 {
			t.Errorf("permission granted while the connection was being revoked is not revoked (revocation waited: %v)", blocked)
		}
	})
}

// S2-A9, the other order: a Grant press that arrives while the transition
// is open waits for it and is refused, so no permission is bound to the
// revision that ended.
func TestS2A9_Postgres_GrantDuringAnOpenRevocationIsRefused(t *testing.T) {
	paRacePostgres(t, func(t *testing.T, s *Store, alice int64) {
		ctx := context.Background()
		w := seedPAApprovalWorld(t, s, alice)
		p := permissions.Permission{
			Principal: alice, ID: "prm_race", ConnectionID: w.conn, AuthorityRevision: w.rev,
			Server: string(connection.ServerAlice), Tool: paPermTool, DeviceIDs: []string{"dev-1"},
			Ceiling: 5, ExpiresAt: t0.Add(24 * time.Hour),
		}

		tx, err := s.DB.BeginTx(ctx, nil)
		must(t, err)
		defer func() { _ = tx.Rollback() }()
		_, err = transitionPAConnTx(ctx, tx, alice, w.conn, connection.Transition{
			From: connection.StateActive, To: connection.StateRevoked, ExpectRevision: w.rev, Reason: "refresh_reuse", At: t0,
		})
		must(t, err)

		done := paRaceStart(func() error {
			return inTx(t, s, func(gtx *sql.Tx) error { return s.InsertPAPermission(ctx, gtx, p, t0) })
		})
		blocked, gerr := paRaceBlocked(t, s, tx, done)
		must(t, tx.Commit())
		if blocked {
			gerr = paRaceWait(t, done)
		}

		var ref *permissions.Refusal
		if !errors.As(gerr, &ref) || ref.Reason != permissions.ReasonConnectionChange {
			t.Errorf("grant during an open revocation: %v, want the connection_change refusal (grant waited: %v)", gerr, blocked)
		}
		var n int
		must(t, s.DB.QueryRow(`SELECT COUNT(*) FROM pa_permissions WHERE principal = $1 AND id = $2`, alice, p.ID).Scan(&n))
		if n != 0 {
			t.Errorf("%d permission rows on the revoked connection, want 0", n)
		}
	})
}
