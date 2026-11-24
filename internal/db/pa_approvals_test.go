package db

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/pa/approval"
	"github.com/mctlhq/mctl-telegram/internal/pa/catalog"
	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
)

// Store tests of the approval and dispatch ledger (#1320 slice P2-S2). They
// run on SQLite always and on Postgres when TEST_DATABASE_URL is set. The
// personas are the synthetic Alice and Bob of paConvoDialects.

// paApprovalDialects is paConvoDialects with the ledger and connection
// rows of both personas removed before and after.
func paApprovalDialects(t *testing.T, body func(t *testing.T, s *Store, alice, bob int64)) {
	paConvoDialects(t, func(t *testing.T, s *Store, alice, bob int64) {
		clean := func() {
			for _, tb := range []string{"pa_approvals", "pa_dispatches", "pa_connections"} {
				_, _ = s.DB.Exec(`DELETE FROM `+tb+` WHERE principal IN ($1, $2)`, alice, bob)
			}
		}
		clean()
		t.Cleanup(clean)
		body(t, s, alice, bob)
	})
}

// paApprovalWorld is one principal with an open conversation and an active
// connection, the two rows an approval is created from.
type paApprovalWorld struct {
	s         *Store
	principal int64
	conv      string
	conn      string
	rev       int64
}

const paApprovalConvTTL = 24 * time.Hour

func seedPAApprovalWorld(t *testing.T, s *Store, principal int64) paApprovalWorld {
	t.Helper()
	ctx := context.Background()
	w := paApprovalWorld{s: s, principal: principal, conn: "pac_apr_" + randomSuffix(t), rev: 5}
	must(t, inTx(t, s, func(tx *sql.Tx) error {
		c, err := s.OpenPAConversation(ctx, tx, principal, "pcv_apr_"+randomSuffix(t), t0, paApprovalConvTTL)
		w.conv = c.ID
		return err
	}))
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO pa_connections(id, principal, server, state, authority_revision, token_generation, kek_id,
			wrapped_dek, sealed_tokens, granted_scope, created_at_ms, updated_at_ms)
		 VALUES($1, $2, $3, $4, $5, 1, 'test', $6, $7, 'home', $8, $8)`,
		w.conn, principal, string(connection.ServerAlice), string(connection.StateActive), w.rev,
		[]byte("wrapped"), []byte("tokens"), t0.UnixMilli()); err != nil {
		t.Fatalf("seed connection: %v", err)
	}
	return w
}

func (w paApprovalWorld) binding() approval.Binding {
	return approval.Binding{
		Principal: w.principal, ConnectionID: w.conn, AuthorityRevision: w.rev,
		Server: string(connection.ServerAlice), Tool: "alice_set_volume", Class: catalog.ClassWrite,
		SchemaSHA: paHash("schema"), DescriptionSHA: paHash("description"), AnnotationSHA: paHash("annotations"),
		ArgsSHA: paHash(`{"level":3}`), ConversationID: w.conv, JobID: 7,
	}
}

// build returns an unsaved approval created at at. The sealed arguments
// are opaque to the store; the tests use a marker they can compare.
func (w paApprovalWorld) build(t *testing.T, at time.Time) approval.Approval {
	t.Helper()
	a, err := approval.New(w.binding(), at)
	must(t, err)
	a.SealedArgs = []byte("sealed:" + a.ID)
	return a
}

// pending creates an approval at at, with its two callbacks.
func (w paApprovalWorld) pending(t *testing.T, at time.Time) approval.Approval {
	t.Helper()
	ctx := context.Background()
	a := w.build(t, at)
	must(t, inTx(t, w.s, func(tx *sql.Tx) error {
		if err := w.s.CreatePAApproval(ctx, tx, a); err != nil {
			return err
		}
		if err := w.s.CreatePACallback(ctx, tx, w.principal, a.ApproveCallbackID, "approve:"+a.ID, a.ExpiresAt); err != nil {
			return err
		}
		return w.s.CreatePACallback(ctx, tx, w.principal, a.CancelCallbackID, "cancel:"+a.ID, a.ExpiresAt)
	}))
	return a
}

// approved creates an approval at at and approves it a second later.
func (w paApprovalWorld) approved(t *testing.T, at time.Time) approval.Approval {
	t.Helper()
	a := w.pending(t, at)
	must(t, inTx(t, w.s, func(tx *sql.Tx) error {
		_, err := w.s.ApprovePAApproval(context.Background(), tx, w.principal, a.ID, at.Add(time.Second))
		return err
	}))
	return a
}

// consume runs ConsumePAApproval for principal in its own transaction,
// committed on success and rolled back on a refusal, as the executor does.
func paConsume(t *testing.T, s *Store, principal int64, id string, now time.Time) (approval.Approval, approval.Dispatch, error) {
	t.Helper()
	var (
		a approval.Approval
		d approval.Dispatch
	)
	err := inTx(t, s, func(tx *sql.Tx) error {
		var cerr error
		a, d, cerr = s.ConsumePAApproval(context.Background(), tx, approval.ConsumeRequest{
			Principal: principal, ApprovalID: id, DispatchID: approval.NewID(), Now: now, Lease: time.Minute,
		})
		return cerr
	})
	return a, d, err
}

// paApprovalRow is what the tests read back of one approval row.
type paApprovalRow struct {
	status   string
	sealed   []byte
	approver int64
}

func readPAApprovalRow(t *testing.T, s *Store, principal int64, id string) paApprovalRow {
	t.Helper()
	var r paApprovalRow
	if err := s.DB.QueryRowContext(context.Background(),
		`SELECT status, sealed_args, approver FROM pa_approvals WHERE principal = $1 AND id = $2`,
		principal, id).Scan(&r.status, &r.sealed, &r.approver); err != nil {
		t.Fatalf("read approval row %s: %v", id, err)
	}
	return r
}

func paDispatchStatuses(t *testing.T, s *Store, principal int64) []string {
	t.Helper()
	rows, err := s.DB.QueryContext(context.Background(),
		`SELECT status FROM pa_dispatches WHERE principal = $1 ORDER BY created_at_ms, id`, principal)
	must(t, err)
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var st string
		must(t, rows.Scan(&st))
		out = append(out, st)
	}
	must(t, rows.Err())
	return out
}

// wantUntouched fails unless the approval is still approved with its
// arguments and the principal has no dispatch record: a refused consume
// changed nothing.
func wantUntouched(t *testing.T, s *Store, principal int64, a approval.Approval) {
	t.Helper()
	r := readPAApprovalRow(t, s, principal, a.ID)
	if r.status != string(approval.StatusApproved) || !bytes.Equal(r.sealed, a.SealedArgs) {
		t.Errorf("after a refused consume the row is status %q, args %q; want approved with its arguments", r.status, r.sealed)
	}
	if got := paDispatchStatuses(t, s, principal); len(got) != 0 {
		t.Errorf("after a refused consume there are dispatch records %v, want none", got)
	}
}

// noArgsOutsideOpen fails if any row that is not pending or approved still
// holds sealed arguments (owner retention decision, #1320).
func noArgsOutsideOpen(t *testing.T, s *Store, principals ...int64) {
	t.Helper()
	for _, p := range principals {
		var n int
		must(t, s.DB.QueryRowContext(context.Background(),
			`SELECT COUNT(*) FROM pa_approvals WHERE principal = $1 AND sealed_args IS NOT NULL
			   AND status NOT IN ('pending', 'approved')`, p).Scan(&n))
		if n != 0 {
			t.Errorf("principal %d: %d ended approvals still hold sealed arguments, want 0", p, n)
		}
	}
}

// S2-A1: replay is refused. The receipt compare-and-set lets one consume
// through; the second finds the row dispatching, and later done.
func TestS2A1_ReceiptIsConsumedOnce(t *testing.T) {
	paApprovalDialects(t, func(t *testing.T, s *Store, alice, _ int64) {
		w := seedPAApprovalWorld(t, s, alice)
		a := w.approved(t, t0)
		now := t0.Add(time.Minute)

		got, d, err := paConsume(t, s, alice, a.ID, now)
		must(t, err)
		if !bytes.Equal(got.SealedArgs, a.SealedArgs) || got.Status != approval.StatusDispatching {
			t.Fatalf("consume returned status %q args %q, want dispatching with the stored arguments", got.Status, got.SealedArgs)
		}
		if d.ApprovalID != a.ID || d.IdempotencyKey != a.IdempotencyKey || d.ArgsSHA != a.ArgsSHA ||
			d.Status != approval.DispatchDispatching || !d.LeaseUntil.Equal(now.Add(time.Minute)) {
			t.Fatalf("dispatch = %+v, want dispatching, bound to the approval, lease +1m", d)
		}
		if r := readPAApprovalRow(t, s, alice, a.ID); r.status != "dispatching" || r.sealed != nil || r.approver != alice {
			t.Fatalf("row after consume = %+v, want dispatching, no arguments, approver alice", r)
		}

		if _, _, err := paConsume(t, s, alice, a.ID, now.Add(time.Second)); !errors.Is(err, approval.ErrConsumed) {
			t.Fatalf("second consume: err = %v, want ErrConsumed", err)
		}
		must(t, inTx(t, s, func(tx *sql.Tx) error {
			_, err := s.FinishPADispatch(context.Background(), tx, alice, d.ID, approval.DispatchOK, now.Add(2*time.Second))
			return err
		}))
		if _, _, err := paConsume(t, s, alice, a.ID, now.Add(3*time.Second)); !errors.Is(err, approval.ErrConsumed) {
			t.Fatalf("consume after the dispatch finished: err = %v, want ErrConsumed", err)
		}
		if got := paDispatchStatuses(t, s, alice); len(got) != 1 || got[0] != "ok" {
			t.Fatalf("dispatch records = %v, want exactly one, ok", got)
		}
		if r := readPAApprovalRow(t, s, alice, a.ID); r.status != "done" {
			t.Fatalf("approval after its dispatch finished: status %q, want done", r.status)
		}
		noArgsOutsideOpen(t, s, alice)
	})
}

// S2-A1, the double tap: consumes racing on one receipt, each in its own
// transaction. One wins; no other gets the arguments or a dispatch record.
func TestS2A1_ConcurrentConsumesDispatchOnce(t *testing.T) {
	paApprovalDialects(t, func(t *testing.T, s *Store, alice, _ int64) {
		w := seedPAApprovalWorld(t, s, alice)
		a := w.approved(t, t0)
		const racers = 8
		var (
			wg    sync.WaitGroup
			start = make(chan struct{})
			errs  = make([]error, racers)
			args  = make([][]byte, racers)
		)
		for i := range racers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				tx, err := s.DB.BeginTx(context.Background(), nil)
				if err != nil {
					errs[i] = err
					return
				}
				got, _, err := s.ConsumePAApproval(context.Background(), tx, approval.ConsumeRequest{
					Principal: alice, ApprovalID: a.ID, DispatchID: approval.NewID(), Now: t0.Add(time.Minute), Lease: time.Minute})
				if err != nil {
					_ = tx.Rollback()
					errs[i] = err
					return
				}
				args[i] = got.SealedArgs
				errs[i] = tx.Commit()
			}()
		}
		close(start)
		wg.Wait()
		won := 0
		for i, err := range errs {
			if err == nil {
				won++
				continue
			}
			if args[i] != nil {
				t.Errorf("racer %d failed (%v) and still holds the arguments", i, err)
			}
		}
		if won != 1 {
			t.Fatalf("%d of %d racing consumes won, want exactly 1: %v", won, racers, errs)
		}
		if got := paDispatchStatuses(t, s, alice); len(got) != 1 || got[0] != "dispatching" {
			t.Fatalf("dispatch records = %v, want exactly one dispatching", got)
		}
		if _, _, err := paConsume(t, s, alice, a.ID, t0.Add(2*time.Minute)); !errors.Is(err, approval.ErrConsumed) {
			t.Fatalf("consume after the race: err = %v, want ErrConsumed", err)
		}
	})
}

// S2-A1, second barrier: even an approval row that claims to be approved
// again cannot pay for a second dispatch, because the dispatch record of
// the first holds its idempotency key.
func TestS2A1_DispatchRecordRefusesASecondDispatch(t *testing.T) {
	paApprovalDialects(t, func(t *testing.T, s *Store, alice, _ int64) {
		ctx := context.Background()
		w := seedPAApprovalWorld(t, s, alice)
		a := w.approved(t, t0)
		_, _, err := paConsume(t, s, alice, a.ID, t0.Add(time.Minute))
		must(t, err)
		// What no code path does: put the receipt back.
		if _, err := s.DB.ExecContext(ctx,
			`UPDATE pa_approvals SET status = 'approved', sealed_args = $1 WHERE principal = $2 AND id = $3`,
			a.SealedArgs, alice, a.ID); err != nil {
			t.Fatal(err)
		}
		if _, _, err := paConsume(t, s, alice, a.ID, t0.Add(2*time.Minute)); !errors.Is(err, approval.ErrConsumed) {
			t.Fatalf("consume of a restored receipt: err = %v, want ErrConsumed", err)
		}
		if got := paDispatchStatuses(t, s, alice); len(got) != 1 {
			t.Fatalf("dispatch records = %v, want exactly one", got)
		}
	})
}

// A dispatch id that is already taken is a failed write, not a consumed
// receipt, and the rollback the contract asks for leaves the receipt whole.
func TestPAApproval_ReusedDispatchIDIsNotAConsume(t *testing.T) {
	paApprovalDialects(t, func(t *testing.T, s *Store, alice, _ int64) {
		ctx := context.Background()
		w := seedPAApprovalWorld(t, s, alice)
		first, second := w.approved(t, t0), w.approved(t, t0)
		now := t0.Add(time.Minute)
		_, d, err := paConsume(t, s, alice, first.ID, now)
		must(t, err)

		tx, err := s.DB.BeginTx(ctx, nil)
		must(t, err)
		_, _, err = s.ConsumePAApproval(ctx, tx, approval.ConsumeRequest{
			Principal: alice, ApprovalID: second.ID, DispatchID: d.ID, Now: now, Lease: time.Minute})
		must(t, tx.Rollback())
		if !errors.Is(err, approval.ErrUnreadable) || errors.Is(err, approval.ErrConsumed) {
			t.Fatalf("consume with a taken dispatch id: err = %v, want ErrUnreadable and not ErrConsumed", err)
		}
		if r := readPAApprovalRow(t, s, alice, second.ID); r.status != "approved" || !bytes.Equal(r.sealed, second.SealedArgs) {
			t.Fatalf("after the rollback the receipt is %+v, want approved with its arguments", r)
		}
		if got := paDispatchStatuses(t, s, alice); len(got) != 1 {
			t.Fatalf("dispatch records = %v, want only the first", got)
		}
		if _, _, err := paConsume(t, s, alice, second.ID, now); err != nil {
			t.Fatalf("consume with a fresh dispatch id: %v", err)
		}
	})
}

// S2-A2: an expired approval is refused, at the expiry itself and after
// it, by Approve and by the consume, and no caller can set a longer expiry.
func TestS2A2_ExpiredApprovalIsRefused(t *testing.T) {
	paApprovalDialects(t, func(t *testing.T, s *Store, alice, _ int64) {
		ctx := context.Background()
		w := seedPAApprovalWorld(t, s, alice)

		for _, late := range []time.Duration{approval.TTL, approval.TTL + time.Millisecond} {
			a := w.approved(t, t0)
			if _, _, err := paConsume(t, s, alice, a.ID, t0.Add(late)); !errors.Is(err, approval.ErrExpired) {
				t.Fatalf("consume at +%s: err = %v, want ErrExpired", late, err)
			}
			wantUntouched(t, s, alice, a)
		}
		// One millisecond earlier it is still good.
		a := w.approved(t, t0)
		if _, _, err := paConsume(t, s, alice, a.ID, t0.Add(approval.TTL-time.Millisecond)); err != nil {
			t.Fatalf("consume 1ms before the expiry: %v", err)
		}

		p := w.pending(t, t0)
		err := inTx(t, s, func(tx *sql.Tx) error {
			_, err := s.ApprovePAApproval(ctx, tx, alice, p.ID, t0.Add(approval.TTL))
			return err
		})
		if !errors.Is(err, approval.ErrExpired) {
			t.Fatalf("approve at the expiry: err = %v, want ErrExpired", err)
		}
		if r := readPAApprovalRow(t, s, alice, p.ID); r.status != "pending" {
			t.Fatalf("after a refused approve: status %q, want pending", r.status)
		}

		// The expiry is the store's: created + TTL, whatever the caller set.
		long := w.build(t, t0)
		long.ExpiresAt = t0.Add(time.Hour)
		must(t, inTx(t, s, func(tx *sql.Tx) error { return s.CreatePAApproval(ctx, tx, long) }))
		var got approval.Approval
		must(t, inTx(t, s, func(tx *sql.Tx) error {
			var err error
			got, err = s.GetPAApproval(ctx, tx, alice, long.ID)
			return err
		}))
		if !got.ExpiresAt.Equal(t0.Add(approval.TTL)) {
			t.Fatalf("stored expiry = %s, want created + %s", got.ExpiresAt, approval.TTL)
		}
	})
}

// S2-A4: an approval from a different principal is refused. Bob, with a
// conversation and a connection of his own, uses Alice's approval id and
// callback ids: every call finds nothing, and Alice's row is unchanged and
// still hers to use.
func TestS2A4_OtherPrincipalIsRefused(t *testing.T) {
	paApprovalDialects(t, func(t *testing.T, s *Store, alice, bob int64) {
		ctx := context.Background()
		wa := seedPAApprovalWorld(t, s, alice)
		seedPAApprovalWorld(t, s, bob)
		now := t0.Add(time.Minute)

		a := wa.approved(t, t0)
		if _, _, err := paConsume(t, s, bob, a.ID, now); !errors.Is(err, approval.ErrNotFound) {
			t.Fatalf("bob consumes alice's approval: err = %v, want ErrNotFound", err)
		}
		wantUntouched(t, s, alice, a)
		if got := paDispatchStatuses(t, s, bob); len(got) != 0 {
			t.Fatalf("bob has dispatch records %v, want none", got)
		}

		p := wa.pending(t, t0)
		calls := map[string]func(tx *sql.Tx) error{
			"approve": func(tx *sql.Tx) error { _, err := s.ApprovePAApproval(ctx, tx, bob, p.ID, now); return err },
			"cancel":  func(tx *sql.Tx) error { _, err := s.CancelPAApproval(ctx, tx, bob, p.ID, now); return err },
			"refuse":  func(tx *sql.Tx) error { _, err := s.RefusePAApproval(ctx, tx, bob, p.ID, now); return err },
			"get":     func(tx *sql.Tx) error { _, err := s.GetPAApproval(ctx, tx, bob, p.ID); return err },
			"lookup approve callback": func(tx *sql.Tx) error {
				_, err := s.LookupPAApprovalByCallback(ctx, tx, bob, p.ApproveCallbackID)
				return err
			},
			"lookup cancel callback": func(tx *sql.Tx) error {
				_, err := s.LookupPAApprovalByCallback(ctx, tx, bob, p.CancelCallbackID)
				return err
			},
		}
		for name, call := range calls {
			if err := inTx(t, s, call); !errors.Is(err, approval.ErrNotFound) {
				t.Errorf("bob: %s of alice's approval: err = %v, want ErrNotFound", name, err)
			}
		}
		if r := readPAApprovalRow(t, s, alice, p.ID); r.status != "pending" || !bytes.Equal(r.sealed, p.SealedArgs) || r.approver != 0 {
			t.Fatalf("alice's pending approval after bob's calls = %+v, want pending, unchanged", r)
		}
		if n := paRowsIn(t, s, "pa_callbacks", alice); n != 2 {
			t.Fatalf("alice has %d callbacks after bob's calls, want her 2", n)
		}
		// Alice can still use both.
		if _, _, err := paConsume(t, s, alice, a.ID, now); err != nil {
			t.Fatalf("alice consumes her own approval: %v", err)
		}
		must(t, inTx(t, s, func(tx *sql.Tx) error { _, err := s.ApprovePAApproval(ctx, tx, alice, p.ID, now); return err }))
	})
}

// S2-C10: an approval bound to an old authority_revision is refused. The
// connection row is read by the consume itself, so whatever moved the
// connection on refuses the receipt; a token rotation, which binds
// nothing, does not.
func TestS2C10_OldAuthorityRevisionIsRefused(t *testing.T) {
	ctx := context.Background()
	refused := map[string]func(t *testing.T, s *Store, w paApprovalWorld){
		"revision bumped, still active": func(t *testing.T, s *Store, w paApprovalWorld) {
			_, err := s.DB.ExecContext(ctx,
				`UPDATE pa_connections SET authority_revision = authority_revision + 1 WHERE principal = $1 AND id = $2`,
				w.principal, w.conn)
			must(t, err)
		},
		"state changed, same revision": func(t *testing.T, s *Store, w paApprovalWorld) {
			_, err := s.DB.ExecContext(ctx,
				`UPDATE pa_connections SET state = $1 WHERE principal = $2 AND id = $3`,
				string(connection.StateExpired), w.principal, w.conn)
			must(t, err)
		},
		"disconnect": func(t *testing.T, s *Store, w paApprovalWorld) {
			c, _, _, err := s.RevokePAConnection(ctx, w.principal, w.conn, "disconnect")
			must(t, err)
			if c.AuthorityRevision != w.rev+1 || c.State != connection.StateRevoked {
				t.Fatalf("revoke left revision %d state %s", c.AuthorityRevision, c.State)
			}
		},
		"expired by a failed refresh": func(t *testing.T, s *Store, w paApprovalWorld) {
			_, err := s.TransitionPAConnection(ctx, w.principal, w.conn, connection.Transition{
				From: connection.StateActive, To: connection.StateExpired, ExpectRevision: w.rev, Reason: "invalid_grant"})
			must(t, err)
		},
		"connection row gone": func(t *testing.T, s *Store, w paApprovalWorld) {
			_, err := s.DB.ExecContext(ctx, `DELETE FROM pa_connections WHERE principal = $1 AND id = $2`, w.principal, w.conn)
			must(t, err)
		},
	}
	cancelling := map[string]bool{"disconnect": true, "expired by a failed refresh": true}
	for name, move := range refused {
		t.Run(name, func(t *testing.T) {
			paApprovalDialects(t, func(t *testing.T, s *Store, alice, _ int64) {
				w := seedPAApprovalWorld(t, s, alice)
				a := w.approved(t, t0)
				move(t, s, w)
				_, _, err := paConsume(t, s, alice, a.ID, t0.Add(time.Minute))
				if cancelling[name] {
					// A transition made by the store also cancels the
					// approval in its own transaction (S2-C9, P2-S12),
					// so the consume meets a cancelled row before it
					// compares anything. The raw updates above are what
					// prove the comparison itself.
					if !errors.Is(err, approval.ErrCancelled) {
						t.Fatalf("consume: err = %v, want ErrCancelled", err)
					}
					if r := readPAApprovalRow(t, s, alice, a.ID); r.status != string(approval.StatusCancelled) || r.sealed != nil {
						t.Fatalf("row is status %q, args %q; want cancelled and erased", r.status, r.sealed)
					}
					if got := paDispatchStatuses(t, s, alice); len(got) != 0 {
						t.Fatalf("dispatch records %v, want none", got)
					}
					return
				}
				if !errors.Is(err, approval.ErrAuthorityChanged) {
					t.Fatalf("consume: err = %v, want ErrAuthorityChanged", err)
				}
				wantUntouched(t, s, alice, a)
			})
		})
	}
	// token_generation is bound to nothing (T2): a routine refresh between
	// the card and the tap must not refuse the approval.
	t.Run("token rotation does not refuse", func(t *testing.T) {
		paApprovalDialects(t, func(t *testing.T, s *Store, alice, _ int64) {
			w := seedPAApprovalWorld(t, s, alice)
			a := w.approved(t, t0)
			ok, err := s.ClaimPAConnectionRefresh(ctx, alice, w.conn, 1, "replica-a", t0, t0.Add(time.Minute))
			if err != nil || !ok {
				t.Fatalf("refresh lease: %v %v", ok, err)
			}
			c, err := s.RotatePAConnectionTokens(ctx, alice, w.conn, connection.Rotation{
				ExpectRevision: w.rev, ExpectGeneration: 1, GrantedScope: "home", LeaseOwner: "replica-a",
				SealedTokens: []byte("tokens-gen-2"), Now: t0.Add(time.Second)})
			if err != nil {
				t.Fatalf("rotate: %v", err)
			}
			if c.TokenGeneration != 2 || c.AuthorityRevision != w.rev {
				t.Fatalf("after the rotation: generation %d revision %d, want 2 and %d", c.TokenGeneration, c.AuthorityRevision, w.rev)
			}
			if _, _, err := paConsume(t, s, alice, a.ID, t0.Add(time.Minute)); err != nil {
				t.Fatalf("consume after a token rotation: %v", err)
			}
		})
	})
}

// S2-C12: a crash between the pre-dispatch commit and the result leaves a
// dispatching record. After a restart the sweep makes it outcome_unknown,
// and nothing dispatches again.
func TestS2C12_CrashedDispatchBecomesOutcomeUnknown(t *testing.T) {
	paApprovalDialects(t, func(t *testing.T, s *Store, alice, bob int64) {
		ctx := context.Background()
		w := seedPAApprovalWorld(t, s, alice)
		wb := seedPAApprovalWorld(t, s, bob)
		a := w.approved(t, t0)
		consumedAt := t0.Add(time.Minute)
		_, d, err := paConsume(t, s, alice, a.ID, consumedAt)
		must(t, err)
		// Bob's dispatch has a lease that is still running at the sweep.
		b := wb.approved(t, t0.Add(90*time.Second))
		_, live, err := paConsume(t, s, bob, b.ID, t0.Add(100*time.Second))
		must(t, err)

		// The process dies here: no FinishPADispatch. A new Store on the
		// same database is the restarted process.
		restarted := &Store{DB: s.DB, Crypt: s.Crypt}

		swept, err := restarted.SweepStalePADispatches(ctx, d.LeaseUntil.Add(-time.Millisecond))
		must(t, err)
		if len(swept) != 0 {
			t.Fatalf("sweep before the lease ran out moved %+v, want nothing", swept)
		}
		if got := paDispatchStatuses(t, s, alice); len(got) != 1 || got[0] != "dispatching" {
			t.Fatalf("before the lease ran out: dispatch records %v, want one dispatching", got)
		}

		sweepAt := d.LeaseUntil
		swept, err = restarted.SweepStalePADispatches(ctx, sweepAt)
		must(t, err)
		if len(swept) != 1 || swept[0].ID != d.ID || swept[0].Principal != alice ||
			swept[0].Status != approval.DispatchOutcomeUnknown || swept[0].ApprovalID != a.ID {
			t.Fatalf("sweep moved %+v, want alice's dispatch as outcome_unknown", swept)
		}
		check := func(when string) {
			t.Helper()
			if got := paDispatchStatuses(t, s, alice); len(got) != 1 || got[0] != "outcome_unknown" {
				t.Fatalf("%s: dispatch records %v, want exactly one outcome_unknown", when, got)
			}
			if r := readPAApprovalRow(t, s, alice, a.ID); r.status != "done" || r.sealed != nil {
				t.Fatalf("%s: approval row %+v, want done without arguments", when, r)
			}
			if got := paDispatchStatuses(t, s, bob); len(got) != 1 || got[0] != "dispatching" {
				t.Fatalf("%s: bob's live dispatch is %v, want dispatching", when, got)
			}
			if r := readPAApprovalRow(t, s, bob, b.ID); r.status != "dispatching" {
				t.Fatalf("%s: bob's approval is %q, want dispatching", when, r.status)
			}
		}
		check("after the sweep")

		// No second dispatch: still inside the approval's five minutes, the
		// receipt is not usable again.
		if _, _, err := paConsume(t, restarted, alice, a.ID, sweepAt.Add(time.Second)); !errors.Is(err, approval.ErrConsumed) {
			t.Fatalf("consume after the sweep: err = %v, want ErrConsumed", err)
		}
		// A second sweep moves nothing.
		swept, err = restarted.SweepStalePADispatches(ctx, sweepAt.Add(2*time.Second))
		must(t, err)
		if len(swept) != 0 {
			t.Fatalf("second sweep moved %+v, want nothing", swept)
		}
		// A result that arrives after the sweep does not overwrite it.
		err = inTx(t, s, func(tx *sql.Tx) error {
			_, err := s.FinishPADispatch(ctx, tx, alice, d.ID, approval.DispatchOK, sweepAt.Add(3*time.Second))
			return err
		})
		if !errors.Is(err, approval.ErrDispatchStale) {
			t.Fatalf("finish after the sweep: err = %v, want ErrDispatchStale", err)
		}
		check("after a late result")

		// Bob's call returns in time and is recorded as it ended.
		must(t, inTx(t, s, func(tx *sql.Tx) error {
			_, err := s.FinishPADispatch(ctx, tx, bob, live.ID, approval.DispatchFenced, sweepAt.Add(4*time.Second))
			return err
		}))
		if got := paDispatchStatuses(t, s, bob); len(got) != 1 || got[0] != "fenced" {
			t.Fatalf("bob's finished dispatch is %v, want fenced", got)
		}
		noArgsOutsideOpen(t, s, alice, bob)
	})
}

func TestPADispatch_Finish(t *testing.T) {
	paApprovalDialects(t, func(t *testing.T, s *Store, alice, bob int64) {
		ctx := context.Background()
		w := seedPAApprovalWorld(t, s, alice)
		a := w.approved(t, t0)
		_, d, err := paConsume(t, s, alice, a.ID, t0.Add(time.Minute))
		must(t, err)
		finish := func(principal int64, id string, st approval.DispatchStatus) error {
			return inTx(t, s, func(tx *sql.Tx) error {
				_, err := s.FinishPADispatch(ctx, tx, principal, id, st, t0.Add(2*time.Minute))
				return err
			})
		}
		if err := finish(alice, d.ID, approval.DispatchDispatching); !errors.Is(err, approval.ErrInvalid) {
			t.Fatalf("finish as dispatching: err = %v, want ErrInvalid", err)
		}
		if err := finish(bob, d.ID, approval.DispatchOK); !errors.Is(err, approval.ErrNotFound) {
			t.Fatalf("bob finishes alice's dispatch: err = %v, want ErrNotFound", err)
		}
		if err := finish(alice, "no-such-dispatch", approval.DispatchOK); !errors.Is(err, approval.ErrNotFound) {
			t.Fatalf("finish of an unknown dispatch: err = %v, want ErrNotFound", err)
		}
		if got := paDispatchStatuses(t, s, alice); len(got) != 1 || got[0] != "dispatching" {
			t.Fatalf("after refused finishes: %v, want one dispatching", got)
		}
		must(t, finish(alice, d.ID, approval.DispatchToolError))
		if err := finish(alice, d.ID, approval.DispatchOK); !errors.Is(err, approval.ErrDispatchStale) {
			t.Fatalf("second finish: err = %v, want ErrDispatchStale", err)
		}
		if got := paDispatchStatuses(t, s, alice); len(got) != 1 || got[0] != "tool_error" {
			t.Fatalf("after a second finish: %v, want the first result, tool_error", got)
		}
	})
}

func TestPAApproval_CreateBindsConversationAndConnection(t *testing.T) {
	paApprovalDialects(t, func(t *testing.T, s *Store, alice, bob int64) {
		ctx := context.Background()
		w := seedPAApprovalWorld(t, s, alice)
		wb := seedPAApprovalWorld(t, s, bob)
		create := func(a approval.Approval) error {
			return inTx(t, s, func(tx *sql.Tx) error { return s.CreatePAApproval(ctx, tx, a) })
		}
		cases := map[string]func(a *approval.Approval){
			"another principal's conversation": func(a *approval.Approval) { a.ConversationID = wb.conv },
			"another principal's connection":   func(a *approval.Approval) { a.ConnectionID = wb.conn },
			// Both rows are Bob's and consistent with each other: the row
			// would be created under Bob for a card Alice's run asked for.
			"another principal's conversation and connection": func(a *approval.Approval) {
				a.ConversationID, a.ConnectionID = wb.conv, wb.conn
			},
			"unknown conversation": func(a *approval.Approval) { a.ConversationID = "pcv_none" },
			"unknown connection":   func(a *approval.Approval) { a.ConnectionID = "pac_none" },
			"another revision":     func(a *approval.Approval) { a.AuthorityRevision = w.rev - 1 },
			"another server":       func(a *approval.Approval) { a.Server = string(connection.ServerTG) },
			"conversation expired": func(a *approval.Approval) {
				a.CreatedAt = t0.Add(paApprovalConvTTL)
			},
		}
		for name, edit := range cases {
			a := w.build(t, t0)
			edit(&a)
			if err := create(a); !errors.Is(err, approval.ErrBinding) {
				t.Errorf("%s: err = %v, want ErrBinding", name, err)
			}
		}
		invalid := map[string]func(a *approval.Approval){
			"no arguments":       func(a *approval.Approval) { a.SealedArgs = nil },
			"not pending":        func(a *approval.Approval) { a.Status = approval.StatusApproved },
			"no idempotency key": func(a *approval.Approval) { a.IdempotencyKey = "" },
			"one callback id":    func(a *approval.Approval) { a.CancelCallbackID = a.ApproveCallbackID },
			"bad args hash":      func(a *approval.Approval) { a.ArgsSHA = "abc" },
			"a read class":       func(a *approval.Approval) { a.Class = catalog.ClassRead },
		}
		for name, edit := range invalid {
			a := w.build(t, t0)
			edit(&a)
			if err := create(a); !errors.Is(err, approval.ErrInvalid) {
				t.Errorf("%s: err = %v, want ErrInvalid", name, err)
			}
		}
		// Not active: the connection is the principal's, at the revision,
		// but revoked.
		if _, err := s.DB.ExecContext(ctx, `UPDATE pa_connections SET state = $1 WHERE id = $2`,
			string(connection.StateRevoked), w.conn); err != nil {
			t.Fatal(err)
		}
		if err := create(w.build(t, t0)); !errors.Is(err, approval.ErrBinding) {
			t.Errorf("revoked connection: err = %v, want ErrBinding", err)
		}
		// A closed conversation.
		must(t, inTx(t, s, func(tx *sql.Tx) error { return s.ClosePAConversations(ctx, tx, bob, t0.Add(time.Minute)) }))
		if err := create(wb.build(t, t0.Add(2*time.Minute))); !errors.Is(err, approval.ErrBinding) {
			t.Errorf("closed conversation: err = %v, want ErrBinding", err)
		}
		if n := paRowsIn(t, s, "pa_approvals", alice) + paRowsIn(t, s, "pa_approvals", bob); n != 0 {
			t.Errorf("%d approval rows after refused creates, want 0", n)
		}
	})
}

// The consume refuses once the conversation the approval was made in is
// closed or expired, even if nothing cancelled the approval.
func TestPAApproval_ConsumeNeedsTheConversationOpen(t *testing.T) {
	paApprovalDialects(t, func(t *testing.T, s *Store, alice, _ int64) {
		ctx := context.Background()
		w := seedPAApprovalWorld(t, s, alice)
		a := w.approved(t, t0)
		if _, err := s.DB.ExecContext(ctx, `UPDATE pa_conversations SET closed_at_ms = $1 WHERE id = $2`,
			t0.Add(time.Minute).UnixMilli(), w.conv); err != nil {
			t.Fatal(err)
		}
		if _, _, err := paConsume(t, s, alice, a.ID, t0.Add(2*time.Minute)); !errors.Is(err, approval.ErrConversationClosed) {
			t.Fatalf("closed conversation: err = %v, want ErrConversationClosed", err)
		}
		wantUntouched(t, s, alice, a)
		// Open again, but past its own expiry at the consume.
		if _, err := s.DB.ExecContext(ctx, `UPDATE pa_conversations SET closed_at_ms = 0, expires_at_ms = $1 WHERE id = $2`,
			t0.Add(2*time.Minute).UnixMilli(), w.conv); err != nil {
			t.Fatal(err)
		}
		if _, _, err := paConsume(t, s, alice, a.ID, t0.Add(2*time.Minute)); !errors.Is(err, approval.ErrConversationClosed) {
			t.Fatalf("expired conversation: err = %v, want ErrConversationClosed", err)
		}
		wantUntouched(t, s, alice, a)
		if _, _, err := paConsume(t, s, alice, a.ID, t0.Add(2*time.Minute-time.Millisecond)); err != nil {
			t.Fatalf("1ms before the conversation expires: %v", err)
		}
	})
}

// The tap transitions: approve once, cancel only before the dispatch, and
// the callbacks of a card go when the approval leaves pending.
func TestPAApproval_TapTransitions(t *testing.T) {
	paApprovalDialects(t, func(t *testing.T, s *Store, alice, _ int64) {
		ctx := context.Background()
		w := seedPAApprovalWorld(t, s, alice)
		now := t0.Add(time.Minute)
		step := func(fn func(tx *sql.Tx) (approval.Approval, error)) (approval.Approval, error) {
			var a approval.Approval
			err := inTx(t, s, func(tx *sql.Tx) error {
				var err error
				a, err = fn(tx)
				return err
			})
			return a, err
		}
		approve := func(id string) (approval.Approval, error) {
			return step(func(tx *sql.Tx) (approval.Approval, error) { return s.ApprovePAApproval(ctx, tx, alice, id, now) })
		}
		cancel := func(id string) (approval.Approval, error) {
			return step(func(tx *sql.Tx) (approval.Approval, error) { return s.CancelPAApproval(ctx, tx, alice, id, now) })
		}
		refuse := func(id string) (approval.Approval, error) {
			return step(func(tx *sql.Tx) (approval.Approval, error) { return s.RefusePAApproval(ctx, tx, alice, id, now) })
		}
		lookup := func(cb string) (approval.Approval, error) {
			return step(func(tx *sql.Tx) (approval.Approval, error) { return s.LookupPAApprovalByCallback(ctx, tx, alice, cb) })
		}

		// Approve: once, and the card's callbacks are gone.
		a := w.pending(t, t0)
		other := w.pending(t, t0)
		got, err := approve(a.ID)
		must(t, err)
		if got.Status != approval.StatusApproved || got.Approver != alice || got.SealedArgs != nil {
			t.Fatalf("approve returned %+v, want approved by alice, no arguments in the read", got)
		}
		if n := paRowsIn(t, s, "pa_callbacks", alice); n != 2 {
			t.Fatalf("%d callbacks after one approve, want the other card's 2", n)
		}
		if _, err := approve(a.ID); !errors.Is(err, approval.ErrAlreadyApproved) {
			t.Fatalf("second approve: err = %v, want ErrAlreadyApproved", err)
		}
		// A tap whose callback is gone is answered from the row.
		for _, cb := range []string{a.ApproveCallbackID, a.CancelCallbackID} {
			found, err := lookup(cb)
			if err != nil || found.ID != a.ID || found.Status != approval.StatusApproved || found.SealedArgs != nil {
				t.Fatalf("lookup by callback %s = %+v, %v; want the approved approval without arguments", cb, found, err)
			}
		}
		if _, err := lookup("no-such-callback"); !errors.Is(err, approval.ErrNotFound) {
			t.Fatalf("lookup of an unknown callback: err = %v, want ErrNotFound", err)
		}
		if _, _, err := paConsume(t, s, alice, other.ID, now); !errors.Is(err, approval.ErrNotApproved) {
			t.Fatalf("consume of a pending approval: err = %v, want ErrNotApproved", err)
		}

		// Cancel after Approve, before the dispatch: allowed, arguments go.
		got, err = cancel(a.ID)
		must(t, err)
		if got.Status != approval.StatusCancelled || got.FinishedAt.IsZero() {
			t.Fatalf("cancel returned %+v, want cancelled with a finish time", got)
		}
		if r := readPAApprovalRow(t, s, alice, a.ID); r.status != "cancelled" || r.sealed != nil {
			t.Fatalf("cancelled row = %+v, want no arguments", r)
		}
		for name, call := range map[string]func(string) (approval.Approval, error){"approve": approve, "cancel": cancel, "refuse": refuse} {
			if _, err := call(a.ID); !errors.Is(err, approval.ErrCancelled) {
				t.Errorf("%s of a cancelled approval: err = %v, want ErrCancelled", name, err)
			}
		}
		if _, _, err := paConsume(t, s, alice, a.ID, now); !errors.Is(err, approval.ErrCancelled) {
			t.Fatalf("consume of a cancelled approval: err = %v, want ErrCancelled", err)
		}

		// Cancel of a pending card deletes its callbacks.
		_, err = cancel(other.ID)
		must(t, err)
		if n := paRowsIn(t, s, "pa_callbacks", alice); n != 0 {
			t.Fatalf("%d callbacks after both cards ended, want 0", n)
		}

		// Refuse burns an approved receipt.
		r := w.approved(t, t0)
		got, err = refuse(r.ID)
		must(t, err)
		if got.Status != approval.StatusRefused {
			t.Fatalf("refuse returned status %q", got.Status)
		}
		if _, _, err := paConsume(t, s, alice, r.ID, now); !errors.Is(err, approval.ErrRefused) {
			t.Fatalf("consume of a refused approval: err = %v, want ErrRefused", err)
		}

		// A dispatched call is never marked cancelled or refused.
		d := w.approved(t, t0)
		_, _, err = paConsume(t, s, alice, d.ID, now)
		must(t, err)
		for name, call := range map[string]func(string) (approval.Approval, error){"cancel": cancel, "refuse": refuse, "approve": approve} {
			if _, err := call(d.ID); !errors.Is(err, approval.ErrConsumed) {
				t.Errorf("%s of a dispatching approval: err = %v, want ErrConsumed", name, err)
			}
		}
		if row := readPAApprovalRow(t, s, alice, d.ID); row.status != "dispatching" {
			t.Fatalf("dispatching approval after cancel and refuse: status %q", row.status)
		}
		if _, err := approve("no-such-approval"); !errors.Is(err, approval.ErrNotFound) {
			t.Fatalf("approve of an unknown id: err = %v, want ErrNotFound", err)
		}
		noArgsOutsideOpen(t, s, alice)
	})
}

// /disconnect step 4 (the store half; the caller is P2-S12): only the
// approvals of that connection are cancelled, and not a dispatched one.
func TestPAApproval_CancelForConnection(t *testing.T) {
	paApprovalDialects(t, func(t *testing.T, s *Store, alice, bob int64) {
		ctx := context.Background()
		w := seedPAApprovalWorld(t, s, alice)
		wb := seedPAApprovalWorld(t, s, bob)
		// A second active connection of alice (another server in practice).
		second := w
		second.conn = "pac_apr_second_" + randomSuffix(t)
		if _, err := s.DB.ExecContext(ctx,
			`INSERT INTO pa_connections(id, principal, server, state, authority_revision, kek_id, created_at_ms, updated_at_ms)
			 VALUES($1, $2, $3, $4, $5, 'test', $6, $6)`,
			second.conn, alice, string(connection.ServerAlice), string(connection.StateActive), second.rev, t0.UnixMilli()); err != nil {
			t.Fatal(err)
		}
		pend, appr, disp := w.pending(t, t0), w.approved(t, t0), w.approved(t, t0)
		_, _, err := paConsume(t, s, alice, disp.ID, t0.Add(time.Minute))
		must(t, err)
		keep := second.pending(t, t0)
		bobs := wb.pending(t, t0)

		var n int64
		must(t, inTx(t, s, func(tx *sql.Tx) error {
			var err error
			n, err = s.CancelPAApprovalsForConnection(ctx, tx, alice, w.conn, t0.Add(2*time.Minute))
			return err
		}))
		if n != 2 {
			t.Fatalf("cancelled %d approvals, want 2", n)
		}
		want := map[string]string{pend.ID: "cancelled", appr.ID: "cancelled", disp.ID: "dispatching", keep.ID: "pending"}
		for id, st := range want {
			if r := readPAApprovalRow(t, s, alice, id); r.status != st {
				t.Errorf("approval %s: status %q, want %q", id, r.status, st)
			}
		}
		if r := readPAApprovalRow(t, s, bob, bobs.ID); r.status != "pending" || r.sealed == nil {
			t.Errorf("bob's approval = %+v, want pending with its arguments", r)
		}
		if n := paRowsIn(t, s, "pa_callbacks", alice); n != 2 {
			t.Errorf("alice has %d callbacks, want the 2 of the other connection's card", n)
		}
		if n := paRowsIn(t, s, "pa_callbacks", bob); n != 2 {
			t.Errorf("bob has %d callbacks, want 2", n)
		}
		noArgsOutsideOpen(t, s, alice, bob)
	})
}

// /new, /forget and consent withdrawal: no sealed arguments outlive the
// conversation they came from.
func TestPAApproval_ConversationEndErasesArguments(t *testing.T) {
	type ended struct {
		name string
		end  func(s *Store, tx *sql.Tx, principal int64) error
		// rows: whether the approval rows survive (as cancelled tombstones).
		rows bool
	}
	ctx := context.Background()
	at := t0.Add(2 * time.Minute)
	for _, c := range []ended{
		{"new", func(s *Store, tx *sql.Tx, p int64) error { return s.ClosePAConversations(ctx, tx, p, at) }, true},
		{"forget", func(s *Store, tx *sql.Tx, p int64) error { return s.ForgetPAConversations(ctx, tx, p) }, false},
		{"withdraw", func(s *Store, tx *sql.Tx, p int64) error { return s.WithdrawPAConsent(ctx, tx, p, at) }, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			paApprovalDialects(t, func(t *testing.T, s *Store, alice, bob int64) {
				w := seedPAApprovalWorld(t, s, alice)
				wb := seedPAApprovalWorld(t, s, bob)
				pend, appr, disp, done := w.pending(t, t0), w.approved(t, t0), w.approved(t, t0), w.approved(t, t0)
				_, _, err := paConsume(t, s, alice, disp.ID, t0.Add(time.Minute))
				must(t, err)
				_, dd, err := paConsume(t, s, alice, done.ID, t0.Add(time.Minute))
				must(t, err)
				must(t, inTx(t, s, func(tx *sql.Tx) error {
					_, err := s.FinishPADispatch(ctx, tx, alice, dd.ID, approval.DispatchOK, t0.Add(90*time.Second))
					return err
				}))
				bobs := wb.pending(t, t0)

				must(t, inTx(t, s, func(tx *sql.Tx) error { return c.end(s, tx, alice) }))

				var withArgs int
				must(t, s.DB.QueryRowContext(ctx,
					`SELECT COUNT(*) FROM pa_approvals WHERE principal = $1 AND sealed_args IS NOT NULL`, alice).Scan(&withArgs))
				if withArgs != 0 {
					t.Errorf("%d of alice's approvals still hold sealed arguments, want 0", withArgs)
				}
				if n := paRowsIn(t, s, "pa_callbacks", alice); n != 0 {
					t.Errorf("alice has %d callbacks left, want 0", n)
				}
				// The call on the wire keeps its record in every case.
				if r := readPAApprovalRow(t, s, alice, disp.ID); r.status != "dispatching" {
					t.Errorf("the dispatching approval is %q, want dispatching", r.status)
				}
				if c.rows {
					for _, id := range []string{pend.ID, appr.ID} {
						if r := readPAApprovalRow(t, s, alice, id); r.status != "cancelled" {
							t.Errorf("approval %s: status %q, want cancelled", id, r.status)
						}
					}
					if got := paDispatchStatuses(t, s, alice); len(got) != 2 {
						t.Errorf("dispatch records %v, want both kept", got)
					}
				} else {
					if n := paRowsIn(t, s, "pa_approvals", alice); n != 1 {
						t.Errorf("alice has %d approval rows, want only the dispatching one", n)
					}
					if got := paDispatchStatuses(t, s, alice); len(got) != 1 || got[0] != "dispatching" {
						t.Errorf("dispatch records %v, want only the dispatching one", got)
					}
				}
				// The consume of what was open is refused, not "not found".
				if c.rows {
					if _, _, err := paConsume(t, s, alice, appr.ID, at); !errors.Is(err, approval.ErrCancelled) {
						t.Errorf("consume after %s: err = %v, want ErrCancelled", c.name, err)
					}
				}
				if r := readPAApprovalRow(t, s, bob, bobs.ID); r.status != "pending" || r.sealed == nil {
					t.Errorf("bob's approval = %+v, want pending with its arguments", r)
				}
				if n := paRowsIn(t, s, "pa_callbacks", bob); n != 2 {
					t.Errorf("bob has %d callbacks, want 2", n)
				}
			})
		})
	}
}

// The sweep: an approval past its five minutes is expired and loses its
// arguments; rows go approval.Retention after they were created; a
// dispatching row is never touched.
func TestSweepPAState_ApprovalRetention(t *testing.T) {
	paApprovalDialects(t, func(t *testing.T, s *Store, alice, _ int64) {
		ctx := context.Background()
		w := seedPAApprovalWorld(t, s, alice)
		pend, appr := w.pending(t, t0), w.approved(t, t0)
		fresh := w.pending(t, t0.Add(4*time.Minute))
		disp, done := w.approved(t, t0), w.approved(t, t0)
		_, _, err := paConsume(t, s, alice, disp.ID, t0.Add(time.Minute))
		must(t, err)
		_, dd, err := paConsume(t, s, alice, done.ID, t0.Add(time.Minute))
		must(t, err)
		must(t, inTx(t, s, func(tx *sql.Tx) error {
			_, err := s.FinishPADispatch(ctx, tx, alice, dd.ID, approval.DispatchOK, t0.Add(90*time.Second))
			return err
		}))
		// A consume that failed after its compare-and-set, committed against
		// the contract: a dispatching approval that no dispatch record owns.
		orphan := w.approved(t, t0)
		if _, err := s.DB.ExecContext(ctx, `UPDATE pa_approvals SET status = 'dispatching', sealed_args = NULL WHERE id = $1`, orphan.ID); err != nil {
			t.Fatal(err)
		}
		sweep := func(now time.Time) {
			t.Helper()
			if _, err := s.SweepPAState(ctx, now, now.Add(-48*time.Hour)); err != nil {
				t.Fatalf("sweep: %v", err)
			}
		}
		status := func(id string) string {
			t.Helper()
			var st string
			err := s.DB.QueryRowContext(ctx, `SELECT status FROM pa_approvals WHERE principal = $1 AND id = $2`, alice, id).Scan(&st)
			if errors.Is(err, sql.ErrNoRows) {
				return "(deleted)"
			}
			must(t, err)
			return st
		}
		wantStatuses := func(when string, want map[string]string) {
			t.Helper()
			for id, st := range want {
				if got := status(id); got != st {
					t.Errorf("%s: approval %s is %s, want %s", when, id, got, st)
				}
			}
		}

		// At the expiry of the first cards: they expire, the fresh one stays.
		sweep(t0.Add(approval.TTL))
		wantStatuses("at +5m", map[string]string{pend.ID: "expired", appr.ID: "expired", fresh.ID: "pending",
			disp.ID: "dispatching", done.ID: "done"})
		noArgsOutsideOpen(t, s, alice)
		if r := readPAApprovalRow(t, s, alice, fresh.ID); r.sealed == nil {
			t.Errorf("the unexpired approval lost its arguments")
		}
		if _, _, err := paConsume(t, s, alice, appr.ID, t0.Add(approval.TTL)); !errors.Is(err, approval.ErrExpired) {
			t.Errorf("consume of a swept approval: err = %v, want ErrExpired", err)
		}

		// Just inside the retention nothing is deleted.
		sweep(t0.Add(approval.Retention))
		wantStatuses("at +24h", map[string]string{pend.ID: "expired", appr.ID: "expired", fresh.ID: "expired",
			disp.ID: "dispatching", done.ID: "done", orphan.ID: "dispatching"})
		if got := paDispatchStatuses(t, s, alice); len(got) != 2 {
			t.Errorf("at +24h: dispatch records %v, want both", got)
		}

		// Past it the ended rows go; the dispatching pair stays.
		sweep(t0.Add(approval.Retention + 5*time.Minute))
		wantStatuses("past retention", map[string]string{pend.ID: "(deleted)", appr.ID: "(deleted)", fresh.ID: "(deleted)",
			disp.ID: "dispatching", done.ID: "(deleted)", orphan.ID: "(deleted)"})
		if got := paDispatchStatuses(t, s, alice); len(got) != 1 || got[0] != "dispatching" {
			t.Errorf("past retention: dispatch records %v, want only the dispatching one", got)
		}
	})
}

func TestPAApprovalRetention_Bounds(t *testing.T) {
	if approval.Retention > 24*time.Hour {
		t.Errorf("approval.Retention = %s, want at most the 24h the consent text promises", approval.Retention)
	}
	if approval.TTL != 5*time.Minute {
		t.Errorf("approval.TTL = %s, want 5m (threat model T7)", approval.TTL)
	}
}

// A row or a read that cannot be interpreted is ErrUnreadable: never "no
// approval", never "expired", never an empty sweep.
func TestPAApproval_UnreadableIsNotAbsence(t *testing.T) {
	notAbsence := func(t *testing.T, what string, err error) {
		t.Helper()
		if !errors.Is(err, approval.ErrUnreadable) {
			t.Errorf("%s: err = %v, want ErrUnreadable", what, err)
		}
		for _, absent := range []error{approval.ErrNotFound, approval.ErrExpired, approval.ErrConsumed, approval.ErrCancelled} {
			if errors.Is(err, absent) {
				t.Errorf("%s: err = %v reads as %v", what, err, absent)
			}
		}
	}
	paApprovalDialects(t, func(t *testing.T, s *Store, alice, _ int64) {
		ctx := context.Background()
		w := seedPAApprovalWorld(t, s, alice)
		now := t0.Add(time.Minute)

		// A status this build does not know.
		a := w.approved(t, t0)
		if _, err := s.DB.ExecContext(ctx, `UPDATE pa_approvals SET status = 'paused' WHERE id = $1`, a.ID); err != nil {
			t.Fatal(err)
		}
		err := inTx(t, s, func(tx *sql.Tx) error { _, err := s.GetPAApproval(ctx, tx, alice, a.ID); return err })
		notAbsence(t, "get of a row with an unknown status", err)
		_, _, err = paConsume(t, s, alice, a.ID, now)
		notAbsence(t, "consume of a row with an unknown status", err)
		err = inTx(t, s, func(tx *sql.Tx) error { _, err := s.CancelPAApproval(ctx, tx, alice, a.ID, now); return err })
		notAbsence(t, "cancel of a row with an unknown status", err)

		// An approved row without arguments.
		b := w.approved(t, t0)
		if _, err := s.DB.ExecContext(ctx, `UPDATE pa_approvals SET sealed_args = NULL WHERE id = $1`, b.ID); err != nil {
			t.Fatal(err)
		}
		_, _, err = paConsume(t, s, alice, b.ID, now)
		notAbsence(t, "consume of an approved row without arguments", err)
		if got := paDispatchStatuses(t, s, alice); len(got) != 0 {
			t.Errorf("dispatch records %v after unreadable consumes, want none", got)
		}

		// A dispatch row with an unknown status.
		c := w.approved(t, t0)
		_, d, err := paConsume(t, s, alice, c.ID, now)
		must(t, err)
		if _, err := s.DB.ExecContext(ctx, `UPDATE pa_dispatches SET status = 'sent' WHERE id = $1`, d.ID); err != nil {
			t.Fatal(err)
		}
		err = inTx(t, s, func(tx *sql.Tx) error {
			_, err := s.FinishPADispatch(ctx, tx, alice, d.ID, approval.DispatchOK, now)
			return err
		})
		notAbsence(t, "finish of a dispatch with an unknown status", err)
		if errors.Is(err, approval.ErrDispatchStale) {
			t.Errorf("finish of an unreadable dispatch reads as stale: %v", err)
		}

		// A failed read: the context is already cancelled.
		dead, stop := context.WithCancel(ctx)
		stop()
		e := w.approved(t, t0)
		tx, err := s.DB.BeginTx(ctx, nil)
		must(t, err)
		_, _, err = s.ConsumePAApproval(dead, tx, approval.ConsumeRequest{
			Principal: alice, ApprovalID: e.ID, DispatchID: approval.NewID(), Now: now, Lease: time.Minute})
		notAbsence(t, "consume on a failed read", err)
		_, err = s.GetPAApproval(dead, tx, alice, e.ID)
		notAbsence(t, "get on a failed read", err)
		_, err = s.LookupPAApprovalByCallback(dead, tx, alice, e.ApproveCallbackID)
		notAbsence(t, "lookup on a failed read", err)
		_, err = s.FinishPADispatch(dead, tx, alice, d.ID, approval.DispatchOK, now)
		notAbsence(t, "finish on a failed read", err)
		must(t, tx.Rollback())
		swept, err := s.SweepStalePADispatches(dead, now.Add(time.Hour))
		notAbsence(t, "sweep on a failed read", err)
		if swept != nil {
			t.Errorf("a failed sweep returned %v", swept)
		}
	})
}

func TestPAApproval_InvalidRequests(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	must(t, inTx(t, s, func(tx *sql.Tx) error {
		ok := approval.ConsumeRequest{Principal: 555, ApprovalID: "a", DispatchID: "d", Now: t0, Lease: time.Minute}
		bad := map[string]approval.ConsumeRequest{}
		for name, edit := range map[string]func(r *approval.ConsumeRequest){
			"no principal": func(r *approval.ConsumeRequest) { r.Principal = 0 },
			"no approval":  func(r *approval.ConsumeRequest) { r.ApprovalID = "" },
			"no dispatch":  func(r *approval.ConsumeRequest) { r.DispatchID = "" },
			"no time":      func(r *approval.ConsumeRequest) { r.Now = time.Time{} },
			"no lease":     func(r *approval.ConsumeRequest) { r.Lease = 0 },
			"long lease":   func(r *approval.ConsumeRequest) { r.Lease = approval.MaxDispatchLease + time.Second },
		} {
			r := ok
			edit(&r)
			bad[name] = r
		}
		for name, r := range bad {
			if _, _, err := s.ConsumePAApproval(ctx, tx, r); !errors.Is(err, approval.ErrInvalid) {
				t.Errorf("consume, %s: err = %v, want ErrInvalid", name, err)
			}
		}
		if _, _, err := s.ConsumePAApproval(ctx, nil, ok); !errors.Is(err, approval.ErrInvalid) {
			t.Errorf("consume without a transaction: err = %v, want ErrInvalid", err)
		}
		return nil
	}))
	if _, err := s.SweepStalePADispatches(ctx, time.Time{}); !errors.Is(err, approval.ErrInvalid) {
		t.Errorf("sweep without a time: err = %v, want ErrInvalid", err)
	}
}

// The ledger's tables exist after the migration, on both dialects.
func TestPAApprovals_Migrated(t *testing.T) {
	paApprovalDialects(t, func(t *testing.T, s *Store, alice, _ int64) {
		for _, tb := range []string{"pa_approvals", "pa_dispatches"} {
			if n := paRowsIn(t, s, tb, alice); n != 0 {
				t.Errorf("%s: %d rows for a fresh principal", tb, n)
			}
		}
		// Idempotent: a second pass of the DDL changes nothing.
		pg, err := s.postgresDialect(context.Background())
		must(t, err)
		if err := migratePAApprovals(context.Background(), s.DB, pg); err != nil {
			t.Fatalf("second migration pass: %v", fmt.Errorf("%w", err))
		}
	})
}
