package db

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/pa/approval"
	"github.com/mctlhq/mctl-telegram/internal/pa/jobs"
)

// Store tests of the approval card (#1320 slice P2-S5): the card-level
// outbox row and the deliverer's read of the approval, on SQLite always
// and on Postgres when TEST_DATABASE_URL is set.

// TestPAApprovalForCard: the deliverer reads an approval by its Approve
// callback id, with the sealed arguments, under the principal only.
func TestPAApprovalForCard(t *testing.T) {
	paApprovalDialects(t, func(t *testing.T, s *Store, alice, bob int64) {
		ctx := context.Background()
		wa := seedPAApprovalWorld(t, s, alice)
		seedPAApprovalWorld(t, s, bob)
		a := wa.pending(t, t0)

		got, err := s.PAApprovalForCard(ctx, alice, a.ApproveCallbackID)
		must(t, err)
		if got.ID != a.ID || got.Status != approval.StatusPending || !bytes.Equal(got.SealedArgs, a.SealedArgs) ||
			got.CancelCallbackID != a.CancelCallbackID || !got.ExpiresAt.Equal(a.ExpiresAt) {
			t.Fatalf("read %+v, want the pending approval %s with its arguments", got, a.ID)
		}
		for name, read := range map[string]func() error{
			"bob, alice's approve id": func() error { _, err := s.PAApprovalForCard(ctx, bob, a.ApproveCallbackID); return err },
			"alice, the cancel id":    func() error { _, err := s.PAApprovalForCard(ctx, alice, a.CancelCallbackID); return err },
			"alice, the approval id":  func() error { _, err := s.PAApprovalForCard(ctx, alice, a.ID); return err },
		} {
			if err := read(); !errors.Is(err, approval.ErrNotFound) {
				t.Errorf("%s: err = %v, want ErrNotFound", name, err)
			}
		}
		for name, read := range map[string]func() error{
			"no principal": func() error { _, err := s.PAApprovalForCard(ctx, 0, a.ApproveCallbackID); return err },
			"no id":        func() error { _, err := s.PAApprovalForCard(ctx, alice, ""); return err },
		} {
			if err := read(); !errors.Is(err, approval.ErrInvalid) {
				t.Errorf("%s: err = %v, want ErrInvalid", name, err)
			}
		}

		// An ended approval is still found, with nothing left to show.
		must(t, inTx(t, s, func(tx *sql.Tx) error {
			_, err := s.CancelPAApproval(ctx, tx, alice, a.ID, t0.Add(time.Second))
			return err
		}))
		got, err = s.PAApprovalForCard(ctx, alice, a.ApproveCallbackID)
		must(t, err)
		if got.Status != approval.StatusCancelled || len(got.SealedArgs) != 0 {
			t.Fatalf("after cancel: status %q, %d bytes of arguments", got.Status, len(got.SealedArgs))
		}
	})
}

// TestPAApprovalForCard_UnreadableIsNotAbsence: a failed read is an error
// of its own, never "no such approval" (I9).
func TestPAApprovalForCard_UnreadableIsNotAbsence(t *testing.T) {
	s := newTestStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := s.PAApprovalForCard(ctx, 555, "cb")
	if !errors.Is(err, approval.ErrUnreadable) || errors.Is(err, approval.ErrNotFound) {
		t.Fatalf("read on a cancelled context: err = %v, want ErrUnreadable", err)
	}
}

func cardItem(p int64, button string) jobs.OutboxItem {
	return jobs.OutboxItem{Principal: p, Kind: jobs.OutboxApprovalCard, Button: button}
}

// TestPAOutbox_CardRow: a card row is written with its transaction, once
// per Approve callback id, and reads back as the item that was enqueued. A
// second card for the same id is an error, never a silent drop: its
// approval is written in the same transaction and must not commit without
// it.
func TestPAOutbox_CardRow(t *testing.T) {
	paApprovalDialects(t, func(t *testing.T, s *Store, alice, bob int64) {
		ctx := context.Background()
		clean := func() { _, _ = s.DB.Exec(`DELETE FROM pa_outbox WHERE principal IN ($1, $2)`, alice, bob) }
		clean()
		t.Cleanup(clean)
		now := t0

		must(t, inTx(t, s, func(tx *sql.Tx) error { return s.EnqueuePAOutbox(ctx, tx, cardItem(alice, "cb-one"), now) }))
		must(t, inTx(t, s, func(tx *sql.Tx) error { return s.EnqueuePAOutbox(ctx, tx, cardItem(alice, "cb-two"), now) }))
		// The same id for another principal is another card.
		must(t, inTx(t, s, func(tx *sql.Tx) error { return s.EnqueuePAOutbox(ctx, tx, cardItem(bob, "cb-one"), now) }))

		err := inTx(t, s, func(tx *sql.Tx) error { return s.EnqueuePAOutbox(ctx, tx, cardItem(alice, "cb-one"), now) })
		if !errors.Is(err, jobs.ErrOutboxUpdateReused) {
			t.Fatalf("second card for one callback id: err = %v, want ErrOutboxUpdateReused", err)
		}

		rows, err := s.PAOutboxRows(ctx, alice)
		must(t, err)
		if len(rows) != 2 {
			t.Fatalf("%d rows for alice, want 2", len(rows))
		}
		for _, r := range rows {
			if !r.Valid() || r.Kind != jobs.OutboxApprovalCard || r.UpdateID != 0 || r.JobID != 0 ||
				(r.Button != "cb-one" && r.Button != "cb-two") {
				t.Errorf("row reads back as %+v", r)
			}
		}
		// The stored update id is negative, so it never meets a Telegram
		// update id in the conversation-level key.
		var positive int
		must(t, s.DB.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM pa_outbox WHERE principal = $1 AND kind = $2 AND update_id >= 0`,
			alice, string(jobs.OutboxApprovalCard)).Scan(&positive))
		if positive != 0 {
			t.Fatalf("%d card rows with a non-negative update_id", positive)
		}

		for name, it := range map[string]jobs.OutboxItem{
			"no button":        {Principal: alice, Kind: jobs.OutboxApprovalCard},
			"with an update":   {Principal: alice, Kind: jobs.OutboxApprovalCard, Button: "cb-x", UpdateID: 7},
			"with a job":       {Principal: alice, Kind: jobs.OutboxApprovalCard, Button: "cb-x", JobID: 7},
			"with an approval": {Principal: alice, Kind: jobs.OutboxApprovalCard, Button: "cb-x", ApprovalID: "apr"},
		} {
			err := inTx(t, s, func(tx *sql.Tx) error { return s.EnqueuePAOutbox(ctx, tx, it, now) })
			if !errors.Is(err, jobs.ErrInvalid) {
				t.Errorf("%s: err = %v, want ErrInvalid", name, err)
			}
		}
	})
}

// TestPAJobHasApproval: a run has had a card once any approval row of its
// job exists, whatever became of it, and only for that principal and that
// job (#1320 slice P2-S14, "one approval card per run").
func TestPAJobHasApproval(t *testing.T) {
	paApprovalDialects(t, func(t *testing.T, s *Store, alice, bob int64) {
		ctx := context.Background()
		wa := seedPAApprovalWorld(t, s, alice)
		seedPAApprovalWorld(t, s, bob)
		job := wa.binding().JobID
		has := func(principal, jobID int64) bool {
			t.Helper()
			var got bool
			must(t, inTx(t, s, func(tx *sql.Tx) error {
				var err error
				got, err = s.PAJobHasApproval(ctx, tx, principal, jobID)
				return err
			}))
			return got
		}
		if has(alice, job) {
			t.Fatal("a job with no approval reads as carded")
		}
		a := wa.pending(t, t0)
		if !has(alice, job) {
			t.Fatal("the job's pending approval is not seen")
		}
		if has(alice, job+1) || has(bob, job) {
			t.Fatal("another job, or another principal's job of the same id, reads as carded")
		}
		// An approval that ended still counts: the run had its card.
		must(t, inTx(t, s, func(tx *sql.Tx) error {
			_, err := s.CancelPAApproval(ctx, tx, alice, a.ID, t0.Add(time.Second))
			return err
		}))
		if !has(alice, job) {
			t.Fatal("after the card was cancelled the job reads as not carded")
		}
		for name, args := range map[string][2]int64{"no principal": {0, job}, "no job": {alice, 0}} {
			err := inTx(t, s, func(tx *sql.Tx) error {
				_, err := s.PAJobHasApproval(ctx, tx, args[0], args[1])
				return err
			})
			if !errors.Is(err, approval.ErrInvalid) {
				t.Errorf("%s: err = %v, want ErrInvalid", name, err)
			}
		}
		if _, err := s.PAJobHasApproval(ctx, nil, alice, job); !errors.Is(err, approval.ErrInvalid) {
			t.Errorf("no transaction: err = %v, want ErrInvalid", err)
		}
	})
}

// TestPAJobHasApproval_UnreadableIsNotAbsence: a failed read is never "no
// card yet" (I9).
func TestPAJobHasApproval_UnreadableIsNotAbsence(t *testing.T) {
	s := newTestStore(t)
	tx, err := s.DB.BeginTx(context.Background(), nil)
	must(t, err)
	must(t, tx.Rollback())
	carded, err := s.PAJobHasApproval(context.Background(), tx, 555, 7)
	if carded || !errors.Is(err, approval.ErrUnreadable) {
		t.Fatalf("read on a finished transaction: carded=%v err=%v, want ErrUnreadable", carded, err)
	}
}
