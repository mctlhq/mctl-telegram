package db

import (
	"context"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/pa/jobs"
)

// TestPAOutbox_ApprovalNoticeOncePerApproval (#1320 slice P2-S3): an
// approval gets one outcome notice whatever its kind, so the executor and
// the stale-dispatch sweep cannot both report one call; two approvals, and
// a conversation-level row of the same principal, keep their own rows. The
// row is read back without the update id it stores for the older index,
// and can be claimed like any other.
func TestPAOutbox_ApprovalNoticeOncePerApproval(t *testing.T) {
	paLinkDialects(t, func(t *testing.T, s *Store) {
		ctx := context.Background()
		p := paLinkPrincipal(t, s)
		t.Cleanup(func() { _, _ = s.DB.Exec(`DELETE FROM pa_outbox WHERE principal = $1`, p) })
		for _, it := range []jobs.OutboxItem{
			{Principal: p, Kind: jobs.OutboxForgotten, UpdateID: 7},
			{Principal: p, Kind: jobs.OutboxWriteDone, ApprovalID: "apr_one"},
			{Principal: p, Kind: jobs.OutboxWriteUnknown, ApprovalID: "apr_one"},
			{Principal: p, Kind: jobs.OutboxWriteFenced, ApprovalID: "apr_two"},
			{Principal: p, Kind: jobs.OutboxWriteFenced, ApprovalID: "apr_two"},
		} {
			tx, err := s.DB.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := enqueuePAOutbox(ctx, tx, it, 1); err != nil {
				_ = tx.Rollback()
				t.Fatalf("enqueue %+v: %v", it, err)
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
		}
		rows, err := s.PAOutboxRows(ctx, p)
		if err != nil || len(rows) != 3 {
			t.Fatalf("rows %+v (%v), want one per approval and the conversation row", rows, err)
		}
		want := []jobs.OutboxItem{
			{Kind: jobs.OutboxForgotten, UpdateID: 7},
			{Kind: jobs.OutboxWriteDone, ApprovalID: "apr_one"},
			{Kind: jobs.OutboxWriteFenced, ApprovalID: "apr_two"},
		}
		for i, r := range rows {
			if r.Kind != want[i].Kind || r.ApprovalID != want[i].ApprovalID || r.UpdateID != want[i].UpdateID || !r.Valid() {
				t.Fatalf("row %d: %+v, want %+v", i, r, want[i])
			}
		}
		now := time.UnixMilli(10)
		got := 0
		for range 3 {
			res, err := s.ClaimPAOutbox(ctx, jobs.OutboxClaimRequest{Now: now, Lease: time.Minute, Principal: p, Limit: 1})
			if err != nil {
				t.Fatal(err)
			}
			for _, it := range res.Items {
				if !it.Valid() {
					t.Fatalf("claimed an invalid item %+v", it)
				}
				got++
				if err := s.CompletePAOutbox(ctx, it, jobs.OutboxCompletion{Now: now, Status: jobs.OutboxSent}); err != nil {
					t.Fatal(err)
				}
			}
		}
		if got != 3 {
			t.Fatalf("claimed %d rows, want 3", got)
		}
	})
}

// TestPAOutbox_ApprovalItemShape: an approval-level item has an approval
// id and nothing else, and no other kind may carry one.
func TestPAOutbox_ApprovalItemShape(t *testing.T) {
	ok := jobs.OutboxItem{Principal: 1, Kind: jobs.OutboxWriteUnknown, ApprovalID: "apr_one"}
	if !ok.Valid() {
		t.Fatal("a plain approval item is not valid")
	}
	for name, it := range map[string]jobs.OutboxItem{
		"no approval":     {Principal: 1, Kind: jobs.OutboxWriteUnknown},
		"with a job":      {Principal: 1, Kind: jobs.OutboxWriteUnknown, ApprovalID: "apr_one", JobID: 3},
		"with an update":  {Principal: 1, Kind: jobs.OutboxWriteUnknown, ApprovalID: "apr_one", UpdateID: 3},
		"with connection": {Principal: 1, Kind: jobs.OutboxWriteUnknown, ApprovalID: "apr_one", ConnectionID: "pac_a"},
		"other kind":      {Principal: 1, Kind: jobs.OutboxForgotten, UpdateID: 7, ApprovalID: "apr_one"},
	} {
		if it.Valid() {
			t.Errorf("%s: %+v is valid", name, it)
		}
	}
	if a, b := paApprovalOutboxUpdateID("apr_one"), paApprovalOutboxUpdateID("apr_two"); a >= 0 || b >= 0 || a == b {
		t.Fatalf("stored update ids %d %d, want distinct negatives", a, b)
	}
}
