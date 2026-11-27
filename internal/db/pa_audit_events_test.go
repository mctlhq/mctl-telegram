// Copyright 2025 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/pa/approval"
	"github.com/mctlhq/mctl-telegram/internal/pa/auditevent"
)

// paEventWorld is Alice with a users row, an open conversation and one
// active alice connection: what a grant, an approval and an audit row need.
type paEventWorld struct {
	paApprovalWorld
	user int64
}

func newPAEventWorld(t *testing.T, s *Store, principal int64) paEventWorld {
	t.Helper()
	user, err := s.EnsureUserByTelegramID(context.Background(), principal, "alice", "Alice")
	must(t, err)
	t.Cleanup(func() {
		for _, q := range []string{
			`DELETE FROM pa_audit_events WHERE principal = $1`,
			`DELETE FROM pa_permissions WHERE principal = $1`,
			`DELETE FROM pa_principal_disables WHERE principal = $1`,
		} {
			_, _ = s.DB.Exec(q, principal)
		}
		_, _ = s.DB.Exec(`DELETE FROM audit_logs WHERE user_id = $1`, user)
		_, _ = s.DB.Exec(`DELETE FROM users WHERE id = $1`, user)
	})
	return paEventWorld{paApprovalWorld: seedPAApprovalWorld(t, s, principal), user: user}
}

func (w paEventWorld) grant(t *testing.T, id string, at time.Time) {
	t.Helper()
	pw := paPermWorld{s: w.s, principal: w.principal, conn: w.conn, rev: w.rev}
	p := pw.perm(id)
	p.ExpiresAt = at.Add(time.Hour)
	must(t, pw.insert(t, p, at))
}

// queued lists the principal's queued events as "kind subject reason".
func (w paEventWorld) queued(t *testing.T) []string {
	t.Helper()
	rows, err := w.s.DB.Query(`SELECT kind, subject, reason FROM pa_audit_events WHERE principal = $1 ORDER BY id`, w.principal)
	must(t, err)
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var k, sub, r string
		must(t, rows.Scan(&k, &sub, &r))
		out = append(out, strings.TrimSpace(k+" "+sub+" "+r))
	}
	must(t, rows.Err())
	return out
}

// paEventRow renders an event the way the service's sweeper does
// (connector.AuditEventRow, which this package cannot import).
func paEventRow(e auditevent.Event) (ToolCall, error) {
	rec, err := e.Record()
	if err != nil {
		return ToolCall{}, err
	}
	return ToolCall{Tool: "pa:" + e.Server + "/" + e.Tool, PeerRedacted: rec, Status: string(e.Kind), CallPath: "pa"}, nil
}

// drain runs one pass over the whole queue and returns its counts. Rows
// other tests left behind on a shared Postgres belong to principals
// without a users row and are dropped; the assertions here read this
// principal's rows only.
func (w paEventWorld) drain(t *testing.T, render func(auditevent.Event) (ToolCall, error)) PAAuditDrain {
	t.Helper()
	res, err := w.s.DrainPAAuditEvents(context.Background(), 100000, render)
	must(t, err)
	return res
}

// audit lists the user's audit rows, oldest first, as "status record".
func (w paEventWorld) audit(t *testing.T) []string {
	t.Helper()
	rows, err := w.s.DB.Query(`SELECT tool_name, status, peer_redacted, call_path, COALESCE(error, '') FROM audit_logs WHERE user_id = $1 ORDER BY id`, w.user)
	must(t, err)
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var tool, status, rec, path, errText string
		must(t, rows.Scan(&tool, &status, &rec, &path, &errText))
		if tool != "pa:alice/alice_set_volume" || path != "pa" || errText != "" {
			t.Errorf("audit row %s %s has tool %q, call_path %q, error %q", status, rec, tool, path, errText)
		}
		out = append(out, status+" "+rec)
	}
	must(t, rows.Err())
	return out
}

func (w paEventWorld) wantChain(t *testing.T) {
	t.Helper()
	v, err := w.s.VerifyAuditChain(context.Background(), w.user)
	must(t, err)
	if !v.OK {
		t.Fatalf("audit chain does not verify: %+v", v)
	}
}

// TestS2A8_PermissionChangesAreAudited: a grant, and a revocation by each
// of the changes that revoke, queue their audit event in the transaction
// of the change, and the drain appends each to the principal's audit
// chain exactly once. The record holds the permission's id, its
// connection and revision and a closed reason: no device, no ceiling.
func TestS2A8_PermissionChangesAreAudited(t *testing.T) {
	paConvoDialects(t, func(t *testing.T, s *Store, alice, _ int64) {
		ctx := context.Background()
		w := newPAEventWorld(t, s, alice)
		at := func(min int) time.Time { return t0.Add(time.Duration(min) * time.Minute) }

		// A grant that does not commit queues nothing.
		tx, err := s.DB.BeginTx(ctx, nil)
		must(t, err)
		pw := paPermWorld{s: s, principal: alice, conn: w.conn, rev: w.rev}
		must(t, s.InsertPAPermission(ctx, tx, pw.perm("prm_lost"), at(0)))
		must(t, tx.Rollback())
		if got := w.queued(t); len(got) != 0 {
			t.Fatalf("a rolled back grant queued %v", got)
		}

		w.grant(t, "prm_a", at(1))
		w.grant(t, "prm_b", at(2))
		must(t, inTx(t, s, func(tx *sql.Tx) error { return s.RevokePAPermission(ctx, tx, alice, "prm_a", at(3)) }))
		// A second press finds nothing to revoke, and queues nothing.
		if err := inTx(t, s, func(tx *sql.Tx) error { return s.RevokePAPermission(ctx, tx, alice, "prm_a", at(3)) }); err == nil {
			t.Fatal("a second revoke of the same permission succeeded")
		}
		must(t, s.SetPAPrincipalDisabled(ctx, alice, alice, "test", at(4)))
		w.grant(t, "prm_c", at(5))
		must(t, inTx(t, s, func(tx *sql.Tx) error { return s.ForgetPAConversations(ctx, tx, alice) }))
		w.grant(t, "prm_d", at(6))
		w.grant(t, "prm_e", at(6))
		if _, err := s.RevokePAConnectionAt(ctx, alice, w.conn, w.rev, 1, "user_disconnect"); err != nil {
			t.Fatalf("revoke connection: %v", err)
		}
		want := []string{
			"permission_granted prm_a", "permission_granted prm_b",
			"permission_revoked prm_a by_principal",
			"permission_revoked prm_b principal_disabled",
			"permission_granted prm_c",
			"permission_revoked prm_c data_forgotten",
			"permission_granted prm_d", "permission_granted prm_e",
			"permission_revoked prm_d connection_changed", "permission_revoked prm_e connection_changed",
		}
		got := w.queued(t)
		// The two rows one statement revoked have no order of their own.
		slices.Sort(got[len(got)-2:])
		if !slices.Equal(got, want) {
			t.Fatalf("queued events:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
		}
		if len(w.audit(t)) != 0 {
			t.Fatal("an event reached the chain before the drain")
		}

		if res := w.drain(t, paEventRow); res.Failed != 0 || res.Appended < len(want) {
			t.Fatalf("drain %+v, want %d appended and none failed", res, len(want))
		}
		if left := w.queued(t); len(left) != 0 {
			t.Fatalf("still queued after the drain: %v", left)
		}
		audit := w.audit(t)
		if len(audit) != len(want) {
			t.Fatalf("%d audit rows, want %d:\n%s", len(audit), len(want), strings.Join(audit, "\n"))
		}
		rec := func(kind, id, reason string, min int) string {
			return fmt.Sprintf("%s pa-event/v1 event=%s principal=%d server=alice tool=alice_set_volume conn=%s rev=%d permission=%s approval=- args=- reason=%s at=%d",
				kind, kind, alice, w.conn, w.rev, id, reason, at(min).UnixMilli())
		}
		for i, wantRow := range []string{
			rec("permission_granted", "prm_a", "-", 1), rec("permission_granted", "prm_b", "-", 2),
			rec("permission_revoked", "prm_a", "by_principal", 3), rec("permission_revoked", "prm_b", "principal_disabled", 4),
			rec("permission_granted", "prm_c", "-", 5),
		} {
			if audit[i] != wantRow {
				t.Errorf("audit row %d:\n %s\nwant:\n %s", i, audit[i], wantRow)
			}
		}
		for _, row := range audit {
			if strings.Contains(row, "dev-1") || strings.Contains(row, "ceiling") {
				t.Errorf("audit row names a device or a ceiling: %s", row)
			}
		}
		w.wantChain(t)

		// A second pass appends nothing more.
		w.drain(t, paEventRow)
		if again := w.audit(t); len(again) != len(want) {
			t.Fatalf("%d audit rows after a second drain, want %d", len(again), len(want))
		}
	})
}

// TestS2C9_CancellationsAreAudited: an approval cancelled by its
// principal, by the end of its connection, by /new, by /forget or by an
// admin disable queues one audit event in the transaction of the
// cancellation, under the reason of that change, and the drain appends it.
// An approval that was already ended queues none.
func TestS2C9_CancellationsAreAudited(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		reason string
		// cancel ends what it can; own reports that it cancels one
		// approval only, the first.
		cancel func(t *testing.T, s *Store, w paEventWorld, first string) error
		own    bool
	}{
		{auditevent.ReasonByPrincipal, func(t *testing.T, s *Store, w paEventWorld, first string) error {
			return inTx(t, s, func(tx *sql.Tx) error {
				_, err := s.CancelPAApproval(ctx, tx, w.principal, first, t0.Add(time.Minute))
				return err
			})
		}, true},
		{auditevent.ReasonConnectionChanged, func(t *testing.T, s *Store, w paEventWorld, _ string) error {
			_, err := s.RevokePAConnectionAt(ctx, w.principal, w.conn, w.rev, 1, "user_disconnect")
			return err
		}, false},
		{auditevent.ReasonConversationClosed, func(t *testing.T, s *Store, w paEventWorld, _ string) error {
			return inTx(t, s, func(tx *sql.Tx) error { return s.ClosePAConversations(ctx, tx, w.principal, t0.Add(time.Minute)) })
		}, false},
		{auditevent.ReasonDataForgotten, func(t *testing.T, s *Store, w paEventWorld, _ string) error {
			return inTx(t, s, func(tx *sql.Tx) error { return s.ForgetPAConversations(ctx, tx, w.principal) })
		}, false},
		{auditevent.ReasonPrincipalDisabled, func(t *testing.T, s *Store, w paEventWorld, _ string) error {
			return s.SetPAPrincipalDisabled(ctx, w.principal, w.principal, "test", t0.Add(time.Minute))
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.reason, func(t *testing.T) {
			paConvoDialects(t, func(t *testing.T, s *Store, alice, _ int64) {
				w := newPAEventWorld(t, s, alice)
				pending := w.pending(t, t0)
				approved := w.approved(t, t0)
				// One that a refusal already ended: not a cancellation.
				refused := w.pending(t, t0)
				must(t, inTx(t, s, func(tx *sql.Tx) error {
					_, err := s.RefusePAApproval(ctx, tx, alice, refused.ID, t0.Add(time.Second))
					return err
				}))
				if got := w.queued(t); len(got) != 0 {
					t.Fatalf("queued before any cancellation: %v", got)
				}
				must(t, tc.cancel(t, s, w, pending.ID))
				want := []string{"approval_cancelled " + pending.ID + " " + tc.reason}
				if !tc.own {
					want = append(want, "approval_cancelled "+approved.ID+" "+tc.reason)
				}
				got := w.queued(t)
				slices.Sort(got)
				slices.Sort(want)
				if !slices.Equal(got, want) {
					t.Fatalf("queued events %v, want %v", got, want)
				}
				if res := w.drain(t, paEventRow); res.Failed != 0 {
					t.Fatalf("drain %+v", res)
				}
				audit := w.audit(t)
				if len(audit) != len(want) || len(w.queued(t)) != 0 {
					t.Fatalf("audit rows %v, queue %v", audit, w.queued(t))
				}
				for _, row := range audit {
					id := pending.ID
					if strings.Contains(row, "approval="+approved.ID+" ") {
						id = approved.ID
					}
					wantRow := fmt.Sprintf("approval_cancelled pa-event/v1 event=approval_cancelled principal=%d server=alice tool=alice_set_volume conn=%s rev=%d permission=- approval=%s args=%s reason=%s at=",
						alice, w.conn, w.rev, id, pending.ArgsSHA, tc.reason)
					if !strings.HasPrefix(row, wantRow) {
						t.Errorf("audit row:\n %s\nwant prefix:\n %s", row, wantRow)
					}
					if strings.Contains(row, "sealed") || strings.Contains(row, "level") {
						t.Errorf("audit row carries arguments: %s", row)
					}
				}
				w.wantChain(t)
			})
		})
	}
}

// TestS2C9_CancellationWithoutItsEventDoesNotCommit: the event is part of
// the change. When it cannot be queued the cancellation, and the
// revocation, fail with it.
func TestS2C9_CancellationWithoutItsEventDoesNotCommit(t *testing.T) {
	paConvoDialects(t, func(t *testing.T, s *Store, alice, _ int64) {
		ctx := context.Background()
		w := newPAEventWorld(t, s, alice)
		a := w.pending(t, t0)
		w.grant(t, "prm_a", t0)
		must(t, inTx(t, s, func(tx *sql.Tx) error {
			_, err := tx.Exec(`DELETE FROM pa_audit_events WHERE principal = $1`, alice)
			return err
		}))
		// The queue is gone for the length of one transaction.
		tx, err := s.DB.BeginTx(ctx, nil)
		must(t, err)
		defer func() { _ = tx.Rollback() }()
		if _, err := tx.Exec(`ALTER TABLE pa_audit_events RENAME TO pa_audit_events_gone`); err != nil {
			t.Fatal(err)
		}
		if _, err := s.CancelPAApproval(ctx, tx, alice, a.ID, t0.Add(time.Minute)); err == nil {
			t.Fatal("the cancellation succeeded without its audit event")
		}
		must(t, tx.Rollback())
		tx, err = s.DB.BeginTx(ctx, nil)
		must(t, err)
		defer func() { _ = tx.Rollback() }()
		if _, err := tx.Exec(`ALTER TABLE pa_audit_events RENAME TO pa_audit_events_gone`); err != nil {
			t.Fatal(err)
		}
		if err := s.RevokePAPermission(ctx, tx, alice, "prm_a", t0.Add(time.Minute)); err == nil {
			t.Fatal("the revocation succeeded without its audit event")
		}
		must(t, tx.Rollback())
		var status string
		must(t, s.DB.QueryRow(`SELECT status FROM pa_approvals WHERE principal = $1 AND id = $2`, alice, a.ID).Scan(&status))
		var revoked int64
		must(t, s.DB.QueryRow(`SELECT revoked_at_ms FROM pa_permissions WHERE principal = $1 AND id = 'prm_a'`, alice).Scan(&revoked))
		if status != string(approval.StatusPending) || revoked != 0 {
			t.Fatalf("approval is %s and the permission revoked at %d, want pending and 0", status, revoked)
		}
	})
}

// TestPAAuditEvents_DrainKeepsWhatItCannotAppend: an event that cannot be
// rendered or appended stays queued, is counted as failed and does not
// keep the events after it from being appended; a later pass appends it.
// An event of a principal without a users row has no chain and is
// dropped. A failed queue read is an error, not an empty pass.
func TestPAAuditEvents_DrainKeepsWhatItCannotAppend(t *testing.T) {
	paConvoDialects(t, func(t *testing.T, s *Store, alice, bob int64) {
		ctx := context.Background()
		w := newPAEventWorld(t, s, alice)
		for i, id := range []string{"prm_a", "prm_b", "prm_c"} {
			w.grant(t, id, t0.Add(time.Duration(i)*time.Minute))
		}
		// Bob has no users row.
		t.Cleanup(func() { _, _ = s.DB.Exec(`DELETE FROM pa_audit_events WHERE principal = $1`, bob) })
		_, err := s.DB.Exec(`INSERT INTO pa_audit_events(principal, kind, subject, server, tool, connection_id, authority_revision, created_at_ms)
			VALUES($1, 'permission_granted', 'prm_bob', 'alice', 'alice_set_volume', 'pac_bob', 1, $2)`, bob, t0.UnixMilli())
		must(t, err)

		failB := func(e auditevent.Event) (ToolCall, error) {
			if e.Subject == "prm_b" {
				return ToolCall{}, errors.New("injected render failure")
			}
			return paEventRow(e)
		}
		res := w.drain(t, failB)
		if res.Failed != 1 || res.Dropped < 1 {
			t.Fatalf("drain %+v, want one failed and Bob's dropped", res)
		}
		if got := w.queued(t); !slices.Equal(got, []string{"permission_granted prm_b"}) {
			t.Fatalf("queued after the failing pass: %v", got)
		}
		if audit := w.audit(t); len(audit) != 2 || !strings.Contains(audit[0], "permission=prm_a ") || !strings.Contains(audit[1], "permission=prm_c ") {
			t.Fatalf("audit rows after the failing pass: %v", audit)
		}
		var tries, bobRows int
		must(t, s.DB.QueryRow(`SELECT tries FROM pa_audit_events WHERE principal = $1`, alice).Scan(&tries))
		must(t, s.DB.QueryRow(`SELECT COUNT(*) FROM pa_audit_events WHERE principal = $1`, bob).Scan(&bobRows))
		if tries != 1 || bobRows != 0 {
			t.Fatalf("tries %d, Bob's queued rows %d; want 1 and 0", tries, bobRows)
		}

		// A row that does not render at all (an unknown kind) is kept too.
		_, err = s.DB.Exec(`INSERT INTO pa_audit_events(principal, kind, subject, server, tool, connection_id, authority_revision, created_at_ms)
			VALUES($1, 'something_else', 'prm_x', 'alice', 'alice_set_volume', $2, 1, $3)`, alice, w.conn, t0.UnixMilli())
		must(t, err)
		res = w.drain(t, paEventRow)
		if res.Failed != 1 {
			t.Fatalf("second drain %+v, want the unknown kind failed", res)
		}
		if got := w.queued(t); !slices.Equal(got, []string{"something_else prm_x"}) {
			t.Fatalf("queued after the second pass: %v", got)
		}
		if audit := w.audit(t); len(audit) != 3 || !strings.Contains(audit[2], "permission=prm_b ") {
			t.Fatalf("audit rows after the second pass: %v", audit)
		}
		w.wantChain(t)

		if _, err := s.DrainPAAuditEvents(ctx, 0, paEventRow); err == nil {
			t.Fatal("a drain without a limit ran")
		}
		if _, err := s.DrainPAAuditEvents(ctx, 10, nil); err == nil {
			t.Fatal("a drain without a renderer ran")
		}
	})
}

// TestPAAuditEvents_UnreadableQueueIsAnError: a queue that cannot be read
// is an error from the drain, never an empty pass.
func TestPAAuditEvents_UnreadableQueueIsAnError(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if n, err := s.CountPAAuditEvents(ctx); err != nil || n != 0 {
		t.Fatalf("an empty queue counts %d, %v", n, err)
	}
	for range 2 {
		if _, err := s.DB.Exec(`INSERT INTO pa_audit_events(principal, kind, subject, server, tool, connection_id, authority_revision, created_at_ms)
			VALUES (4242001, 'permission_revoked', 'prm_1', 'alice', 'alice_set_volume', 'pac_1', 1, 1000)`); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := s.CountPAAuditEvents(ctx); err != nil || n != 2 {
		t.Fatalf("two queued events count %d, %v", n, err)
	}
	if _, err := s.DB.Exec(`ALTER TABLE pa_audit_events RENAME TO pa_audit_events_gone`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DrainPAAuditEvents(ctx, 10, paEventRow); err == nil {
		t.Fatal("the drain of an unreadable queue reported a clean pass")
	}
	if n, err := s.CountPAAuditEvents(ctx); err == nil {
		t.Fatalf("an unreadable queue counts %d", n)
	}
}
