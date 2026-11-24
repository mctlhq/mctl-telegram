package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/pa/approval"
	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
	"github.com/mctlhq/mctl-telegram/internal/pa/convo"
	"github.com/mctlhq/mctl-telegram/internal/pa/permissions"
)

// Store tests of S2-C9 (#1320 slice P2-S12): whatever ends a connection,
// and a consent withdrawal, /forget or an admin disable of the principal,
// cancels the approvals that were not dispatched, revokes the standing
// permissions and queues one notice, in the transaction of that change.
// They run on SQLite always and on Postgres when TEST_DATABASE_URL is set.
// The personas are the synthetic Alice and Bob of paConvoDialects.

// paCancelWorld is one principal with two active connections. Each has a
// pending approval, an approved one and a standing permission; the first
// also has an approval whose call is on the wire.
type paCancelWorld struct {
	s          *Store
	principal  int64
	a, b       paApprovalWorld
	pend, appr approval.Approval // on connection a
	disp       approval.Approval // on connection a, consumed
	pendB      approval.Approval // on connection b
	apprB      approval.Approval // on connection b
}

func paCancelDialects(t *testing.T, body func(t *testing.T, s *Store, alice, bob int64)) {
	paApprovalDialects(t, func(t *testing.T, s *Store, alice, bob int64) {
		clean := func() {
			for _, tb := range []string{"pa_permissions", "pa_outbox", "pa_callbacks", "pa_principal_disables", "pa_consents"} {
				_, _ = s.DB.Exec(`DELETE FROM `+tb+` WHERE principal IN ($1, $2)`, alice, bob)
			}
		}
		clean()
		t.Cleanup(clean)
		body(t, s, alice, bob)
	})
}

func seedPACancelWorld(t *testing.T, s *Store, principal int64) paCancelWorld {
	t.Helper()
	ctx := context.Background()
	w := paCancelWorld{s: s, principal: principal, a: seedPAApprovalWorld(t, s, principal)}
	w.b = w.a
	w.b.conn = "pac_apr_b_" + randomSuffix(t)
	paPermWorld{s: s, principal: principal, conn: w.b.conn, rev: w.b.rev}.seedConn(t, w.b.conn, connection.ServerAlice, connection.StateActive)
	must(t, inTx(t, s, func(tx *sql.Tx) error {
		return s.AcceptPAConsent(ctx, tx, principal, convo.ConsentVersion, convo.ConsentTextSHA256(), t0)
	}))
	w.pend, w.appr, w.disp = w.a.pending(t, t0), w.a.approved(t, t0), w.a.approved(t, t0)
	_, _, err := paConsume(t, s, principal, w.disp.ID, t0.Add(time.Minute))
	must(t, err)
	w.pendB, w.apprB = w.b.pending(t, t0), w.b.approved(t, t0)
	for id, conn := range map[string]string{"prm_a": w.a.conn, "prm_b": w.b.conn} {
		p := permissions.Permission{
			Principal: principal, ID: id, ConnectionID: conn, AuthorityRevision: w.a.rev,
			Server: string(connection.ServerAlice), Tool: paPermTool, DeviceIDs: []string{"dev-1"},
			Ceiling: 5, ExpiresAt: t0.Add(24 * time.Hour),
		}
		must(t, inTx(t, s, func(tx *sql.Tx) error { return s.InsertPAPermission(ctx, tx, p, t0) }))
	}
	return w
}

// statuses is the status of each of the world's approvals, "gone" for a
// deleted row, with "+args" while the sealed arguments are still there.
func (w paCancelWorld) statuses(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	for name, id := range map[string]string{
		"pend": w.pend.ID, "appr": w.appr.ID, "disp": w.disp.ID, "pendB": w.pendB.ID, "apprB": w.apprB.ID,
	} {
		var st string
		var sealed []byte
		err := w.s.DB.QueryRowContext(context.Background(),
			`SELECT status, sealed_args FROM pa_approvals WHERE principal = $1 AND id = $2`, w.principal, id).Scan(&st, &sealed)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			st = "gone"
		case err != nil:
			t.Fatalf("read approval %s: %v", name, err)
		case sealed != nil:
			st += "+args"
		}
		out[name] = st
	}
	return out
}

// untouched is statuses of a world nothing was cancelled in.
var paCancelUntouched = map[string]string{
	"pend": "pending+args", "appr": "approved+args", "disp": "dispatching", "pendB": "pending+args", "apprB": "approved+args",
}

func (w paCancelWorld) wantStatuses(t *testing.T, want map[string]string) {
	t.Helper()
	got := w.statuses(t)
	for name, st := range want {
		if got[name] != st {
			t.Errorf("approval %s: %s, want %s", name, got[name], st)
		}
	}
}

func (w paCancelWorld) revoked(t *testing.T, id string) bool {
	t.Helper()
	var at int64
	must(t, w.s.DB.QueryRowContext(context.Background(),
		`SELECT revoked_at_ms FROM pa_permissions WHERE principal = $1 AND id = $2`, w.principal, id).Scan(&at))
	return at != 0
}

func (w paCancelWorld) wantRevoked(t *testing.T, a, b bool) {
	t.Helper()
	if got := w.revoked(t, "prm_a"); got != a {
		t.Errorf("permission on connection a revoked = %v, want %v", got, a)
	}
	if got := w.revoked(t, "prm_b"); got != b {
		t.Errorf("permission on connection b revoked = %v, want %v", got, b)
	}
}

// notices is the principal's approval-level outbox rows as "kind:approval".
func paCancelNotices(t *testing.T, s *Store, principal int64) []string {
	t.Helper()
	rows, err := s.DB.QueryContext(context.Background(),
		`SELECT kind, approval_id FROM pa_outbox WHERE principal = $1 AND approval_id <> '' ORDER BY id`, principal)
	must(t, err)
	defer func() { _ = rows.Close() }()
	out := []string{}
	for rows.Next() {
		var kind, id string
		must(t, rows.Scan(&kind, &id))
		out = append(out, kind+":"+id)
	}
	must(t, rows.Err())
	return out
}

// wantUntouchedWorld: nothing of the world was cancelled, revoked or
// reported.
func (w paCancelWorld) wantUntouchedWorld(t *testing.T) {
	t.Helper()
	w.wantStatuses(t, paCancelUntouched)
	w.wantRevoked(t, false, false)
	// Two callbacks per pending card; an approved card has spent its own.
	if n := paRowsIn(t, w.s, "pa_callbacks", w.principal); n != 4 {
		t.Errorf("%d callbacks, want 4", n)
	}
	if n := paCancelNotices(t, w.s, w.principal); len(n) != 0 {
		t.Errorf("notices %v, want none", n)
	}
}

// paConnectionEnds are the store calls that end connection a of a world:
// every one of them moves its authority revision.
var paConnectionEnds = map[string]func(ctx context.Context, w paCancelWorld) error{
	"disconnect": func(ctx context.Context, w paCancelWorld) error {
		_, _, _, err := w.s.RevokePAConnection(ctx, w.principal, w.a.conn, "user_disconnect")
		return err
	},
	"revoke on refresh token reuse": func(ctx context.Context, w paCancelWorld) error {
		_, err := w.s.RevokePAConnectionAt(ctx, w.principal, w.a.conn, w.a.rev, 1, "refresh_token_reuse")
		return err
	},
	"expired by a failed refresh": func(ctx context.Context, w paCancelWorld) error {
		_, err := w.s.TransitionPAConnection(ctx, w.principal, w.a.conn, connection.Transition{
			From: connection.StateActive, To: connection.StateExpired, ExpectRevision: w.a.rev, Reason: "invalid_grant"})
		return err
	},
}

// paPrincipalEnds are the store calls that end everything of a principal.
// rows says whether the cancelled approval rows stay as tombstones:
// /forget and a consent withdrawal delete them with the conversations.
var paPrincipalEnds = map[string]struct {
	rows bool
	end  func(ctx context.Context, w paCancelWorld, bob int64) error
}{
	"consent withdraw": {false, func(ctx context.Context, w paCancelWorld, _ int64) error {
		return paCommit(ctx, w.s, func(tx *sql.Tx) error { return w.s.WithdrawPAConsent(ctx, tx, w.principal, t0.Add(2*time.Minute)) })
	}},
	"forget": {false, func(ctx context.Context, w paCancelWorld, _ int64) error {
		return paCommit(ctx, w.s, func(tx *sql.Tx) error { return w.s.ForgetPAConversations(ctx, tx, w.principal) })
	}},
	"admin disable": {true, func(ctx context.Context, w paCancelWorld, bob int64) error {
		return w.s.SetPAPrincipalDisabled(ctx, w.principal, bob, "test", t0.Add(2*time.Minute))
	}},
}

func paCommit(ctx context.Context, s *Store, fn func(tx *sql.Tx) error) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// TestS2C9_ConnectionEndCancelsItsApprovalsAndPermissions: whatever ends a
// connection cancels its pending and its approved approvals, erases their
// arguments, deletes their callbacks, revokes its permission and queues one
// notice, and touches nothing of the principal's other connection, of the
// call on the wire or of another principal.
func TestS2C9_ConnectionEndCancelsItsApprovalsAndPermissions(t *testing.T) {
	ctx := context.Background()
	for name, end := range paConnectionEnds {
		t.Run(name, func(t *testing.T) {
			paCancelDialects(t, func(t *testing.T, s *Store, alice, bob int64) {
				w, wb := seedPACancelWorld(t, s, alice), seedPACancelWorld(t, s, bob)
				must(t, end(ctx, w))

				w.wantStatuses(t, map[string]string{
					"pend": "cancelled", "appr": "cancelled", "disp": "dispatching", "pendB": "pending+args", "apprB": "approved+args",
				})
				w.wantRevoked(t, true, false)
				// The pending card of connection b keeps its two buttons.
				if n := paRowsIn(t, s, "pa_callbacks", alice); n != 2 {
					t.Errorf("alice has %d callbacks, want the 2 of the other connection", n)
				}
				want := []string{"actions_cancelled:" + min(w.pend.ID, w.appr.ID)}
				if got := paCancelNotices(t, s, alice); !slices.Equal(got, want) {
					t.Errorf("alice's notices %v, want %v", got, want)
				}
				// The receipt is spent: the consume answers cancelled, not
				// merely "the revision moved".
				for _, id := range []string{w.pend.ID, w.appr.ID} {
					if _, _, err := paConsume(t, s, alice, id, t0.Add(3*time.Minute)); !errors.Is(err, approval.ErrCancelled) {
						t.Errorf("consume of %s: err = %v, want ErrCancelled", id, err)
					}
				}
				if got := paDispatchStatuses(t, s, alice); !slices.Equal(got, []string{"dispatching"}) {
					t.Errorf("dispatch records %v, want the one on the wire", got)
				}
				wb.wantUntouchedWorld(t)
				noArgsOutsideOpen(t, s, alice, bob)
			})
		})
	}
}

// TestS2C9_PrincipalEndCancelsOnEveryConnection: a consent withdrawal,
// /forget and an admin disable cancel the approvals and revoke the
// permissions of every connection of the principal, with one notice for
// all of it, and touch nothing of another principal.
func TestS2C9_PrincipalEndCancelsOnEveryConnection(t *testing.T) {
	ctx := context.Background()
	for name, c := range paPrincipalEnds {
		t.Run(name, func(t *testing.T) {
			paCancelDialects(t, func(t *testing.T, s *Store, alice, bob int64) {
				w, wb := seedPACancelWorld(t, s, alice), seedPACancelWorld(t, s, bob)
				must(t, c.end(ctx, w, bob))

				ended := "gone"
				if c.rows {
					ended = "cancelled"
				}
				w.wantStatuses(t, map[string]string{
					"pend": ended, "appr": ended, "disp": "dispatching", "pendB": ended, "apprB": ended,
				})
				w.wantRevoked(t, true, true)
				if n := paRowsIn(t, s, "pa_callbacks", alice); n != 0 {
					t.Errorf("alice has %d callbacks, want 0", n)
				}
				want := []string{"actions_cancelled:" + min(w.pend.ID, w.appr.ID, w.pendB.ID, w.apprB.ID)}
				if got := paCancelNotices(t, s, alice); !slices.Equal(got, want) {
					t.Errorf("alice's notices %v, want %v", got, want)
				}
				if got := paDispatchStatuses(t, s, alice); !slices.Equal(got, []string{"dispatching"}) {
					t.Errorf("dispatch records %v, want the one on the wire", got)
				}
				wb.wantUntouchedWorld(t)
				noArgsOutsideOpen(t, s, alice, bob)

				// A second run finds nothing to cancel and says nothing more.
				must(t, c.end(ctx, w, bob))
				if got := paCancelNotices(t, s, alice); !slices.Equal(got, want) {
					t.Errorf("after a second run alice's notices are %v, want %v", got, want)
				}
			})
		})
	}
}

// TestS2C9_NothingCancelledQueuesNoNotice: the notice is for a cancelled
// approval. A connection or a principal that had none waiting, only a call
// on the wire and a permission, is ended without one.
func TestS2C9_NothingCancelledQueuesNoNotice(t *testing.T) {
	ctx := context.Background()
	ends := map[string]func(ctx context.Context, w paCancelWorld, bob int64) error{}
	for name, end := range paConnectionEnds {
		ends[name] = func(ctx context.Context, w paCancelWorld, _ int64) error { return end(ctx, w) }
	}
	for name, c := range paPrincipalEnds {
		ends[name] = c.end
	}
	for name, end := range ends {
		t.Run(name, func(t *testing.T) {
			paCancelDialects(t, func(t *testing.T, s *Store, alice, bob int64) {
				w := seedPACancelWorld(t, s, alice)
				// Everything that waits is ended by hand first, as a tap on
				// Cancel ends it: only the call on the wire is left.
				for _, id := range []string{w.pend.ID, w.appr.ID, w.pendB.ID, w.apprB.ID} {
					must(t, inTx(t, s, func(tx *sql.Tx) error {
						_, err := s.CancelPAApproval(ctx, tx, alice, id, t0.Add(time.Minute))
						return err
					}))
				}
				must(t, end(ctx, w, bob))
				if got := paCancelNotices(t, s, alice); len(got) != 0 {
					t.Errorf("notices %v for a change that cancelled nothing", got)
				}
				if !w.revoked(t, "prm_a") {
					t.Error("the permission on the ended connection is still in force")
				}
				if st := w.statuses(t)["disp"]; st != "dispatching" {
					t.Errorf("the call on the wire is %s", st)
				}
			})
		})
	}
}

// paFailStatement makes one kind of statement fail for principal, on
// either dialect, until the test ends.
func paFailStatement(t *testing.T, s *Store, principal int64, table, event string) {
	t.Helper()
	ctx := context.Background()
	name := "pa_s2c9_fail_" + randomSuffix(t)
	row := "NEW"
	if event == "DELETE" {
		row = "OLD"
	}
	if s.isPostgres(ctx) {
		for _, q := range []string{
			`CREATE FUNCTION ` + name + `() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'injected failure'; END $$ LANGUAGE plpgsql`,
			fmt.Sprintf(`CREATE TRIGGER %s BEFORE %s ON %s FOR EACH ROW WHEN (%s.principal = %d) EXECUTE FUNCTION %s()`,
				name, event, table, row, principal, name),
		} {
			if _, err := s.DB.ExecContext(ctx, q); err != nil {
				t.Fatalf("install failing trigger: %v", err)
			}
		}
		t.Cleanup(func() {
			_, _ = s.DB.Exec(`DROP TRIGGER IF EXISTS ` + name + ` ON ` + table)
			_, _ = s.DB.Exec(`DROP FUNCTION IF EXISTS ` + name + `()`)
		})
		return
	}
	if _, err := s.DB.ExecContext(ctx, fmt.Sprintf(
		`CREATE TRIGGER %s BEFORE %s ON %s WHEN %s.principal = %d BEGIN SELECT RAISE(ABORT, 'injected failure'); END`,
		name, event, table, row, principal)); err != nil {
		t.Fatalf("install failing trigger: %v", err)
	}
	t.Cleanup(func() { _, _ = s.DB.Exec(`DROP TRIGGER IF EXISTS ` + name) })
}

// TestS2C9_CancelFailureFailsTheChange: the direction of a failure. Each
// statement of the cancellation (the callbacks, the approvals, the notice,
// the permissions) is made to fail in turn; the change that carried it
// then fails as a whole. The connection stays active at its revision, the
// consent stays given, the principal stays enabled, and no approval,
// callback or permission is changed: nothing is left half revoked, and the
// caller sees an error and can retry. The other direction, a revocation
// that commits while its approvals stay approved, is the one that must not
// exist.
func TestS2C9_CancelFailureFailsTheChange(t *testing.T) {
	ctx := context.Background()
	statements := map[string][2]string{
		"deleting the callbacks":   {"pa_callbacks", "DELETE"},
		"cancelling the approvals": {"pa_approvals", "UPDATE"},
		"queueing the notice":      {"pa_outbox", "INSERT"},
		"revoking the permissions": {"pa_permissions", "UPDATE"},
	}
	ends := map[string]func(ctx context.Context, w paCancelWorld, bob int64) error{}
	for name, end := range paConnectionEnds {
		ends[name] = func(ctx context.Context, w paCancelWorld, _ int64) error { return end(ctx, w) }
	}
	for name, c := range paPrincipalEnds {
		ends[name] = c.end
	}
	for stmt, target := range statements {
		for name, end := range ends {
			t.Run(stmt+"/"+name, func(t *testing.T) {
				paCancelDialects(t, func(t *testing.T, s *Store, alice, bob int64) {
					w := seedPACancelWorld(t, s, alice)
					paFailStatement(t, s, alice, target[0], target[1])

					if err := end(ctx, w, bob); err == nil {
						t.Fatal("the change committed although a statement of the cancellation failed")
					}
					w.wantUntouchedWorld(t)
					var state string
					var rev int64
					must(t, s.DB.QueryRowContext(ctx,
						`SELECT state, authority_revision FROM pa_connections WHERE principal = $1 AND id = $2`,
						alice, w.a.conn).Scan(&state, &rev))
					if state != string(connection.StateActive) || rev != w.a.rev {
						t.Errorf("connection is %s at revision %d, want active at %d", state, rev, w.a.rev)
					}
					disabled, err := s.PAPrincipalDisabledState(ctx, alice)
					if err != nil || disabled {
						t.Errorf("principal disabled = %v, %v; want enabled", disabled, err)
					}
					must(t, inTx(t, s, func(tx *sql.Tx) error {
						rec, err := s.GetPAConsent(ctx, tx, alice)
						if err == nil && rec.State != convo.ConsentAccepted {
							t.Errorf("consent is %s, want accepted", rec.State)
						}
						return err
					}))
				})
			})
		}
	}
}
