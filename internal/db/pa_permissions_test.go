package db

// pa_permissions_test.go: the standing permission store (#1320 slice
// P2-S10; threat model rows S2-A8 and S2-A9), on SQLite and Postgres.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
	"github.com/mctlhq/mctl-telegram/internal/pa/permissions"
)

const paPermTool = "alice_set_volume"

// paPermWorld is a principal with one active alice connection at rev.
type paPermWorld struct {
	s         *Store
	principal int64
	conn      string
	rev       int64
}

func newPAPermWorld(t *testing.T, s *Store, principal int64) paPermWorld {
	t.Helper()
	w := paPermWorld{s: s, principal: principal, conn: "pac_prm_" + randomSuffix(t), rev: 5}
	t.Cleanup(func() {
		for _, tb := range []string{"pa_permissions", "pa_connections", "pa_callbacks"} {
			_, _ = s.DB.Exec(`DELETE FROM `+tb+` WHERE principal = $1`, principal)
		}
	})
	w.seedConn(t, w.conn, connection.ServerAlice, connection.StateActive)
	return w
}

func (w paPermWorld) seedConn(t *testing.T, id string, server connection.Server, state connection.State) {
	t.Helper()
	if _, err := w.s.DB.ExecContext(context.Background(),
		`INSERT INTO pa_connections(id, principal, server, state, authority_revision, token_generation, kek_id,
			wrapped_dek, sealed_tokens, granted_scope, created_at_ms, updated_at_ms)
		 VALUES($1, $2, $3, $4, $5, 1, 'test', $6, $7, 'home', $8, $8)`,
		id, w.principal, string(server), string(state), w.rev,
		[]byte("wrapped"), []byte("tokens"), t0.UnixMilli()); err != nil {
		t.Fatalf("seed connection: %v", err)
	}
}

// perm is a grant on the world's connection at its seeded revision.
func (w paPermWorld) perm(id string) permissions.Permission {
	return permissions.Permission{
		Principal: w.principal, ID: id, ConnectionID: w.conn, AuthorityRevision: w.rev,
		Server: string(connection.ServerAlice), Tool: paPermTool, DeviceIDs: []string{"dev-1", "dev-2"},
		Ceiling: 5, ExpiresAt: t0.Add(24 * time.Hour),
	}
}

func (w paPermWorld) insert(t *testing.T, p permissions.Permission, now time.Time) error {
	t.Helper()
	return inTx(t, w.s, func(tx *sql.Tx) error { return w.s.InsertPAPermission(context.Background(), tx, p, now) })
}

func (w paPermWorld) lookup(t *testing.T, rev int64, now time.Time) []permissions.Permission {
	t.Helper()
	got, err := w.s.LookupPAPermissions(context.Background(), w.principal, w.conn, rev,
		string(connection.ServerAlice), paPermTool, now)
	must(t, err)
	return got
}

func (w paPermWorld) list(t *testing.T, now time.Time) []permissions.Permission {
	t.Helper()
	got, err := w.s.ListActivePAPermissions(context.Background(), w.principal, now)
	must(t, err)
	return got
}

func (w paPermWorld) revokedAt(t *testing.T, id string) int64 {
	t.Helper()
	var ms int64
	must(t, w.s.DB.QueryRow(`SELECT revoked_at_ms FROM pa_permissions WHERE principal = $1 AND id = $2`,
		w.principal, id).Scan(&ms))
	return ms
}

func TestPAPermission_InsertAndRead(t *testing.T) {
	paConvoDialects(t, func(t *testing.T, s *Store, alice, bob int64) {
		w := newPAPermWorld(t, s, alice)
		must(t, w.insert(t, w.perm("prm_a"), t0))
		got := w.lookup(t, w.rev, t0.Add(time.Minute))
		if len(got) != 1 {
			t.Fatalf("lookup: %+v", got)
		}
		p := got[0]
		if p.Principal != alice || p.ID != "prm_a" || p.ConnectionID != w.conn || p.AuthorityRevision != w.rev ||
			p.Server != "alice" || p.Tool != paPermTool || fmt.Sprint(p.DeviceIDs) != "[dev-1 dev-2]" || p.Ceiling != 5 ||
			!p.CreatedAt.Equal(t0) || !p.ExpiresAt.Equal(t0.Add(24*time.Hour)) || !p.RevokedAt.IsZero() {
			t.Fatalf("read back %+v", p)
		}
		if l := w.list(t, t0); len(l) != 1 || l[0].ID != "prm_a" {
			t.Fatalf("list: %+v", l)
		}
		// Another principal reads nothing of it and cannot revoke it.
		if l, err := s.ListActivePAPermissions(context.Background(), bob, t0); err != nil || len(l) != 0 {
			t.Fatalf("bob lists %+v, %v", l, err)
		}
		if l, err := s.LookupPAPermissions(context.Background(), bob, w.conn, w.rev, "alice", paPermTool, t0); err != nil || len(l) != 0 {
			t.Fatalf("bob looks up %+v, %v", l, err)
		}
		err := inTx(t, s, func(tx *sql.Tx) error { return s.RevokePAPermission(context.Background(), tx, bob, "prm_a", t0) })
		if !errors.Is(err, permissions.ErrNotFound) {
			t.Fatalf("bob revokes: %v", err)
		}
		if w.revokedAt(t, "prm_a") != 0 {
			t.Fatal("bob revoked alice's permission")
		}
		// The principal revokes it; a second revoke finds nothing.
		must(t, inTx(t, s, func(tx *sql.Tx) error {
			return s.RevokePAPermission(context.Background(), tx, alice, "prm_a", t0.Add(time.Hour))
		}))
		if len(w.lookup(t, w.rev, t0.Add(2*time.Hour))) != 0 || len(w.list(t, t0.Add(2*time.Hour))) != 0 {
			t.Fatal("a revoked permission is still returned")
		}
		err = inTx(t, s, func(tx *sql.Tx) error {
			return s.RevokePAPermission(context.Background(), tx, alice, "prm_a", t0.Add(3*time.Hour))
		})
		if !errors.Is(err, permissions.ErrNotFound) {
			t.Fatalf("second revoke: %v", err)
		}
	})
}

// TestPAPermission_InsertRefusals: what the insert itself refuses,
// whatever its caller checked, and that a refusal leaves no row.
func TestPAPermission_InsertRefusals(t *testing.T) {
	paConvoDialects(t, func(t *testing.T, s *Store, alice, bob int64) {
		w := newPAPermWorld(t, s, alice)
		w.seedConn(t, w.conn+"_exp", connection.ServerAlice, connection.StateExpired)
		wb := newPAPermWorld(t, s, bob)
		cases := []struct {
			name   string
			mutate func(*permissions.Permission)
			reason permissions.Reason
		}{
			{"never lowerable: control room", func(p *permissions.Permission) { p.Tool = "alice_control_room" }, permissions.ReasonNeverLowerable},
			{"never lowerable: scenario", func(p *permissions.Permission) { p.Tool = "alice_trigger_scenario" }, permissions.ReasonNeverLowerable},
			{"never lowerable: say phrase", func(p *permissions.Permission) { p.Tool = "alice_say_phrase" }, permissions.ReasonNeverLowerable},
			{"never lowerable: send command", func(p *permissions.Permission) { p.Tool = "alice_send_command" }, permissions.ReasonNeverLowerable},
			{"an older revision", func(p *permissions.Permission) { p.AuthorityRevision-- }, permissions.ReasonConnectionChange},
			{"a newer revision", func(p *permissions.Permission) { p.AuthorityRevision++ }, permissions.ReasonConnectionChange},
			{"a connection that is not active", func(p *permissions.Permission) { p.ConnectionID = w.conn + "_exp" }, permissions.ReasonConnectionChange},
			{"another principal's connection", func(p *permissions.Permission) { p.ConnectionID = wb.conn }, permissions.ReasonConnectionChange},
			{"an unknown connection", func(p *permissions.Permission) { p.ConnectionID = "pac_none" }, permissions.ReasonConnectionChange},
			{"another server", func(p *permissions.Permission) { p.Server = "tg" }, permissions.ReasonConnectionChange},
			{"no devices", func(p *permissions.Permission) { p.DeviceIDs = nil }, permissions.ReasonShape},
			{"unsorted devices", func(p *permissions.Permission) { p.DeviceIDs = []string{"dev-2", "dev-1"} }, permissions.ReasonShape},
			{"a device id outside the alphabet", func(p *permissions.Permission) { p.DeviceIDs = []string{"dev 1"} }, permissions.ReasonShape},
			{"a ceiling below none", func(p *permissions.Permission) { p.Ceiling = -2 }, permissions.ReasonShape},
			{"already expired", func(p *permissions.Permission) { p.ExpiresAt = t0 }, permissions.ReasonExpiry},
		}
		for _, tc := range cases {
			p := w.perm("prm_r")
			tc.mutate(&p)
			err := w.insert(t, p, t0)
			if !errors.Is(err, permissions.ErrRefused) || permissions.ReasonOf(err) != tc.reason {
				t.Errorf("%s: %v, want refusal %q", tc.name, err, tc.reason)
			}
		}
		for _, p := range []permissions.Permission{
			func() permissions.Permission { p := w.perm("prm_r"); p.Principal = 0; return p }(),
			w.perm("not an id"),
		} {
			if err := w.insert(t, p, t0); !errors.Is(err, permissions.ErrInvalid) {
				t.Errorf("invalid %+v: %v", p, err)
			}
		}
		if n := paRowsIn(t, s, "pa_permissions", alice) + paRowsIn(t, s, "pa_permissions", bob); n != 0 {
			t.Fatalf("%d rows after refusals", n)
		}
		// The cap on active permissions.
		for i := range permissions.MaxActive {
			must(t, w.insert(t, w.perm(fmt.Sprintf("prm_%d", i)), t0))
		}
		if err := w.insert(t, w.perm("prm_over"), t0); permissions.ReasonOf(err) != permissions.ReasonTooMany {
			t.Fatalf("over the cap: %v", err)
		}
		// An expired one frees its place.
		if err := w.insert(t, w.perm("prm_later"), t0.Add(25*time.Hour)); permissions.ReasonOf(err) != permissions.ReasonExpiry {
			t.Fatalf("expiry in the past: %v", err)
		}
		late := w.perm("prm_later")
		late.ExpiresAt = t0.Add(48 * time.Hour)
		must(t, w.insert(t, late, t0.Add(25*time.Hour)))
	})
}

// TestS2A9_RevisionChangeRevokesPermission: any change of the connection's
// authority revision revokes the permissions bound to it in the same
// transaction, and a lookup needs the revision to be equal on its own: a
// revision that moved without the revocation still returns nothing.
func TestS2A9_RevisionChangeRevokesPermission(t *testing.T) {
	paConvoDialects(t, func(t *testing.T, s *Store, alice, bob int64) {
		ctx := context.Background()
		bumps := map[string]func(t *testing.T, w paPermWorld){
			"transition": func(t *testing.T, w paPermWorld) {
				_, err := s.TransitionPAConnection(ctx, w.principal, w.conn, connection.Transition{
					From: connection.StateActive, To: connection.StateExpired, ExpectRevision: w.rev, Reason: "invalid_grant"})
				must(t, err)
			},
			"disconnect": func(t *testing.T, w paPermWorld) {
				_, _, _, err := s.RevokePAConnection(ctx, w.principal, w.conn, "user_disconnect")
				must(t, err)
			},
			"revoke at": func(t *testing.T, w paPermWorld) {
				_, err := s.RevokePAConnectionAt(ctx, w.principal, w.conn, w.rev, 1, "reuse_detected")
				must(t, err)
			},
		}
		for name, bump := range bumps {
			t.Run(name, func(t *testing.T) {
				w := newPAPermWorld(t, s, alice)
				other := newPAPermWorld(t, s, bob)
				must(t, w.insert(t, w.perm("prm_a"), t0))
				must(t, other.insert(t, other.perm("prm_b"), t0))
				if len(w.lookup(t, w.rev, t0)) != 1 {
					t.Fatal("the permission is not in force before the change")
				}
				bump(t, w)
				var rev int64
				must(t, s.DB.QueryRow(`SELECT authority_revision FROM pa_connections WHERE id = $1`, w.conn).Scan(&rev))
				if rev != w.rev+1 {
					t.Fatalf("revision %d, want %d", rev, w.rev+1)
				}
				if w.revokedAt(t, "prm_a") == 0 {
					t.Error("the revision changed and the permission was not revoked")
				}
				for _, r := range []int64{w.rev, rev} {
					if got := w.lookup(t, r, t0); len(got) != 0 {
						t.Errorf("lookup at revision %d returns %+v", r, got)
					}
				}
				if got := w.list(t, t0); len(got) != 0 {
					t.Errorf("list returns %+v", got)
				}
				// Another principal's permission is untouched.
				if other.revokedAt(t, "prm_b") != 0 || len(other.lookup(t, other.rev, t0)) != 1 {
					t.Error("another principal's permission was revoked")
				}
			})
		}
		t.Run("a revision that moved without the revocation", func(t *testing.T) {
			w := newPAPermWorld(t, s, alice)
			must(t, w.insert(t, w.perm("prm_a"), t0))
			if _, err := s.DB.Exec(`UPDATE pa_connections SET authority_revision = authority_revision + 1 WHERE id = $1`, w.conn); err != nil {
				t.Fatal(err)
			}
			if w.revokedAt(t, "prm_a") != 0 {
				t.Fatal("the fixture revoked the permission")
			}
			if got := w.lookup(t, w.rev+1, t0); len(got) != 0 {
				t.Errorf("lookup at the new revision returns a permission granted at the old one: %+v", got)
			}
			if got := w.list(t, t0); len(got) != 0 {
				t.Errorf("list returns a permission granted at an old revision: %+v", got)
			}
			// At the revision it was granted at it would still be found:
			// the caller passes the revision it just read from the
			// connection, which is the new one.
			if got := w.lookup(t, w.rev, t0); len(got) != 1 {
				t.Errorf("fixture: lookup at the granted revision returns %+v", got)
			}
		})
	})
}

// TestS2A9_ExpiredPermissionIsNotReturned: a permission stops at its
// expiry without anything revoking it.
func TestS2A9_ExpiredPermissionIsNotReturned(t *testing.T) {
	paConvoDialects(t, func(t *testing.T, s *Store, alice, _ int64) {
		w := newPAPermWorld(t, s, alice)
		must(t, w.insert(t, w.perm("prm_a"), t0))
		expiry := t0.Add(24 * time.Hour)
		if len(w.lookup(t, w.rev, expiry.Add(-time.Millisecond))) != 1 || len(w.list(t, expiry.Add(-time.Millisecond))) != 1 {
			t.Fatal("the permission is not in force just before its expiry")
		}
		for _, now := range []time.Time{expiry, expiry.Add(time.Millisecond), expiry.Add(48 * time.Hour)} {
			if got := w.lookup(t, w.rev, now); len(got) != 0 {
				t.Errorf("lookup at %s returns %+v", now, got)
			}
			if got := w.list(t, now); len(got) != 0 {
				t.Errorf("list at %s returns %+v", now, got)
			}
		}
		if w.revokedAt(t, "prm_a") != 0 {
			t.Fatal("the fixture revoked the permission")
		}
	})
}

// TestS2A9_GrantLongerThan30DaysRefused: 30 days is the longest a
// permission lives; a 31-day grant creates no row.
func TestS2A9_GrantLongerThan30DaysRefused(t *testing.T) {
	paConvoDialects(t, func(t *testing.T, s *Store, alice, _ int64) {
		w := newPAPermWorld(t, s, alice)
		for _, d := range []time.Duration{31 * 24 * time.Hour, permissions.MaxTTL + time.Millisecond, 365 * 24 * time.Hour} {
			p := w.perm("prm_long")
			p.ExpiresAt = t0.Add(d)
			if err := w.insert(t, p, t0); permissions.ReasonOf(err) != permissions.ReasonExpiry {
				t.Errorf("a grant for %s: %v, want an expiry refusal", d, err)
			}
		}
		if n := paRowsIn(t, s, "pa_permissions", alice); n != 0 {
			t.Fatalf("%d rows after refused grants", n)
		}
		p := w.perm("prm_max")
		p.ExpiresAt = t0.Add(permissions.MaxTTL)
		must(t, w.insert(t, p, t0))
	})
}

// TestPAPermission_UnreadableIsNotEmpty: a row that does not decode and a
// read that fails are errors, never "no permissions" (I9).
func TestPAPermission_UnreadableIsNotEmpty(t *testing.T) {
	paConvoDialects(t, func(t *testing.T, s *Store, alice, _ int64) {
		ctx := context.Background()
		w := newPAPermWorld(t, s, alice)
		must(t, w.insert(t, w.perm("prm_a"), t0))
		must(t, w.insert(t, w.perm("prm_b"), t0))
		for _, bad := range []string{`not json`, `[]`, `["dev-2","dev-1"]`, `["dev 1"]`, `null`} {
			if _, err := s.DB.Exec(`UPDATE pa_permissions SET device_ids = $1 WHERE principal = $2 AND id = 'prm_b'`, bad, alice); err != nil {
				t.Fatal(err)
			}
			if got, err := s.ListActivePAPermissions(ctx, alice, t0); !errors.Is(err, permissions.ErrUnreadable) || got != nil {
				t.Errorf("device_ids %q: list = %+v, %v", bad, got, err)
			}
			if got, err := s.LookupPAPermissions(ctx, alice, w.conn, w.rev, "alice", paPermTool, t0); !errors.Is(err, permissions.ErrUnreadable) || got != nil {
				t.Errorf("device_ids %q: lookup = %+v, %v", bad, got, err)
			}
		}
		cctx, cancel := context.WithCancel(ctx)
		cancel()
		if got, err := s.ListActivePAPermissions(cctx, alice, t0); !errors.Is(err, permissions.ErrUnreadable) || got != nil {
			t.Errorf("a failed read: list = %+v, %v", got, err)
		}
		if got, err := s.LookupPAPermissions(cctx, alice, w.conn, w.rev, "alice", paPermTool, t0); !errors.Is(err, permissions.ErrUnreadable) || got != nil {
			t.Errorf("a failed read: lookup = %+v, %v", got, err)
		}
		if got, err := s.ActivePAConnectionRefs(cctx, alice); !errors.Is(err, permissions.ErrUnreadable) || got != nil {
			t.Errorf("a failed read: connections = %+v, %v", got, err)
		}
	})
}

func TestPAPermission_CallbackAndConnections(t *testing.T) {
	paConvoDialects(t, func(t *testing.T, s *Store, alice, bob int64) {
		ctx := context.Background()
		w := newPAPermWorld(t, s, alice)
		w.seedConn(t, w.conn+"_exp", connection.ServerTG, connection.StateExpired)
		refs, err := s.ActivePAConnectionRefs(ctx, alice)
		must(t, err)
		if len(refs) != 1 || refs[0] != (permissions.ConnectionRef{ID: w.conn, Server: "alice", AuthorityRevision: w.rev, GrantedScope: "home"}) {
			t.Fatalf("refs %+v", refs)
		}
		for _, action := range []string{"approval_approve", "consent_accept:v1:x", "", "permission"} {
			if err := s.IssuePAPermissionCallback(ctx, alice, "cb_x", action, t0.Add(time.Minute)); !errors.Is(err, permissions.ErrInvalid) {
				t.Errorf("action %q: %v", action, err)
			}
		}
		action, err := permissions.RevokeAction("prm_a")
		must(t, err)
		must(t, s.IssuePAPermissionCallback(ctx, alice, "cb_prm", action, t0.Add(time.Minute)))
		// Only the principal it was issued for consumes it.
		err = inTx(t, s, func(tx *sql.Tx) error {
			_, err := s.ConsumePACallback(ctx, tx, bob, "cb_prm", t0)
			return err
		})
		if err == nil {
			t.Fatal("another principal consumed the callback")
		}
		var got string
		must(t, inTx(t, s, func(tx *sql.Tx) error {
			var err error
			got, err = s.ConsumePACallback(ctx, tx, alice, "cb_prm", t0)
			return err
		}))
		if got != action {
			t.Fatalf("consumed %q", got)
		}
	})
}

// TestPAPermission_ReadInTransaction: the read the write executor makes
// inside its pre-dispatch transaction (P2-S11) returns the row as it is,
// revoked or expired included, so that the caller decides; it finds
// nothing for another principal, and a row that does not decode is
// unreadable, never absent.
func TestPAPermission_ReadInTransaction(t *testing.T) {
	paConvoDialects(t, func(t *testing.T, s *Store, alice, bob int64) {
		ctx := context.Background()
		w := newPAPermWorld(t, s, alice)
		must(t, w.insert(t, w.perm("prm_tx"), t0))
		// The executor's transaction has resolved the dialect by the time
		// it reads a permission (BeginPAWrite); a bare transaction of this
		// test has not.
		if _, err := s.postgresDialect(ctx); err != nil {
			t.Fatal(err)
		}
		read := func(principal int64, id string) (permissions.Permission, error) {
			var p permissions.Permission
			err := inTx(t, s, func(tx *sql.Tx) error {
				var err error
				p, err = s.PAPermissionIn(ctx, tx, principal, id)
				return err
			})
			return p, err
		}
		p, err := read(alice, "prm_tx")
		must(t, err)
		if p.ID != "prm_tx" || p.Principal != alice || p.ConnectionID != w.conn || p.AuthorityRevision != w.rev ||
			p.Tool != paPermTool || fmt.Sprint(p.DeviceIDs) != "[dev-1 dev-2]" || p.Ceiling != 5 ||
			!p.ExpiresAt.Equal(t0.Add(24*time.Hour)) || !p.RevokedAt.IsZero() {
			t.Fatalf("read back %+v", p)
		}
		if _, err := read(bob, "prm_tx"); !errors.Is(err, permissions.ErrNotFound) {
			t.Fatalf("bob reads alice's permission: %v", err)
		}
		if _, err := read(alice, "prm_none"); !errors.Is(err, permissions.ErrNotFound) {
			t.Fatalf("an unknown id: %v", err)
		}
		if _, err := read(alice, "not an id"); !errors.Is(err, permissions.ErrInvalid) {
			t.Fatalf("a malformed id: %v", err)
		}
		if _, err := s.PAPermissionIn(ctx, nil, alice, "prm_tx"); !errors.Is(err, permissions.ErrInvalid) {
			t.Fatalf("no transaction: %v", err)
		}
		// A revoked row is returned, with its revocation.
		must(t, inTx(t, s, func(tx *sql.Tx) error { return s.RevokePAPermission(ctx, tx, alice, "prm_tx", t0.Add(time.Hour)) }))
		p, err = read(alice, "prm_tx")
		must(t, err)
		if !p.RevokedAt.Equal(t0.Add(time.Hour)) {
			t.Fatalf("revoked row read back %+v", p)
		}
		// A row that does not decode is unreadable.
		_, err = s.DB.Exec(`UPDATE pa_permissions SET device_ids = 'not json' WHERE principal = $1 AND id = $2`, alice, "prm_tx")
		must(t, err)
		if _, err := read(alice, "prm_tx"); !errors.Is(err, permissions.ErrUnreadable) || errors.Is(err, permissions.ErrNotFound) {
			t.Fatalf("an undecodable row: %v", err)
		}
	})
}

// TestS2A9_EndedPermissionsAreSwept: a permission that was revoked, or
// whose expiry passed, permissions.Retention ago is deleted by the
// conversation sweep. One that still counts is kept whatever its age, and
// so is one that ended more recently.
func TestS2A9_EndedPermissionsAreSwept(t *testing.T) {
	paConvoDialects(t, func(t *testing.T, s *Store, alice, bob int64) {
		ctx := context.Background()
		wa, wb := newPAPermWorld(t, s, alice), newPAPermWorld(t, s, bob)
		long := func(w paPermWorld, id string) permissions.Permission {
			p := w.perm(id)
			p.ExpiresAt = t0.Add(permissions.MaxTTL)
			return p
		}
		// All granted at t0. The sweep runs ten days later.
		now := t0.Add(10 * 24 * time.Hour)
		ret := permissions.Retention
		for _, id := range []string{"prm_live", "prm_revoked_old", "prm_revoked_new"} {
			must(t, wa.insert(t, long(wa, id), t0))
		}
		must(t, wb.insert(t, long(wb, "prm_bob_old"), t0))
		must(t, wb.insert(t, long(wb, "prm_bob_live"), t0))
		revoke := func(principal int64, id string, at time.Time) {
			t.Helper()
			must(t, inTx(t, s, func(tx *sql.Tx) error { return s.RevokePAPermission(ctx, tx, principal, id, at) }))
		}
		revoke(alice, "prm_revoked_old", now.Add(-ret-time.Minute))
		revoke(alice, "prm_revoked_new", now.Add(-ret+time.Minute))
		revoke(bob, "prm_bob_old", now.Add(-ret-time.Minute))
		// Expired rows are made by moving the expiry: a grant cannot be
		// made with one in the past.
		for id, exp := range map[string]time.Time{"prm_expired_old": now.Add(-ret - time.Minute), "prm_expired_new": now.Add(-ret + time.Minute)} {
			must(t, wa.insert(t, long(wa, id), t0))
			_, err := s.DB.Exec(`UPDATE pa_permissions SET expires_at_ms = $3 WHERE principal = $1 AND id = $2`, alice, id, exp.UnixMilli())
			must(t, err)
		}
		ids := func(principal int64) []string {
			t.Helper()
			rows, err := s.DB.Query(`SELECT id FROM pa_permissions WHERE principal = $1 ORDER BY id`, principal)
			must(t, err)
			defer func() { _ = rows.Close() }()
			var out []string
			for rows.Next() {
				var id string
				must(t, rows.Scan(&id))
				out = append(out, id)
			}
			must(t, rows.Err())
			return out
		}
		if _, err := s.SweepPAState(ctx, now, now.Add(-48*time.Hour)); err != nil {
			t.Fatalf("sweep: %v", err)
		}
		if got, want := ids(alice), []string{"prm_expired_new", "prm_live", "prm_revoked_new"}; !slices.Equal(got, want) {
			t.Fatalf("alice's rows after the sweep: %v, want %v", got, want)
		}
		if got, want := ids(bob), []string{"prm_bob_live"}; !slices.Equal(got, want) {
			t.Fatalf("bob's rows after the sweep: %v, want %v", got, want)
		}
		// The row in force still lowers; the two that ended do not, swept
		// or not.
		if got := wa.list(t, now); len(got) != 1 || got[0].ID != "prm_live" {
			t.Fatalf("active permissions after the sweep: %+v", got)
		}
		// Once their retention has passed the other two go as well.
		later := now.Add(2 * time.Minute)
		if _, err := s.SweepPAState(ctx, later, later.Add(-48*time.Hour)); err != nil {
			t.Fatalf("second sweep: %v", err)
		}
		if got, want := ids(alice), []string{"prm_live"}; !slices.Equal(got, want) {
			t.Fatalf("alice's rows after the second sweep: %v, want %v", got, want)
		}
	})
}
