package db

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"math/rand/v2"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/pa/convo"
)

// paConvoDialects runs body on SQLite and, when TEST_DATABASE_URL is set,
// Postgres. On Postgres the database outlives the run, so the personas get
// random ids (Alice and Bob offsets in a range no fixture uses) and their
// rows are deleted before and after.
func paConvoDialects(t *testing.T, body func(t *testing.T, s *Store, alice, bob int64)) {
	t.Run("sqlite", func(t *testing.T) { body(t, newTestStore(t), 555, 556) })
	t.Run("postgres", func(t *testing.T) {
		dsn := os.Getenv("TEST_DATABASE_URL")
		if dsn == "" {
			t.Skip("TEST_DATABASE_URL not set")
		}
		s := newPostgresTestStore(t, dsn)
		base := 9_000_000_000 + rand.Int64N(1_000_000_000)*2
		alice, bob := base, base+1
		clean := func() {
			for _, q := range []string{
				`DELETE FROM pa_fragments WHERE principal IN ($1, $2)`,
				`DELETE FROM pa_conversations WHERE principal IN ($1, $2)`,
				`DELETE FROM pa_callbacks WHERE principal IN ($1, $2)`,
				`DELETE FROM pa_consents WHERE principal IN ($1, $2)`,
				`DELETE FROM pa_principal_locks WHERE principal IN ($1, $2)`,
			} {
				_, _ = s.DB.Exec(q, alice, bob)
			}
		}
		clean()
		t.Cleanup(clean)
		body(t, s, alice, bob)
	})
}

// inTx runs fn in a committed transaction.
func inTx(t *testing.T, s *Store, fn func(tx *sql.Tx) error) error {
	t.Helper()
	tx, err := s.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

var t0 = time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)

func TestPAConsent_Store(t *testing.T) {
	paConvoDialects(t, func(t *testing.T, s *Store, alice, bob int64) {
		ctx := context.Background()
		get := func(p int64) (convo.ConsentRecord, error) {
			var rec convo.ConsentRecord
			var gerr error
			must(t, inTx(t, s, func(tx *sql.Tx) error { rec, gerr = s.GetPAConsent(ctx, tx, p); return nil }))
			return rec, gerr
		}
		if _, err := get(alice); !errors.Is(err, convo.ErrNotFound) {
			t.Fatalf("no row: err = %v, want ErrNotFound", err)
		}
		must(t, inTx(t, s, func(tx *sql.Tx) error {
			return s.AcceptPAConsent(ctx, tx, alice, convo.ConsentVersion, convo.ConsentTextSHA256(), t0)
		}))
		rec, err := get(alice)
		if err != nil || !convo.Satisfied(rec) {
			t.Fatalf("after accept: %+v %v", rec, err)
		}
		if _, err := get(bob); !errors.Is(err, convo.ErrNotFound) {
			t.Fatalf("bob sees consent: %v", err)
		}
		// S1-N2 at the row: a state this build does not know is unreadable,
		// not "no consent" and not consent.
		_, err = s.DB.Exec(`UPDATE pa_consents SET state = 'maybe' WHERE principal = $1`, alice)
		must(t, err)
		if _, err := get(alice); !errors.Is(err, convo.ErrUnreadable) {
			t.Fatalf("corrupt state: err = %v, want ErrUnreadable", err)
		}
		_, err = s.DB.Exec(`UPDATE pa_consents SET state = 'accepted', version = '' WHERE principal = $1`, alice)
		must(t, err)
		if _, err := get(alice); !errors.Is(err, convo.ErrUnreadable) {
			t.Fatalf("empty version: err = %v, want ErrUnreadable", err)
		}
	})
}

// TestPAConversation_TTLAnchoredAtCreation: expires_at is created_at + TTL
// and does not slide with activity; past it the conversation is not loaded
// and a new one is opened.
func TestPAConversation_TTLAnchoredAtCreation(t *testing.T) {
	paConvoDialects(t, func(t *testing.T, s *Store, alice, _ int64) {
		ctx := context.Background()
		ttl := 24 * time.Hour
		var c1 convo.Conversation
		must(t, inTx(t, s, func(tx *sql.Tx) (err error) {
			c1, err = s.OpenPAConversation(ctx, tx, alice, "conv-1", t0, ttl)
			return err
		}))
		if !c1.ExpiresAt.Equal(t0.Add(ttl)) || c1.ID != "conv-1" {
			t.Fatalf("conversation = %+v", c1)
		}
		// Activity 23h later reuses it without moving the expiry.
		var c2 convo.Conversation
		must(t, inTx(t, s, func(tx *sql.Tx) (err error) {
			c2, err = s.OpenPAConversation(ctx, tx, alice, "conv-2", t0.Add(23*time.Hour), ttl)
			return err
		}))
		if c2.ID != "conv-1" || !c2.ExpiresAt.Equal(t0.Add(ttl)) {
			t.Fatalf("23h later = %+v, want conv-1 with the original expiry", c2)
		}
		if _, err := s.LoadPAFragments(ctx, alice, "conv-1", t0.Add(ttl-time.Second)); err != nil {
			t.Fatalf("load before expiry: %v", err)
		}
		if _, err := s.LoadPAFragments(ctx, alice, "conv-1", t0.Add(ttl)); !errors.Is(err, convo.ErrNotFound) {
			t.Fatalf("load at expiry: err = %v, want ErrNotFound", err)
		}
		var c3 convo.Conversation
		must(t, inTx(t, s, func(tx *sql.Tx) (err error) {
			c3, err = s.OpenPAConversation(ctx, tx, alice, "conv-3", t0.Add(ttl), ttl)
			return err
		}))
		if c3.ID != "conv-3" {
			t.Fatalf("after expiry = %+v, want a new conversation", c3)
		}
	})
}

// TestPAState_SweepAndPurge: the sweeper hard-deletes expired and closed
// conversations with their fragments, expired callbacks and old pa_updates,
// and leaves live state alone. The purge deletes only unmarked fragments.
func TestPAState_SweepAndPurge(t *testing.T) {
	paConvoDialects(t, func(t *testing.T, s *Store, alice, bob int64) {
		ctx := context.Background()
		ttl := time.Hour
		frag := func(p int64, conv string, seq int64, prov convo.Provenance) convo.SealedFragment {
			return convo.SealedFragment{ConversationID: conv, Seq: seq, Principal: p, Kind: convo.KindText,
				Provenance: prov, Sealed: []byte{1, 2, 3}, CreatedAt: t0}
		}
		convA, convB := "sweep-a-"+strconv.FormatInt(alice, 10), "sweep-b-"+strconv.FormatInt(bob, 10)
		must(t, inTx(t, s, func(tx *sql.Tx) error {
			if _, err := s.OpenPAConversation(ctx, tx, alice, convA, t0, ttl); err != nil {
				return err
			}
			if _, err := s.OpenPAConversation(ctx, tx, bob, convB, t0.Add(2*time.Hour), ttl); err != nil {
				return err
			}
			for _, f := range []convo.SealedFragment{frag(alice, convA, 1, convo.ProvenanceUser), frag(bob, convB, 1, convo.ProvenanceExternal)} {
				if err := s.AppendPAFragment(ctx, tx, f); err != nil {
					return err
				}
			}
			if err := s.CreatePACallback(ctx, tx, alice, "cb-old", "x", t0.Add(time.Minute)); err != nil {
				return err
			}
			return s.CreatePACallback(ctx, tx, bob, "cb-live", "x", t0.Add(10*time.Hour))
		}))
		// The store refuses to write an unmarked fragment...
		err := inTx(t, s, func(tx *sql.Tx) error { return s.AppendPAFragment(ctx, tx, frag(bob, convB, 2, "")) })
		if !errors.Is(err, convo.ErrInvalid) {
			t.Fatalf("unmarked append: err = %v, want ErrInvalid", err)
		}
		// ...and one that exists anyway is purged and refused on load.
		_, err = s.DB.Exec(`INSERT INTO pa_fragments(conversation_id, seq, principal, kind, provenance, sealed, created_at_ms)
			VALUES($1, 2, $2, 'text', '', $3, 0)`, convB, bob, []byte{9})
		must(t, err)
		// A marked row of a kind this build does not know is undecodable too.
		_, err = s.DB.Exec(`INSERT INTO pa_fragments(conversation_id, seq, principal, kind, provenance, sealed, created_at_ms)
			VALUES($1, 3, $2, 'sticker', 'user', $3, 0)`, convB, bob, []byte{9})
		must(t, err)
		rows, err := s.LoadPAFragments(ctx, bob, convB, t0.Add(2*time.Hour))
		must(t, err)
		if len(rows) != 3 || rows[1].Provenance.Known() || rows[2].Kind.Valid() {
			t.Fatalf("raw load = %+v", rows)
		}
		n, err := s.PurgeUnmarkedPAState(ctx)
		must(t, err)
		if n < 2 {
			t.Fatalf("purged %d rows, want the unmarked and the unknown-kind one", n)
		}
		if rows, _ := s.LoadPAFragments(ctx, bob, convB, t0.Add(2*time.Hour)); len(rows) != 1 || rows[0].Seq != 1 {
			t.Fatalf("after purge: %+v, want the marked text one only", rows)
		}

		// pa_updates: one old, one recent.
		oldID, newID := 7_000_000_000+alice, 7_000_000_000+bob
		_, _ = s.DB.Exec(`DELETE FROM pa_updates WHERE update_id IN ($1, $2)`, oldID, newID)
		t.Cleanup(func() { _, _ = s.DB.Exec(`DELETE FROM pa_updates WHERE update_id IN ($1, $2)`, oldID, newID) })
		now := t0.Add(90 * time.Minute) // Alice's expired, Bob's live.
		_, err = s.DB.Exec(`INSERT INTO pa_updates(update_id, received_at) VALUES($1, $2), ($3, $4)`,
			oldID, now.Add(-49*time.Hour), newID, now.Add(-47*time.Hour))
		must(t, err)

		// Lock rows: Alice's unused for 49h, Bob's used 47h ago.
		_, err = s.DB.Exec(`INSERT INTO pa_principal_locks(principal, locked_at_ms) VALUES($1, $2), ($3, $4)`,
			alice, now.Add(-49*time.Hour).UnixMilli(), bob, now.Add(-47*time.Hour).UnixMilli())
		must(t, err)

		r, err := s.SweepPAState(ctx, now, now.Add(-48*time.Hour))
		must(t, err)
		// SweepPAState leaves lock rows alone: SweepPAPrincipalLocks is
		// their only sweep (#1318), and runs with the PA off too.
		if n := countRows(t, s, `SELECT count(*) FROM pa_principal_locks WHERE principal = $1`, alice); n != 1 {
			t.Fatalf("SweepPAState touched a lock row: %d left, want 1", n)
		}
		locks, err := s.SweepPAPrincipalLocks(ctx, now.Add(-48*time.Hour))
		must(t, err)
		if locks < 1 {
			t.Fatalf("SweepPAPrincipalLocks deleted %d rows, want the stale one", locks)
		}
		if n := countRows(t, s, `SELECT count(*) FROM pa_principal_locks WHERE principal = $1`, alice); n != 0 {
			t.Fatalf("stale lock row survived the sweep: %d", n)
		}
		if n := countRows(t, s, `SELECT count(*) FROM pa_principal_locks WHERE principal = $1`, bob); n != 1 {
			t.Fatalf("fresh lock row swept: %d left", n)
		}
		if r.Conversations < 1 || r.Fragments < 1 || r.Callbacks < 1 || r.Updates < 1 {
			t.Fatalf("sweep = %+v, want each class swept", r)
		}
		count := func(q string, args ...any) int {
			var n int
			must(t, s.DB.QueryRow(q, args...).Scan(&n))
			return n
		}
		if count(`SELECT count(*) FROM pa_conversations WHERE principal = $1`, alice) != 0 ||
			count(`SELECT count(*) FROM pa_fragments WHERE principal = $1`, alice) != 0 ||
			count(`SELECT count(*) FROM pa_callbacks WHERE principal = $1`, alice) != 0 {
			t.Fatal("alice's expired state survived the sweep")
		}
		if count(`SELECT count(*) FROM pa_conversations WHERE principal = $1`, bob) != 1 ||
			count(`SELECT count(*) FROM pa_fragments WHERE principal = $1`, bob) != 1 ||
			count(`SELECT count(*) FROM pa_callbacks WHERE principal = $1`, bob) != 1 {
			t.Fatal("bob's live state was swept")
		}
		if count(`SELECT count(*) FROM pa_updates WHERE update_id = $1`, oldID) != 0 ||
			count(`SELECT count(*) FROM pa_updates WHERE update_id = $1`, newID) != 1 {
			t.Fatal("pa_updates retention is not 48h")
		}

		// A closed (/new) conversation is swept even before its expiry.
		must(t, inTx(t, s, func(tx *sql.Tx) error { return s.ClosePAConversations(ctx, tx, bob, now) }))
		_, err = s.SweepPAState(ctx, now, now.Add(-48*time.Hour))
		must(t, err)
		if count(`SELECT count(*) FROM pa_conversations WHERE principal = $1`, bob) != 0 ||
			count(`SELECT count(*) FROM pa_fragments WHERE principal = $1`, bob) != 0 {
			t.Fatal("closed conversation survived the sweep")
		}
	})
}

// TestPACallback_KeyedByPrincipal is the store half of the T4 callback
// rule: an id resolves only under its own principal, once, before expiry,
// and another principal's attempt neither resolves nor consumes it.
func TestPACallback_KeyedByPrincipal(t *testing.T) {
	paConvoDialects(t, func(t *testing.T, s *Store, alice, bob int64) {
		ctx := context.Background()
		consume := func(p int64, id string, at time.Time) (string, error) {
			var a string
			var cerr error
			must(t, inTx(t, s, func(tx *sql.Tx) error { a, cerr = s.ConsumePACallback(ctx, tx, p, id, at); return nil }))
			return a, cerr
		}
		must(t, inTx(t, s, func(tx *sql.Tx) error {
			return s.CreatePACallback(ctx, tx, alice, "opaque-a", "consent_accept:x", t0.Add(time.Hour))
		}))
		if _, err := consume(bob, "opaque-a", t0); !errors.Is(err, convo.ErrNotFound) {
			t.Fatalf("bob resolved alice's id: %v", err)
		}
		if _, err := consume(alice, "opaque-a", t0.Add(time.Hour)); !errors.Is(err, convo.ErrNotFound) {
			t.Fatalf("expired id resolved: %v", err)
		}
		a, err := consume(alice, "opaque-a", t0)
		if err != nil || a != "consent_accept:x" {
			t.Fatalf("alice: %q %v (bob's attempt must not have consumed it)", a, err)
		}
		if _, err := consume(alice, "opaque-a", t0); !errors.Is(err, convo.ErrNotFound) {
			t.Fatalf("second use resolved: %v", err)
		}
	})
}

// TestPAFragments_KeyedByPrincipal: a fragment cannot be appended to, nor
// loaded from, another principal's conversation.
func TestPAFragments_KeyedByPrincipal(t *testing.T) {
	paConvoDialects(t, func(t *testing.T, s *Store, alice, bob int64) {
		ctx := context.Background()
		conv := "keyed-" + strconv.FormatInt(alice, 10)
		must(t, inTx(t, s, func(tx *sql.Tx) error {
			_, err := s.OpenPAConversation(ctx, tx, alice, conv, t0, time.Hour)
			return err
		}))
		f := convo.SealedFragment{ConversationID: conv, Seq: 1, Principal: bob, Kind: convo.KindText,
			Provenance: convo.ProvenanceUser, Sealed: bytes.Repeat([]byte{1}, 4), CreatedAt: t0}
		if err := inTx(t, s, func(tx *sql.Tx) error { return s.AppendPAFragment(ctx, tx, f) }); !errors.Is(err, convo.ErrNotFound) {
			t.Fatalf("bob appended to alice's conversation: %v", err)
		}
		if err := inTx(t, s, func(tx *sql.Tx) error { _, err := s.NextPAFragmentSeq(ctx, tx, bob, conv); return err }); !errors.Is(err, convo.ErrNotFound) {
			t.Fatalf("bob read alice's sequence: %v", err)
		}
		if _, err := s.LoadPAFragments(ctx, bob, conv, t0); !errors.Is(err, convo.ErrNotFound) {
			t.Fatalf("bob loaded alice's conversation: %v", err)
		}
	})
}

// TestPAPrincipalLock_SerialisesWithdraw (S1-N4, concurrency): a message
// transaction that read consent=accepted and wrote a conversation, racing
// /consent withdraw or /forget in a second transaction. With both taking
// LockPAPrincipal first, the second waits for the first, then sees and
// deletes its rows. Without the lock (Postgres, READ COMMITTED) the second
// commits at once and the message's conversation survives it. SQLite
// serialises writers by itself, so only Postgres can show the race.
func TestPAPrincipalLock_SerialisesWithdraw(t *testing.T) {
	for _, op := range []string{"withdraw", "forget"} {
		t.Run(op, func(t *testing.T) {
			paConvoDialects(t, func(t *testing.T, s *Store, alice, _ int64) {
				if strings.HasSuffix(t.Name(), "/sqlite") {
					t.Skip("SQLite serialises writers; the race needs Postgres")
				}
				ctx := context.Background()
				must(t, inTx(t, s, func(tx *sql.Tx) error {
					return s.AcceptPAConsent(ctx, tx, alice, convo.ConsentVersion, convo.ConsentTextSHA256(), t0)
				}))
				// T1: the message, up to just before commit.
				t1, err := s.DB.BeginTx(ctx, nil)
				must(t, err)
				defer func() { _ = t1.Rollback() }()
				must(t, s.LockPAPrincipal(ctx, t1, alice))
				rec, err := s.GetPAConsent(ctx, t1, alice)
				must(t, err)
				if !convo.Satisfied(rec) {
					t.Fatal("consent not satisfied")
				}
				convID := "conv-race-" + op + "-" + strconv.FormatInt(alice, 10)
				c, err := s.OpenPAConversation(ctx, t1, alice, convID, t0, 24*time.Hour)
				must(t, err)
				must(t, s.AppendPAFragment(ctx, t1, convo.SealedFragment{ConversationID: c.ID, Seq: 1, Principal: alice,
					Kind: convo.KindText, Provenance: convo.ProvenanceUser, Sealed: []byte{1, 2, 3}, CreatedAt: t0}))

				// T2: the command, in its own transaction.
				done := make(chan error, 1)
				go func() {
					done <- func() error {
						tx, err := s.DB.BeginTx(ctx, nil)
						if err != nil {
							return err
						}
						defer func() { _ = tx.Rollback() }()
						if err := s.LockPAPrincipal(ctx, tx, alice); err != nil {
							return err
						}
						if op == "withdraw" {
							err = s.WithdrawPAConsent(ctx, tx, alice, t0.Add(time.Second))
						} else {
							err = s.ForgetPAConversations(ctx, tx, alice)
						}
						if err != nil {
							return err
						}
						return tx.Commit()
					}()
				}()
				select {
				case err := <-done:
					t.Fatalf("%s committed (err=%v) while the message transaction was still open", op, err)
				case <-time.After(time.Second):
				}
				must(t, t1.Commit())
				select {
				case err := <-done:
					must(t, err)
				case <-time.After(10 * time.Second):
					t.Fatalf("%s never finished after the message committed", op)
				}
				frags, err := s.LoadPAFragments(ctx, alice, c.ID, t0.Add(2*time.Second))
				if err == nil && len(frags) > 0 {
					t.Fatalf("the racing message's conversation survives %s: %d fragments", op, len(frags))
				}
				if !errors.Is(err, convo.ErrNotFound) {
					t.Fatalf("load after %s: err = %v, want ErrNotFound", op, err)
				}
			})
		})
	}
}
