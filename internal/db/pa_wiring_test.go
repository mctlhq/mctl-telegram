package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
)

// Store-level guards of the linking wiring (#1338): the per-principal
// pending cap, the Begin fence against account deletion, and the account
// deletion that revokes provider tokens before the purge.

// seedPAConnectionWithTokens creates a connection of principal and drives
// it to pending_confirm, the first state that holds provider tokens.
func seedPAConnectionWithTokens(t *testing.T, s *Store, principal int64) string {
	t.Helper()
	ctx := context.Background()
	id := seedPAConnection(t, s, principal)
	for _, tr := range []connection.Transition{
		{From: connection.StatePendingLink, To: connection.StatePendingOAuth, ExpectRevision: 1},
		{From: connection.StatePendingOAuth, To: connection.StatePendingReturn, ExpectRevision: 2, SealedCode: []byte("code")},
		{From: connection.StatePendingReturn, To: connection.StatePendingConfirm, ExpectRevision: 3,
			AccountID: "acct", GrantedScope: "telegram:dialogs:read", SealedTokens: []byte("tokens")},
	} {
		if _, err := s.TransitionPAConnection(ctx, principal, id, tr); err != nil {
			t.Fatalf("%s -> %s: %v", tr.From, tr.To, err)
		}
	}
	return id
}

func newPAConn(principal int64, id string) (connection.Connection, connection.Sealed) {
	return connection.Connection{
		ID: id, Principal: principal, Server: connection.ServerTG, State: connection.StatePendingLink, AuthorityRevision: 1,
	}, connection.Sealed{KEKID: "test", WrappedDEK: []byte("wrapped")}
}

// T10: the pending cap holds for concurrent Begins. Every Begin is admitted
// first (nothing is pending yet, so admission alone would let all of them
// through); only the count under the principal's lock in CreatePAConnection
// stops the rest.
func TestCreatePAConnection_PendingCapUnderConcurrentBegins(t *testing.T) {
	deletionDialects(t, func(t *testing.T, s *Store, base int64) {
		ctx := context.Background()
		alice := base + 32
		t.Cleanup(func() { _, _ = s.DB.Exec(`DELETE FROM pa_connections WHERE principal = $1`, alice) })
		const begins = 8
		adms := make([]connection.Admission, begins)
		for i := range adms {
			adms[i] = mustAdmitPA(t, s, alice)
		}
		var wg sync.WaitGroup
		errs := make([]error, begins)
		for i := range begins {
			wg.Add(1)
			go func() {
				defer wg.Done()
				c, sealed := newPAConn(alice, fmt.Sprintf("pac_cap_%d_%d_%s", alice, i, randomSuffix(t)))
				errs[i] = s.CreatePAConnection(ctx, c, sealed, adms[i])
			}()
		}
		wg.Wait()
		created, capped := 0, 0
		for _, err := range errs {
			switch {
			case err == nil:
				created++
			case errors.Is(err, connection.ErrTooManyPending):
				capped++
			default:
				t.Errorf("create: %v", err)
			}
		}
		if created != connection.MaxPendingConnections || capped != begins-connection.MaxPendingConnections {
			t.Fatalf("created %d, capped %d; want %d and %d", created, capped,
				connection.MaxPendingConnections, begins-connection.MaxPendingConnections)
		}
		if n := paRowsIn(t, s, "pa_connections", alice); n != connection.MaxPendingConnections {
			t.Fatalf("%d pending rows, want %d", n, connection.MaxPendingConnections)
		}
		if _, err := s.AdmitPAConnection(ctx, alice); !errors.Is(err, connection.ErrTooManyPending) {
			t.Fatalf("admission at the cap: %v, want ErrTooManyPending", err)
		}
	})
}

// The cap counts only pending connections: a failed one frees a slot, and
// an active one never takes one.
func TestAdmitPAConnection_CountsOnlyPending(t *testing.T) {
	deletionDialects(t, func(t *testing.T, s *Store, base int64) {
		ctx := context.Background()
		bob := base + 33
		ids := make([]string, connection.MaxPendingConnections)
		for i := range ids {
			ids[i] = seedPAConnection(t, s, bob)
		}
		if _, err := s.AdmitPAConnection(ctx, bob); !errors.Is(err, connection.ErrTooManyPending) {
			t.Fatalf("admission at the cap: %v, want ErrTooManyPending", err)
		}
		if _, err := s.TransitionPAConnection(ctx, bob, ids[0], connection.Transition{
			From: connection.StatePendingLink, To: connection.StateFailed, ExpectRevision: 1, Reason: "test",
		}); err != nil {
			t.Fatalf("fail: %v", err)
		}
		if _, err := s.AdmitPAConnection(ctx, bob); err != nil {
			t.Fatalf("admission after one failed: %v", err)
		}
	})
}

// A failed admission read is an error, never an admission.
func TestAdmitPAConnection_UnreadableRefuses(t *testing.T) {
	isolatedDialects(t, func(t *testing.T, s *Store) {
		if _, err := s.DB.Exec(`ALTER TABLE pa_principal_locks RENAME COLUMN purged_at_ms TO purged_at_ms_gone`); err != nil {
			t.Fatal(err)
		}
		if _, err := s.AdmitPAConnection(context.Background(), 5858); !errors.Is(err, connection.ErrUnreadable) {
			t.Fatalf("admission with an unreadable mark: %v, want ErrUnreadable", err)
		}
	})
}

// A Begin admitted before an account deletion cannot create a connection
// after it: the deletion raised the principal's mark. A Begin admitted after
// the deletion links again.
func TestCreatePAConnection_FencedByAccountDeletion(t *testing.T) {
	deletionDialects(t, func(t *testing.T, s *Store, base int64) {
		ctx := context.Background()
		dana := base + 34
		uid, err := s.EnsureUserByTelegramID(ctx, dana, "dana", "Dana")
		if err != nil {
			t.Fatalf("ensure: %v", err)
		}
		seedAccountForTelegramID(t, s, uid, dana, nil)
		t.Cleanup(func() {
			_, _ = s.DB.Exec(`DELETE FROM pa_connections WHERE principal = $1`, dana)
			_, _ = s.DB.Exec(`DELETE FROM pa_principal_locks WHERE principal = $1`, dana)
		})
		before := mustAdmitPA(t, s, dana)
		if _, err := s.HardDeleteAccount(ctx, uid); err != nil {
			t.Fatalf("delete: %v", err)
		}
		c, sealed := newPAConn(dana, "pac_fence_"+randomSuffix(t))
		if err := s.CreatePAConnection(ctx, c, sealed, before); !errors.Is(err, connection.ErrPrincipalDeleted) {
			t.Fatalf("create admitted before the deletion: %v, want ErrPrincipalDeleted", err)
		}
		if n := paRowsIn(t, s, "pa_connections", dana); n != 0 {
			t.Fatalf("%d connections after the fenced create, want 0", n)
		}
		after := mustAdmitPA(t, s, dana)
		if err := s.CreatePAConnection(ctx, c, sealed, after); err != nil {
			t.Fatalf("create admitted after the deletion: %v", err)
		}
	})
}

// The deletion mark grows on every deletion, even when the clock does not:
// a mark already at or past now is raised by one.
func TestPurgePAPrincipals_MarkStrictlyGrows(t *testing.T) {
	deletionDialects(t, func(t *testing.T, s *Store, base int64) {
		ctx := context.Background()
		carol := base + 35
		uid, err := s.EnsureUserByTelegramID(ctx, carol, "carol", "Carol")
		if err != nil {
			t.Fatalf("ensure: %v", err)
		}
		seedAccountForTelegramID(t, s, uid, carol, nil)
		future := time.Now().Add(time.Hour).UnixMilli()
		if _, err := s.DB.ExecContext(ctx,
			`INSERT INTO pa_principal_locks(principal, locked_at_ms, purged_at_ms) VALUES($1, $2, $2)`, carol, future); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _, _ = s.DB.Exec(`DELETE FROM pa_principal_locks WHERE principal = $1`, carol) })
		adm := mustAdmitPA(t, s, carol)
		if _, err := s.HardDeleteAccount(ctx, uid); err != nil {
			t.Fatalf("delete: %v", err)
		}
		if m := paPurgeMark(t, s, carol); m != future+1 {
			t.Fatalf("mark = %d after a deletion at a clock behind it, want %d", m, future+1)
		}
		c, sealed := newPAConn(carol, "pac_mark_"+randomSuffix(t))
		t.Cleanup(func() { _, _ = s.DB.Exec(`DELETE FROM pa_connections WHERE principal = $1`, carol) })
		if err := s.CreatePAConnection(ctx, c, sealed, adm); !errors.Is(err, connection.ErrPrincipalDeleted) {
			t.Fatalf("create admitted before the deletion: %v, want ErrPrincipalDeleted", err)
		}
	})
}

// fakePARevoker stands in for (*connection.Manager).RevokeHeldTokens.
type fakePARevoker struct {
	s     *Store
	err   error
	noop  bool
	mu    sync.Mutex
	calls []int64
}

func (f *fakePARevoker) RevokeHeldTokens(ctx context.Context, principal int64) error {
	f.mu.Lock()
	f.calls = append(f.calls, principal)
	f.mu.Unlock()
	if f.err != nil || f.noop {
		return f.err
	}
	list, err := f.s.ListPAConnections(ctx, principal)
	if err != nil {
		return err
	}
	for _, c := range list {
		if _, _, _, err := f.s.RevokePAConnection(ctx, principal, c.ID, "account_deleted"); err != nil {
			return err
		}
	}
	return nil
}

func accountRows(t *testing.T, s *Store, uid int64) int {
	t.Helper()
	var n int
	if err := s.DB.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM telegram_accounts WHERE user_id = $1`, uid).Scan(&n); err != nil {
		t.Fatalf("count accounts: %v", err)
	}
	return n
}

// Account deletion revokes every token-holding connection of every Telegram
// id of the account before the purge. A failed revocation refuses the whole
// deletion and keeps the connection with its tokens; a revoker that leaves
// tokens behind is caught by the purge's own check.
func TestDeleteAccountRevokingPA(t *testing.T) {
	deletionDialects(t, func(t *testing.T, s *Store, base int64) {
		ctx := context.Background()
		login, session := base+37, base+36
		alice, err := s.EnsureUserByTelegramID(ctx, login, "alice", "Alice")
		if err != nil {
			t.Fatalf("ensure: %v", err)
		}
		seedAccountForTelegramID(t, s, alice, session, nil)
		t.Cleanup(func() {
			_, _ = s.DB.Exec(`DELETE FROM pa_principal_locks WHERE principal IN ($1, $2)`, login, session)
		})
		loginConn := seedPAConnectionWithTokens(t, s, login)
		sessionConn := seedPAConnectionWithTokens(t, s, session)

		cause := errors.New("provider unreachable")
		failing := &fakePARevoker{s: s, err: cause}
		if _, err := s.DeleteAccountRevokingPA(ctx, alice, failing); !errors.Is(err, ErrPAConnectionsNeedRevocation) || !errors.Is(err, cause) {
			t.Fatalf("delete with a failing revocation: %v, want ErrPAConnectionsNeedRevocation and the cause", err)
		}
		if n := accountRows(t, s, alice); n != 1 {
			t.Fatalf("telegram_accounts rows = %d after a refused delete, want 1", n)
		}
		for p, id := range map[int64]string{login: loginConn, session: sessionConn} {
			if _, sealed, err := s.GetPAConnectionSealed(ctx, p, id); err != nil || len(sealed.SealedTokens) == 0 {
				t.Fatalf("connection of %d after a refused delete: err %v, %d token bytes, want it kept", p, err, len(sealed.SealedTokens))
			}
		}

		noop := &fakePARevoker{s: s, noop: true}
		if _, err := s.DeleteAccountRevokingPA(ctx, alice, noop); !errors.Is(err, ErrPAConnectionsNeedRevocation) {
			t.Fatalf("delete after a revoker that revoked nothing: %v, want the purge to refuse", err)
		}
		if n := accountRows(t, s, alice); n != 1 {
			t.Fatalf("telegram_accounts rows = %d after a refused delete, want 1", n)
		}

		ok := &fakePARevoker{s: s}
		if _, err := s.DeleteAccountRevokingPA(ctx, alice, ok); err != nil {
			t.Fatalf("delete: %v", err)
		}
		if want := []int64{min(login, session), max(login, session)}; !slices.Equal(ok.calls, want) {
			t.Fatalf("revoked principals %v, want every Telegram id of the account in order %v", ok.calls, want)
		}
		if n := accountRows(t, s, alice); n != 0 {
			t.Fatalf("telegram_accounts rows = %d after the delete, want 0", n)
		}
		for _, p := range []int64{login, session} {
			if n := paRowsIn(t, s, "pa_connections", p); n != 0 {
				t.Fatalf("%d connections of %d after the delete, want 0", n, p)
			}
		}
	})
}

// A nil revoker is refused rather than read as "nothing to revoke".
func TestDeleteAccountRevokingPA_NilRevoker(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.DeleteAccountRevokingPA(context.Background(), 1, nil); err == nil {
		t.Fatal("delete with a nil revoker succeeded")
	}
}

// waitForPALockWait waits until a Postgres backend running a statement that
// starts with prefix is waiting on a lock.
func waitForPALockWait(t *testing.T, s *Store, prefix string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var n int
		if err := s.DB.QueryRow(`SELECT COUNT(*) FROM pg_stat_activity
			WHERE wait_event_type = 'Lock' AND query LIKE $1`, prefix+"%").Scan(&n); err != nil {
			t.Fatalf("pg_stat_activity: %v", err)
		}
		if n > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no backend waiting on a lock in %q", prefix)
}

// Postgres, two real transactions: a Begin admitted before a deletion that
// is still running waits for the deletion's principal lock, then sees the
// raised mark and creates nothing.
func TestCreatePAConnection_WaitsForDeletingTransaction(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	s := newPostgresTestStore(t, dsn)
	ctx := context.Background()
	dana := 9200000000 + (time.Now().UnixNano()/1000)%100000000 + 38
	uid, err := s.EnsureUserByTelegramID(ctx, dana, "dana", "Dana")
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	seedAccountForTelegramID(t, s, uid, dana, nil)
	t.Cleanup(func() {
		_, _ = s.DB.Exec(`DELETE FROM pa_connections WHERE principal = $1`, dana)
		_, _ = s.DB.Exec(`DELETE FROM pa_principal_locks WHERE principal = $1`, dana)
	})
	adm := mustAdmitPA(t, s, dana)

	inPurge, release := make(chan struct{}), make(chan struct{})
	paPurgeAfterDelete = func(context.Context, *sql.Tx, int64) {
		close(inPurge)
		<-release
	}
	t.Cleanup(func() { paPurgeAfterDelete = nil })
	deleted := make(chan error, 1)
	go func() {
		_, err := s.HardDeleteAccount(ctx, uid)
		deleted <- err
	}()
	<-inPurge
	created := make(chan error, 1)
	go func() {
		c, sealed := newPAConn(dana, "pac_wait_"+randomSuffix(t))
		created <- s.CreatePAConnection(ctx, c, sealed, adm)
	}()
	waitForPALockWait(t, s, "INSERT INTO pa_principal_locks")
	close(release)
	if err := <-deleted; err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := <-created; !errors.Is(err, connection.ErrPrincipalDeleted) {
		t.Fatalf("create that waited for the deletion: %v, want ErrPrincipalDeleted", err)
	}
	if n := paRowsIn(t, s, "pa_connections", dana); n != 0 {
		t.Fatalf("%d connections after the deletion, want 0", n)
	}
}

// Postgres, two real transactions: the purge's connection delete waits for
// a writer that is giving a row tokens, and once that writer commits, the
// delete re-checks the row against its predicate (sealed_tokens IS NULL)
// and skips it. The statement is the one paPrincipalPurges runs.
func TestPAConnectionsPurge_SkipsRowThatGainsTokensWhileWaiting(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	s := newPostgresTestStore(t, dsn)
	ctx := context.Background()
	bob := 9200000000 + (time.Now().UnixNano()/1000)%100000000 + 39
	id := seedPAConnection(t, s, bob)
	var purge string
	for _, st := range paPrincipalPurges {
		if st.table == "pa_connections" {
			purge = st.q
		}
	}
	if purge == "" {
		t.Fatal("no pa_connections statement in paPrincipalPurges")
	}

	writer, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = writer.Rollback() }()
	if _, err := writer.ExecContext(ctx,
		`UPDATE pa_connections SET sealed_tokens = $1 WHERE principal = $2 AND id = $3`, []byte("tokens"), bob, id); err != nil {
		t.Fatalf("writer: %v", err)
	}

	type result struct {
		n   int64
		err error
	}
	done := make(chan result, 1)
	go func() {
		tx, err := s.DB.BeginTx(ctx, nil)
		if err != nil {
			done <- result{err: err}
			return
		}
		defer func() { _ = tx.Rollback() }()
		res, err := tx.ExecContext(ctx, purge, bob)
		if err != nil {
			done <- result{err: err}
			return
		}
		n, err := res.RowsAffected()
		if err == nil {
			err = tx.Commit()
		}
		done <- result{n: n, err: err}
	}()
	waitForPALockWait(t, s, "DELETE FROM pa_connections")
	if err := writer.Commit(); err != nil {
		t.Fatalf("writer commit: %v", err)
	}
	r := <-done
	if r.err != nil {
		t.Fatalf("purge: %v", r.err)
	}
	if r.n != 0 {
		t.Fatalf("purge deleted %d rows, want 0: the row gained tokens while the delete waited", r.n)
	}
	if _, sealed, err := s.GetPAConnectionSealed(ctx, bob, id); err != nil || len(sealed.SealedTokens) == 0 {
		t.Fatalf("connection after the purge: err %v, %d token bytes, want it kept with its tokens", err, len(sealed.SealedTokens))
	}
}

// Postgres, deterministic T10 race: Begin A is held between its recount and
// its insert while Begin B, admitted at cap-1 too, runs. B must wait for
// A's principal lock and then count A's row, or both would insert and the
// principal would end past the cap.
func TestCreatePAConnection_PendingCapHeldBegin(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	s := newPostgresTestStore(t, dsn)
	ctx := context.Background()
	bob := 9200000000 + (time.Now().UnixNano()/1000)%100000000 + 40
	t.Cleanup(func() {
		_, _ = s.DB.Exec(`DELETE FROM pa_connections WHERE principal = $1`, bob)
		_, _ = s.DB.Exec(`DELETE FROM pa_principal_locks WHERE principal = $1`, bob)
	})
	for range connection.MaxPendingConnections - 1 {
		seedPAConnection(t, s, bob)
	}
	admA, admB := mustAdmitPA(t, s, bob), mustAdmitPA(t, s, bob)
	cA, sealed := newPAConn(bob, "pac_held_a_"+randomSuffix(t))
	cB, _ := newPAConn(bob, "pac_held_b_"+randomSuffix(t))

	held, release := make(chan struct{}), make(chan struct{})
	paCreateAfterRecount = func(c connection.Connection) {
		if c.ID == cA.ID {
			close(held)
			<-release
		}
	}
	t.Cleanup(func() { paCreateAfterRecount = nil })
	doneA, doneB := make(chan error, 1), make(chan error, 1)
	go func() { doneA <- s.CreatePAConnection(ctx, cA, sealed, admA) }()
	<-held
	go func() { doneB <- s.CreatePAConnection(ctx, cB, sealed, admB) }()

	// B either waits on A's lock (correct) or finishes without waiting.
	var errB error
	finishedEarly := false
	deadline := time.Now().Add(10 * time.Second)
wait:
	for {
		select {
		case errB = <-doneB:
			finishedEarly = true
			break wait
		default:
		}
		var n int
		if err := s.DB.QueryRow(`SELECT COUNT(*) FROM pg_stat_activity
			WHERE wait_event_type = 'Lock' AND query LIKE 'INSERT INTO pa_principal_locks%'`).Scan(&n); err != nil {
			t.Fatalf("pg_stat_activity: %v", err)
		}
		if n > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Begin B neither waited on the principal lock nor finished")
		}
		time.Sleep(20 * time.Millisecond)
	}
	close(release)
	if err := <-doneA; err != nil {
		t.Fatalf("Begin A: %v", err)
	}
	if !finishedEarly {
		errB = <-doneB
	}
	if finishedEarly && errB == nil {
		t.Fatal("Begin B created its row while Begin A was held after its recount: the cap check is not under the principal lock")
	}
	if !errors.Is(errB, connection.ErrTooManyPending) {
		t.Fatalf("Begin B: %v, want ErrTooManyPending", errB)
	}
	if n := paRowsIn(t, s, "pa_connections", bob); n != connection.MaxPendingConnections {
		t.Fatalf("%d pending rows, want %d", n, connection.MaxPendingConnections)
	}
}

// An account deletion of a principal that was never admitted to link leaves
// no pa_principal_locks row, so a deleted account's Telegram id is not kept
// even until the next lock sweep. One that was admitted keeps its row with
// the deletion mark raised, the fence a Begin in flight needs, until
// SweepPAPrincipalLocks removes it.
func TestPurgePAPrincipals_LockRowOnlyAfterAdmission(t *testing.T) {
	deletionDialects(t, func(t *testing.T, s *Store, base int64) {
		ctx := context.Background()
		carol, dana := base+41, base+42
		for _, p := range []int64{carol, dana} {
			uid, err := s.EnsureUserByTelegramID(ctx, p, "carol", "Carol")
			if err != nil {
				t.Fatalf("ensure: %v", err)
			}
			seedAccountForTelegramID(t, s, uid, p, nil)
			t.Cleanup(func() { _, _ = s.DB.Exec(`DELETE FROM pa_principal_locks WHERE principal = $1`, p) })
			if p == dana {
				mustAdmitPA(t, s, p)
			}
			if _, err := s.HardDeleteAccount(ctx, uid); err != nil {
				t.Fatalf("delete %d: %v", p, err)
			}
		}
		if n := paRowsIn(t, s, "pa_principal_locks", carol); n != 0 {
			t.Fatalf("%d pa_principal_locks rows of a never-admitted deleted principal, want 0", n)
		}
		if n := paRowsIn(t, s, "pa_principal_locks", dana); n != 1 {
			t.Fatalf("%d pa_principal_locks rows of an admitted deleted principal, want 1", n)
		}
		if m := paPurgeMark(t, s, dana); m <= 0 {
			t.Fatalf("deletion mark of an admitted principal = %d, want > 0", m)
		}
	})
}

// Postgres, two real transactions: an admission's lock-row insert is still
// open when an account deletion runs. The deletion's UPDATE finds no row,
// its INSERT ... DO NOTHING waits for the admission and loses to it, and it
// must go back to the UPDATE: the admitted row stays with its mark raised,
// so the Begin admitted with the old mark is fenced.
func TestPurgePAPrincipals_LostInsertToAdmissionRaisesMark(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	s := newPostgresTestStore(t, dsn)
	ctx := context.Background()
	dana := 9200000000 + (time.Now().UnixNano()/1000)%100000000 + 43
	uid, err := s.EnsureUserByTelegramID(ctx, dana, "dana", "Dana")
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	seedAccountForTelegramID(t, s, uid, dana, nil)
	t.Cleanup(func() {
		_, _ = s.DB.Exec(`DELETE FROM pa_connections WHERE principal = $1`, dana)
		_, _ = s.DB.Exec(`DELETE FROM pa_principal_locks WHERE principal = $1`, dana)
	})

	adm, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = adm.Rollback() }()
	if _, err := adm.ExecContext(ctx,
		`INSERT INTO pa_principal_locks(principal, locked_at_ms) VALUES($1, $2)
		 ON CONFLICT (principal) DO UPDATE SET locked_at_ms = excluded.locked_at_ms`,
		dana, time.Now().UnixMilli()); err != nil {
		t.Fatalf("admission insert: %v", err)
	}
	old, _, err := paAdmissionState(ctx, adm, dana)
	if err != nil || old != 0 {
		t.Fatalf("admission mark = %d, %v; want 0", old, err)
	}

	deleted := make(chan error, 1)
	go func() {
		_, err := s.HardDeleteAccount(ctx, uid)
		deleted <- err
	}()
	waitForPALockWait(t, s, "INSERT INTO pa_principal_locks(principal, locked_at_ms) VALUES($1, $2) ON CONFLICT (principal) DO NOTHING")
	if err := adm.Commit(); err != nil {
		t.Fatalf("admission commit: %v", err)
	}
	if err := <-deleted; err != nil {
		t.Fatalf("delete: %v", err)
	}
	if n := paRowsIn(t, s, "pa_principal_locks", dana); n != 1 {
		t.Fatalf("%d lock rows after the deletion, want the admitted row kept", n)
	}
	if m := paPurgeMark(t, s, dana); m <= old {
		t.Fatalf("deletion mark = %d, want it raised past the admission's %d", m, old)
	}
	c, sealed := newPAConn(dana, "pac_lost_"+randomSuffix(t))
	if err := s.CreatePAConnection(ctx, c, sealed, connection.Admission{PurgeMark: old, ReadAt: time.Now()}); !errors.Is(err, connection.ErrPrincipalDeleted) {
		t.Fatalf("Begin admitted before the deletion: %v, want ErrPrincipalDeleted", err)
	}
}

// RevokeAccountPATokens fails closed: a nil revoker, and Telegram ids that
// cannot be read, both return ErrPAConnectionsNeedRevocation, never "nothing
// to revoke", and no principal is revoked on an unreadable list.
func TestRevokeAccountPATokens_FailsClosed(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.RevokeAccountPATokens(ctx, 1, nil); !errors.Is(err, ErrPAConnectionsNeedRevocation) {
		t.Fatalf("nil revoker: %v, want ErrPAConnectionsNeedRevocation", err)
	}
	r := &fakePARevoker{s: s}
	if err := s.DB.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := s.RevokeAccountPATokens(ctx, 1, r); !errors.Is(err, ErrPAConnectionsNeedRevocation) {
		t.Fatalf("unreadable telegram ids: %v, want ErrPAConnectionsNeedRevocation", err)
	}
	if len(r.calls) != 0 {
		t.Fatalf("revoked %v on an unreadable id list, want none", r.calls)
	}
}
