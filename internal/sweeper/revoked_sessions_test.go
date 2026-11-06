package sweeper

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/crypto"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/telegram"
)

type fakeSession struct {
	Key string `json:"key"`
}

func sessionBytes(t *testing.T, key string) []byte {
	t.Helper()
	b, err := json.Marshal(fakeSession{Key: key})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func fakeKeyID(data []byte) (string, error) {
	if string(data) == "malformed" {
		return "", errors.New("malformed")
	}
	var s fakeSession
	if err := json.Unmarshal(data, &s); err != nil {
		return "", err
	}
	if s.Key == "" {
		return "", telegram.ErrNoAuthKey
	}
	return s.Key, nil
}

var errAlreadyEnded = errors.New("401")

type logOutRecorder struct {
	keys []string
	err  error
}

func (r *logOutRecorder) deps() RevokedSessionDeps {
	return RevokedSessionDeps{
		LogOut: func(_ context.Context, data []byte) error {
			k, _ := fakeKeyID(data)
			r.keys = append(r.keys, k)
			return r.err
		},
		KeyID:        fakeKeyID,
		AlreadyEnded: func(err error) bool { return errors.Is(err, errAlreadyEnded) },
	}
}

func newRevokedStore(t *testing.T) *db.Store {
	t.Helper()
	ctx := context.Background()
	conn, err := db.Open(ctx, "file:"+t.TempDir()+"/t.db", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := db.MigrateCached(ctx, conn); err != nil {
		t.Fatal(err)
	}
	c, err := crypto.New(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	return db.NewStore(conn, c)
}

// addRow inserts a telegram_accounts row. revoked=false makes it active.
func addRow(t *testing.T, s *db.Store, tg int64, data []byte, revoked bool, reason any) int64 {
	t.Helper()
	ctx := context.Background()
	uid, err := s.EnsureUserByTelegramID(ctx, tg, "", "")
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := s.Crypt.SealForUser(data, uid)
	if err != nil {
		t.Fatal(err)
	}
	var id int64
	var revokedAt any
	if revoked {
		revokedAt = "2026-10-01 00:00:00"
	}
	if err := s.DB.QueryRow(
		`INSERT INTO telegram_accounts(user_id, telegram_user_id, session_encrypted, revoked_at, revoked_reason)
		 VALUES($1,$2,$3,$4,$5) RETURNING id`, uid, tg, sealed, revokedAt, reason).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func hasBlob(t *testing.T, s *db.Store, id int64) bool {
	t.Helper()
	var b []byte
	if err := s.DB.QueryRow(`SELECT session_encrypted FROM telegram_accounts WHERE id=$1`, id).Scan(&b); err != nil {
		t.Fatal(err)
	}
	return b != nil
}

func TestCleanRevokedSessions_LogsOutOnlyTheReasonsThatNeedIt(t *testing.T) {
	cases := []struct {
		reason     any
		wantLogOut bool
	}{
		{nil, true},
		{"disconnect", true},
		{"superseded", true},
		{"idle_expiry", false},
		{"absolute_expiry", false},
		{"unauthorized", false},
		{"login_incomplete", false},
	}
	for i, c := range cases {
		s := newRevokedStore(t)
		id := addRow(t, s, int64(1000+i), sessionBytes(t, "k"), true, c.reason)
		rec := &logOutRecorder{}
		res, err := CleanRevokedSessions(context.Background(), s, rec.deps())
		if err != nil {
			t.Fatal(err)
		}
		if got := len(rec.keys) == 1; got != c.wantLogOut {
			t.Errorf("reason %v: logged out = %v, want %v", c.reason, got, c.wantLogOut)
		}
		if hasBlob(t, s, id) || res.Erased != 1 || res.Failed != 0 {
			t.Errorf("reason %v: blob kept or res = %+v", c.reason, res)
		}
	}
}

func TestCleanRevokedSessions_KeyStillInUseIsNotLoggedOut(t *testing.T) {
	s := newRevokedStore(t)
	revoked := addRow(t, s, 2001, sessionBytes(t, "shared"), true, "superseded")
	active := addRow(t, s, 2001, sessionBytes(t, "shared"), false, nil)
	rec := &logOutRecorder{}
	res, err := CleanRevokedSessions(context.Background(), s, rec.deps())
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.keys) != 0 || res.SharedKey != 1 {
		t.Fatalf("logged out %v, res %+v: this would end a session in use", rec.keys, res)
	}
	if hasBlob(t, s, revoked) || !hasBlob(t, s, active) {
		t.Fatal("must erase the revoked copy and keep the active session")
	}
}

func TestCleanRevokedSessions_DifferentActiveKeyStillLogsOut(t *testing.T) {
	s := newRevokedStore(t)
	addRow(t, s, 2002, sessionBytes(t, "old"), true, "superseded")
	addRow(t, s, 2002, sessionBytes(t, "new"), false, nil)
	rec := &logOutRecorder{}
	if _, err := CleanRevokedSessions(context.Background(), s, rec.deps()); err != nil {
		t.Fatal(err)
	}
	if len(rec.keys) != 1 || rec.keys[0] != "old" {
		t.Fatalf("logged out %v, want only the old key", rec.keys)
	}
}

func TestCleanRevokedSessions_FailedLogOutKeepsTheSessionForRetry(t *testing.T) {
	s := newRevokedStore(t)
	id := addRow(t, s, 2003, sessionBytes(t, "k"), true, "disconnect")
	rec := &logOutRecorder{err: errors.New("network down")}
	res, err := CleanRevokedSessions(context.Background(), s, rec.deps())
	if err != nil {
		t.Fatal(err)
	}
	if !hasBlob(t, s, id) || res.Failed != 1 || res.Erased != 0 {
		t.Fatalf("res = %+v, blob must stay", res)
	}
	rec.err = nil
	if _, err := CleanRevokedSessions(context.Background(), s, rec.deps()); err != nil {
		t.Fatal(err)
	}
	if hasBlob(t, s, id) {
		t.Fatal("the retry must erase after a successful logout")
	}
}

func TestCleanRevokedSessions_KeyAlreadyDeadIsErased(t *testing.T) {
	s := newRevokedStore(t)
	id := addRow(t, s, 2004, sessionBytes(t, "k"), true, "superseded")
	rec := &logOutRecorder{err: errAlreadyEnded}
	if _, err := CleanRevokedSessions(context.Background(), s, rec.deps()); err != nil {
		t.Fatal(err)
	}
	if hasBlob(t, s, id) {
		t.Fatal("a key Telegram no longer accepts has nothing left to end")
	}
}

func TestCleanRevokedSessions_UnreadableSessionsAreKept(t *testing.T) {
	s := newRevokedStore(t)
	malformed := addRow(t, s, 2005, []byte("malformed"), true, "disconnect")
	revoked := addRow(t, s, 2006, sessionBytes(t, "a"), true, "disconnect")
	addRow(t, s, 2006, []byte("malformed"), false, nil)
	undecryptable := addRow(t, s, 2007, sessionBytes(t, "b"), true, "disconnect")
	if _, err := s.DB.Exec(`UPDATE telegram_accounts SET user_id=(SELECT id FROM users WHERE telegram_login_id=2005) WHERE id=$1`, undecryptable); err != nil {
		t.Fatal(err)
	}
	rec := &logOutRecorder{}
	res, err := CleanRevokedSessions(context.Background(), s, rec.deps())
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.keys) != 0 || res.Failed != 3 || res.Erased != 0 {
		t.Fatalf("logged out %v, res %+v", rec.keys, res)
	}
	for _, id := range []int64{malformed, revoked, undecryptable} {
		if !hasBlob(t, s, id) {
			t.Errorf("row %d lost its session without proof it is safe", id)
		}
	}
}

func TestCleanRevokedSessions_NoAuthKeyIsErasedWithoutLogOut(t *testing.T) {
	s := newRevokedStore(t)
	id := addRow(t, s, 2008, sessionBytes(t, ""), true, nil)
	rec := &logOutRecorder{}
	if _, err := CleanRevokedSessions(context.Background(), s, rec.deps()); err != nil {
		t.Fatal(err)
	}
	if len(rec.keys) != 0 || hasBlob(t, s, id) {
		t.Fatalf("logged out %v", rec.keys)
	}
}

func TestEraseRevokedSession_LeavesAnActiveRowAlone(t *testing.T) {
	s := newRevokedStore(t)
	id := addRow(t, s, 2009, sessionBytes(t, "k"), false, sql.NullString{})
	if err := s.EraseRevokedSession(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if !hasBlob(t, s, id) {
		t.Fatal("an active session must never be erased")
	}
}
