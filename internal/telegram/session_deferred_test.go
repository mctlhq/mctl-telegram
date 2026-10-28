package telegram

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/gotd/td/session"
	"github.com/gotd/td/tg"
	"github.com/gotd/td/tgerr"
)

// recordingStorage is a session.Storage that records every write and serves a
// fixed row on load, standing in for the database-backed SessionStore.
type recordingStorage struct {
	row    []byte
	writes [][]byte
	// fail, when set, is returned by every write after recording it.
	fail error
}

func (r *recordingStorage) LoadSession(context.Context) ([]byte, error) {
	if r.row == nil {
		return nil, session.ErrNotFound
	}
	return r.row, nil
}

func (r *recordingStorage) StoreSession(_ context.Context, data []byte) error {
	r.writes = append(r.writes, data)
	return r.fail
}

// TestDeferredSession_MismatchWritesNothing pins #901's criterion 2: a QR
// login that signs in to another account writes no session bytes to the
// store at any point, and logs that new authorization out. The two
// StoreSession calls stand in for gotd saving the auth key on connect and
// again after the scan, both before the account is known.
func TestDeferredSession_MismatchWritesNothing(t *testing.T) {
	ctx := context.Background()
	target := &recordingStorage{row: []byte("existing-good-session")}
	sess := &deferredSession{target: target}

	_ = sess.StoreSession(ctx, []byte("auth-key-on-connect"))
	_ = sess.StoreSession(ctx, []byte("auth-key-after-scan"))
	api := &fakeLogOuter{}
	mismatch := logOutIfMismatch(ctx, api, 1, 4242, 4343)
	if err := sess.settle(ctx, mismatch); err != nil {
		t.Fatalf("settle: %v", err)
	}

	if len(target.writes) != 0 {
		t.Errorf("store writes on a mismatch = %d, want 0", len(target.writes))
	}
	if api.calls != 1 {
		t.Errorf("auth.logOut calls = %d, want 1", api.calls)
	}
}

// TestDeferredSession_MatchWritesLatestOnce: for the expected account the
// buffered session reaches the store exactly once, as its latest bytes.
func TestDeferredSession_MatchWritesLatestOnce(t *testing.T) {
	ctx := context.Background()
	target := &recordingStorage{}
	sess := &deferredSession{target: target}

	_ = sess.StoreSession(ctx, []byte("auth-key-on-connect"))
	_ = sess.StoreSession(ctx, []byte("auth-key-after-scan"))
	api := &fakeLogOuter{}
	mismatch := logOutIfMismatch(ctx, api, 1, 4242, 4242)
	if err := sess.settle(ctx, mismatch); err != nil {
		t.Fatalf("settle: %v", err)
	}

	if len(target.writes) != 1 || !bytes.Equal(target.writes[0], []byte("auth-key-after-scan")) {
		t.Errorf("store writes = %q, want exactly the latest bytes once", target.writes)
	}
	if api.calls != 0 {
		t.Errorf("auth.logOut calls = %d, want 0", api.calls)
	}
}

// TestDeferredSession_NothingBufferedIsAnError keeps the old "no session
// bytes were persisted" sanity check: a login that reports success without
// gotd ever saving a session must not pass as one.
func TestDeferredSession_NothingBufferedIsAnError(t *testing.T) {
	target := &recordingStorage{}
	sess := &deferredSession{target: target}
	if err := sess.settle(context.Background(), false); err == nil {
		t.Fatal("settle with nothing buffered = nil, want an error")
	}
	if len(target.writes) != 0 {
		t.Errorf("store writes = %d, want 0", len(target.writes))
	}
}

// TestDeferredSession_StartsFromAFreshKey: the login must never load the
// user's existing row, or a mismatched account's logOut would end the auth
// key that row holds (#913 describes that gap on the phone path).
func TestDeferredSession_StartsFromAFreshKey(t *testing.T) {
	ctx := context.Background()
	sess := &deferredSession{target: &recordingStorage{row: []byte("existing-good-session")}}

	if _, err := sess.LoadSession(ctx); !errors.Is(err, session.ErrNotFound) {
		t.Fatalf("first load err = %v, want session.ErrNotFound", err)
	}
	_ = sess.StoreSession(ctx, []byte("new-auth-key"))
	got, err := sess.LoadSession(ctx)
	if err != nil || !bytes.Equal(got, []byte("new-auth-key")) {
		t.Errorf("load after store = %q, %v; want the buffered bytes", got, err)
	}
}

// TestSettleQRLogin_UnfinishedRunWritesNothing: a run that never signed in
// leaves the user's row alone, whatever it ended with. The buffered bytes
// stand in for the unauthorized auth key gotd saves on connect. The
// cancelled case is the one gotd returns for a connection failure under
// the callback while the caller's ctx is still live.
func TestSettleQRLogin_UnfinishedRunWritesNothing(t *testing.T) {
	for name, runErr := range map[string]error{
		"cancelled under a live ctx": fmt.Errorf("qr auth: %w", context.Canceled),
		"no error and no sign-in":    nil,
		"expired":                    fmt.Errorf("qr auth: %w", ErrQRLoginExpired),
	} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			target := &recordingStorage{row: []byte("existing-good-session")}
			sess := &deferredSession{target: target}
			_ = sess.StoreSession(ctx, []byte("unauthorized-auth-key"))

			if err := settleLogin(ctx, "qr login", sess, runErr, false, false, nil); err == nil {
				t.Error("settleLogin = nil, want an error for a run that never signed in")
			}
			if len(target.writes) != 0 {
				t.Errorf("store writes = %d, want 0", len(target.writes))
			}
		})
	}
}

// TestSettleQRLogin_SignedIn: a completed sign-in writes once, even when the
// client's shutdown reports context.Canceled, and a mismatch writes nothing.
func TestSettleQRLogin_SignedIn(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name       string
		runErr     error
		mismatch   bool
		wantWrites int
	}{
		{"clean", nil, false, 1},
		{"cancelled on shutdown", context.Canceled, false, 1},
		{"mismatch", nil, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := &recordingStorage{}
			sess := &deferredSession{target: target}
			_ = sess.StoreSession(ctx, []byte("signed-in-session"))
			if err := settleLogin(ctx, "qr login", sess, tc.runErr, true, tc.mismatch, nil); err != nil {
				t.Fatalf("settleLogin: %v", err)
			}
			if len(target.writes) != tc.wantWrites {
				t.Errorf("store writes = %d, want %d", len(target.writes), tc.wantWrites)
			}
		})
	}
}

// TestAcceptQRAuth_ReportsAcceptanceFirst: OnQRAccepted fires once, before
// the account check's auth.logOut, for the expected account and for another.
func TestAcceptQRAuth_ReportsAcceptanceFirst(t *testing.T) {
	for _, got := range []int64{4242, 4343} {
		api := &fakeLogOuter{}
		hooks, logOutsAtHook := 0, -1
		cfg := LoginConfig{WantTelegramID: 4242, OnQRAccepted: func() {
			hooks++
			logOutsAtHook = api.calls
		}}
		authz := &tg.AuthAuthorization{User: &tg.User{ID: got}}

		user, mismatch, err := acceptQRAuth(context.Background(), api, cfg, 1, authz)
		if err != nil || user.ID != got || mismatch != (got != 4242) {
			t.Fatalf("got=%d: acceptQRAuth = %v, %v, %v", got, user, mismatch, err)
		}
		if hooks != 1 || logOutsAtHook != 0 {
			t.Errorf("got=%d: OnQRAccepted calls=%d, logOuts before it=%d; want 1 and 0", got, hooks, logOutsAtHook)
		}
	}
}

// recordLogOuts replaces logOutSessionFn for the test and returns the
// session bytes of each logout it was asked for.
func recordLogOuts(t *testing.T) *[][]byte {
	t.Helper()
	var got [][]byte
	prev := logOutSessionFn
	logOutSessionFn = func(ctx context.Context, _ int, _ string, data []byte, _ LoginConfig) error {
		if ctx.Err() != nil {
			t.Error("logout ran on a dead context")
		}
		got = append(got, data)
		return nil
	}
	t.Cleanup(func() { logOutSessionFn = prev })
	return &got
}

// TestFinishQRLogin_ScannedButUnfinishedIsLoggedOut pins #919: a run that
// fails after the code was scanned, here cancelled under a cancelled
// caller, writes nothing and logs out the authorization its buffered auth
// key may carry, on a context that is still alive.
func TestFinishQRLogin_ScannedButUnfinishedIsLoggedOut(t *testing.T) {
	logOuts := recordLogOuts(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	target := &recordingStorage{row: []byte("existing-good-session")}
	sess := &deferredSession{target: target}
	_ = sess.StoreSession(ctx, []byte("scanned-auth-key"))

	err := finishLogin(ctx, "qr login", 1, "hash", LoginConfig{}, 1, sess, fmt.Errorf("qr auth: %w", context.Canceled), true, false, false)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want the run's context.Canceled", err)
	}
	if len(target.writes) != 0 {
		t.Errorf("store writes = %d, want 0", len(target.writes))
	}
	if len(*logOuts) != 1 || string((*logOuts)[0]) != "scanned-auth-key" {
		t.Errorf("logouts = %q, want the scanned auth key once", *logOuts)
	}
}

// TestFinishQRLogin_NoLogOutWithoutAScanOrOnSuccess: an unscanned run has
// nothing to log out, a mismatch was logged out by the account check, and a
// completed run hands its bytes to HoldSession without writing them.
func TestFinishQRLogin_NoLogOutWithoutAScanOrOnSuccess(t *testing.T) {
	ctx := context.Background()
	logOuts := recordLogOuts(t)
	for _, tc := range []struct {
		name                        string
		runErr                      error
		scanned, signedIn, mismatch bool
		hold, wantErr               bool
	}{
		{"expired, never scanned", ErrQRLoginExpired, false, false, false, false, true},
		{"mismatch", nil, true, true, true, false, false},
		{"signed in, held", nil, true, true, false, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := &recordingStorage{}
			sess := &deferredSession{target: target}
			_ = sess.StoreSession(ctx, []byte("auth-key"))
			var held []byte
			cfg := LoginConfig{}
			if tc.hold {
				cfg.HoldSession = func(b []byte) { held = b }
			}
			err := finishLogin(ctx, "qr login", 1, "hash", cfg, 1, sess, tc.runErr, tc.scanned, tc.signedIn, tc.mismatch)
			if (err != nil) != tc.wantErr {
				t.Errorf("err = %v, want error %v", err, tc.wantErr)
			}
			if len(target.writes) != 0 {
				t.Errorf("store writes = %d, want 0", len(target.writes))
			}
			if tc.hold && string(held) != "auth-key" {
				t.Errorf("held = %q, want the session bytes", held)
			}
		})
	}
	if len(*logOuts) != 0 {
		t.Errorf("logouts = %d, want 0", len(*logOuts))
	}
}

// TestFinishLogin_FailedWriteIsLoggedOut: on the path that writes the session
// itself (cmd/login, no HoldSession), a write that fails after a matched
// sign-in leaves an authorization nobody holds. settle gives the bytes back,
// so finishLogin logs that authorization out instead of dropping it.
func TestFinishLogin_FailedWriteIsLoggedOut(t *testing.T) {
	logOuts := recordLogOuts(t)
	ctx := context.Background()
	target := &recordingStorage{fail: errors.New("database is locked")}
	sess := &deferredSession{target: target}
	_ = sess.StoreSession(ctx, []byte("signed-in-auth-key"))

	err := finishLogin(ctx, "login", 1, "hash", LoginConfig{}, 1, sess, nil, true, true, false)
	if err == nil || !strings.Contains(err.Error(), "database is locked") {
		t.Errorf("err = %v, want the failed write", err)
	}
	if len(target.writes) != 1 {
		t.Errorf("store writes = %d, want the one failed attempt", len(target.writes))
	}
	if len(*logOuts) != 1 || string((*logOuts)[0]) != "signed-in-auth-key" {
		t.Errorf("logouts = %q, want the signed-in auth key once", *logOuts)
	}
}

func TestWithQRWait(t *testing.T) {
	waitForCtx := func(ctx context.Context) (*tg.AuthAuthorization, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}

	t.Run("no scan in time", func(t *testing.T) {
		_, err := withQRWait(context.Background(), 20*time.Millisecond, waitForCtx)
		if !errors.Is(err, ErrQRLoginExpired) {
			t.Errorf("err = %v, want ErrQRLoginExpired", err)
		}
	})
	t.Run("caller cancelled first", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := withQRWait(ctx, time.Minute, waitForCtx)
		if errors.Is(err, ErrQRLoginExpired) || !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v, want the caller's context.Canceled", err)
		}
	})
	t.Run("password needed passes through", func(t *testing.T) {
		pw := tgerr.New(401, "SESSION_PASSWORD_NEEDED")
		_, err := withQRWait(context.Background(), time.Minute, func(context.Context) (*tg.AuthAuthorization, error) {
			return nil, pw
		})
		if !tgerr.Is(err, "SESSION_PASSWORD_NEEDED") {
			t.Errorf("err = %v, want SESSION_PASSWORD_NEEDED unchanged", err)
		}
	})
	t.Run("no limit", func(t *testing.T) {
		want := &tg.AuthAuthorization{}
		got, err := withQRWait(context.Background(), 0, func(ctx context.Context) (*tg.AuthAuthorization, error) {
			if _, ok := ctx.Deadline(); ok {
				t.Error("a zero QRWait set a deadline")
			}
			return want, nil
		})
		if err != nil || got != want {
			t.Errorf("got %v, %v", got, err)
		}
	})
}
