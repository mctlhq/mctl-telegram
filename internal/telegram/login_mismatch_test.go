package telegram

import (
	"context"
	"errors"
	"testing"

	"github.com/gotd/td/tg"
)

type fakeLogOuter struct {
	calls int
	err   error
}

func (f *fakeLogOuter) AuthLogOut(context.Context) (*tg.AuthLoggedOut, error) {
	f.calls++
	return &tg.AuthLoggedOut{}, f.err
}

// TestLogOutIfMismatch pins #899: an account other than the expected one is
// logged out, so it is not left with a live device it never meant to add.
func TestLogOutIfMismatch(t *testing.T) {
	cases := []struct {
		name      string
		want, got int64
		logOutErr error
		mismatch  bool
	}{
		{"different account", 4242, 4343, nil, true},
		{"logout fails, still a mismatch", 4242, 4343, errors.New("rpc error"), true},
		{"expected account", 4242, 4242, nil, false},
		{"no expectation", 0, 4343, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			api := &fakeLogOuter{err: tc.logOutErr}
			got := logOutIfMismatch(context.Background(), api, 1, tc.want, tc.got)
			if got != tc.mismatch {
				t.Errorf("mismatch = %v, want %v", got, tc.mismatch)
			}
			wantCalls := 0
			if tc.mismatch {
				wantCalls = 1
			}
			if api.calls != wantCalls {
				t.Errorf("auth.logOut calls = %d, want %d", api.calls, wantCalls)
			}
		})
	}
}
