package telegram

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestSessionEndedLogOut(t *testing.T) {
	for name, tc := range map[string]struct {
		logOutErr error
		outcome   string
	}{
		"ok":    {nil, "ok"},
		"error": {errors.New("telegram unreachable"), "error"},
	} {
		t.Run(name, func(t *testing.T) {
			logged := make(chan string, 1)
			prev := logOutSessionFn
			logOutSessionFn = func(ctx context.Context, _ int, _ string, data []byte, _ LoginConfig) error {
				if ctx.Err() != nil {
					t.Error("logout ran on a dead context")
				}
				logged <- string(data)
				return tc.logOutErr
			}
			t.Cleanup(func() { logOutSessionFn = prev })

			counted := make(chan [2]string, 1)
			hook := SessionEndedLogOut(1, "hash", LoginConfig{}, func(reason, outcome string) {
				counted <- [2]string{reason, outcome}
			})
			hook(7, []byte("session-bytes"))

			select {
			case got := <-logged:
				if got != "session-bytes" {
					t.Errorf("logged out %q", got)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("no logout was attempted")
			}
			select {
			case got := <-counted:
				if got != [2]string{LogOutReasonSessionEnded, tc.outcome} {
					t.Errorf("counted %v", got)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("logout was not counted")
			}
		})
	}
}

// The hook runs under the client pool's lock, so it must not wait on Telegram.
func TestSessionEndedLogOut_DoesNotBlockCaller(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{})
	prev := logOutSessionFn
	logOutSessionFn = func(context.Context, int, string, []byte, LoginConfig) error {
		close(entered)
		<-release
		return nil
	}
	t.Cleanup(func() { logOutSessionFn = prev })
	t.Cleanup(func() {
		close(release)
		<-entered // the goroutine has read logOutSessionFn before it is restored
	})

	returned := make(chan struct{})
	go func() {
		SessionEndedLogOut(1, "hash", LoginConfig{}, nil)(7, []byte("x"))
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("hook blocked on the logout")
	}
}
