package telegram

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"unicode/utf8"

	"github.com/gotd/td/tg"
	"github.com/gotd/td/tgerr"
)

func TestRenderQR(t *testing.T) {
	url := "tg://login?token=dGVzdA"
	got := renderQR(url)

	if got == "" {
		t.Fatal("renderQR returned empty string")
	}
	lines := strings.Split(strings.TrimRight(got, "\n"), "\n")
	if len(lines) < 5 {
		t.Errorf("renderQR returned too few lines: %d", len(lines))
	}
	// All lines in a QR render must have the same rune count.
	// Each module is 2 runes wide (either "██" or "  "), so byte counts differ
	// between dark and light rows — compare rune counts instead.
	width := utf8.RuneCountInString(lines[0])
	for i, l := range lines {
		if utf8.RuneCountInString(l) != width {
			t.Errorf("line %d has %d runes, want %d", i, utf8.RuneCountInString(l), width)
		}
	}
	// Width must be even (each module = 2 rune-wide chars).
	if width%2 != 0 {
		t.Errorf("renderQR width %d runes is not even", width)
	}
	// Result contains at least one dark module marker.
	if !strings.Contains(got, "\xe2\x96\x88\xe2\x96\x88") { // "██" UTF-8
		t.Error("renderQR output contains no dark modules")
	}
}

func TestRenderQR_ErrorFallback(t *testing.T) {
	// Empty URL is invalid for QR encoding but should not panic.
	got := renderQR("")
	if got == "" {
		t.Error("renderQR with empty URL returned empty string (expected fallback message)")
	}
}

func TestPasswordAfterQR(t *testing.T) {
	ctx := context.Background()
	needed := fmt.Errorf("import: %w", tgerr.New(401, "SESSION_PASSWORD_NEEDED"))
	want := &tg.AuthAuthorization{User: &tg.User{ID: 4242}}
	ask := func(context.Context) (string, error) { return "hunter2", nil }

	t.Run("2FA account checks the password", func(t *testing.T) {
		var got string
		authz, err := passwordAfterQR(ctx, needed, ask, func(_ context.Context, pw string) (*tg.AuthAuthorization, error) {
			got = pw
			return want, nil
		})
		if err != nil || authz != want || got != "hunter2" {
			t.Fatalf("authz=%v err=%v checked=%q", authz, err, got)
		}
	})

	t.Run("other errors pass through without a prompt", func(t *testing.T) {
		other := errors.New("qr token expired")
		asked := false
		_, err := passwordAfterQR(ctx, other, func(context.Context) (string, error) {
			asked = true
			return "", nil
		}, nil)
		if !errors.Is(err, other) || asked {
			t.Fatalf("err=%v asked=%v", err, asked)
		}
	})

	t.Run("no prompt keeps the Telegram error", func(t *testing.T) {
		_, err := passwordAfterQR(ctx, needed, nil, nil)
		if err == nil || !tgerr.Is(err, "SESSION_PASSWORD_NEEDED") {
			t.Fatalf("err=%v", err)
		}
	})

	t.Run("wrong password is asked again in the same flow", func(t *testing.T) {
		inputs := []string{"hunter1", "hunter2"}
		var seen []Reprompt
		askTwice := func(ctx context.Context) (string, error) {
			rp, _ := RepromptFrom(ctx)
			seen = append(seen, rp)
			return inputs[len(seen)-1], nil
		}
		authz, err := passwordAfterQR(ctx, needed, askTwice, func(_ context.Context, pw string) (*tg.AuthAuthorization, error) {
			if pw != "hunter2" {
				return nil, fmt.Errorf("check: %w", tgerr.New(400, "PASSWORD_HASH_INVALID"))
			}
			return want, nil
		})
		if err != nil || authz != want {
			t.Fatalf("authz=%v err=%v", authz, err)
		}
		if len(seen) != 2 || seen[1] != (Reprompt{Reason: RepromptBadPassword, AttemptsLeft: 2}) {
			t.Fatalf("prompts saw %v", seen)
		}
	})

	t.Run("wrong password fails", func(t *testing.T) {
		bad := errors.New("PASSWORD_HASH_INVALID")
		_, err := passwordAfterQR(ctx, needed, ask, func(context.Context, string) (*tg.AuthAuthorization, error) {
			return nil, bad
		})
		if !errors.Is(err, bad) {
			t.Fatalf("err=%v", err)
		}
	})
}

// TestLoginTokenSignal_KeptWhileAuthIsBusy: an updateLoginToken that arrives
// while qr.Auth is not parked in its select (exporting a token, or inside the
// show callback) must still be seen when it gets back there. An unbuffered
// non-blocking send drops it, and the accepted scan then goes unnoticed.
func TestLoginTokenSignal_KeptWhileAuthIsBusy(t *testing.T) {
	var scanned atomic.Bool
	loggedIn, onLoginToken := loginTokenSignal(&scanned)

	// Nobody is receiving: the handler runs while Auth is busy. A second
	// update coalesces rather than blocking the dispatcher.
	for range 2 {
		if err := onLoginToken(context.Background(), tg.Entities{}, &tg.UpdateLoginToken{}); err != nil {
			t.Fatalf("handler: %v", err)
		}
	}
	if !scanned.Load() {
		t.Error("the scan was not recorded")
	}
	select {
	case <-loggedIn:
	default:
		t.Fatal("the login token update was lost while Auth was busy")
	}
}

// TestOnScanReported: the scan hook runs once, after the wrapped handler,
// however many updateLoginToken updates arrive; a nil hook leaves the
// handler as it is (#931).
func TestOnScanReported(t *testing.T) {
	var handled, hooked int
	h := onScanReported(func(context.Context, tg.Entities, *tg.UpdateLoginToken) error {
		handled++
		if handled == 1 && hooked != 0 {
			t.Error("hook ran before the wrapped handler")
		}
		return nil
	}, func() { hooked++ })
	for range 3 {
		if err := h(context.Background(), tg.Entities{}, &tg.UpdateLoginToken{}); err != nil {
			t.Fatal(err)
		}
	}
	if handled != 3 || hooked != 1 {
		t.Errorf("handled=%d hooked=%d, want 3 and 1", handled, hooked)
	}
	if onScanReported(nil, nil) != nil {
		t.Error("a nil hook must return the handler unchanged")
	}
}
