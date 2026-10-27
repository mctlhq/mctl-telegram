package telegram

import (
	"context"
	"errors"
	"fmt"
	"strings"
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
