package db

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestHiddenDialogs_HideListUnhide(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	alice, _ := s.EnsureUserByTelegramID(ctx, 77101, "alice", "Alice")
	bob, _ := s.EnsureUserByTelegramID(ctx, 77102, "bob", "Bob")

	if err := s.HideDialog(ctx, alice, " channel:0042 ", "News"); err != nil {
		t.Fatalf("hide: %v", err)
	}
	if err := s.HideDialog(ctx, alice, "channel:42", "Renamed"); err != nil {
		t.Fatalf("re-hide: %v", err)
	}
	if err := s.HideDialog(ctx, alice, "user:7", "Bob"); err != nil {
		t.Fatalf("hide: %v", err)
	}
	rows, err := s.ListHiddenDialogs(ctx, alice)
	if err != nil || len(rows) != 2 || rows[0] != (HiddenDialog{Peer: "user:7", Title: "Bob"}) || rows[1] != (HiddenDialog{Peer: "channel:42", Title: "Renamed"}) {
		t.Fatalf("alice rows = %+v, %v", rows, err)
	}
	if rows, err := s.ListHiddenDialogs(ctx, bob); err != nil || len(rows) != 0 {
		t.Fatalf("bob sees alice's rows: %+v, %v", rows, err)
	}
	if removed, err := s.UnhideDialog(ctx, bob, "user:7"); err != nil || removed {
		t.Fatalf("bob unhid alice's chat: %v %v", removed, err)
	}
	if removed, err := s.UnhideDialog(ctx, alice, "user:7"); err != nil || !removed {
		t.Fatalf("unhide = %v %v", removed, err)
	}
	if err := s.HideDialog(ctx, alice, "@alice", ""); err == nil {
		t.Error("a username was stored as a hidden chat")
	}
}

func TestHiddenDialogs_TitleCutOnRuneBoundary(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	carol, _ := s.EnsureUserByTelegramID(ctx, 77103, "carol", "Carol")
	if err := s.HideDialog(ctx, carol, "chat:1", strings.Repeat("ж", 300)); err != nil {
		t.Fatalf("hide: %v", err)
	}
	rows, _ := s.ListHiddenDialogs(ctx, carol)
	if len(rows) != 1 || !utf8.ValidString(rows[0].Title) || utf8.RuneCountInString(rows[0].Title) != 256 {
		t.Fatalf("title = %q", rows)
	}
}

func TestHiddenDialogs_Cap(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	dana, _ := s.EnsureUserByTelegramID(ctx, 77104, "dana", "Dana")
	for i := 1; i <= MaxHiddenDialogs; i++ {
		if err := s.HideDialog(ctx, dana, fmt.Sprintf("chat:%d", i), ""); err != nil {
			t.Fatalf("hide %d: %v", i, err)
		}
	}
	if err := s.HideDialog(ctx, dana, "chat:100000", ""); !errors.Is(err, ErrTooManyHiddenDialogs) {
		t.Fatalf("over cap = %v", err)
	}
	// Re-hiding a chat already in the list stays possible at the cap.
	if err := s.HideDialog(ctx, dana, "chat:1", "renamed"); err != nil {
		t.Fatalf("re-hide at cap: %v", err)
	}
}

// A failed read is an error, never an empty set.
func TestHiddenDialogs_FailedReadIsAnError(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	if _, err := s.DB.ExecContext(ctx, `DROP TABLE hidden_dialogs`); err != nil {
		t.Fatal(err)
	}
	if rows, err := s.ListHiddenDialogs(ctx, 1); err == nil {
		t.Fatalf("failed read returned %+v, nil", rows)
	}
}

func TestHardDeleteAccount_PurgesHiddenDialogs(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, _ := s.EnsureUserByTelegramID(ctx, 77105, "bob", "Bob")
	if err := s.HideDialog(ctx, uid, "user:9", "Carol"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.HardDeleteAccount(ctx, uid); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM hidden_dialogs WHERE user_id = $1`, uid).Scan(&n); err != nil || n != 0 {
		t.Fatalf("hidden rows after hard delete = %d, %v", n, err)
	}
}
