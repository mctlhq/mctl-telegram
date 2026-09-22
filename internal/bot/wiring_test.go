package bot

import (
	"context"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

// TestKnownChatFunc is the gatekeeper deciding whether an inbound update is
// dispatched or dropped as unknown_chat, so each of its branches is pinned
// here. The receiver tests use an in-memory stub, which never exercises this.
func TestKnownChatFunc(t *testing.T) {
	ctx := context.Background()
	store := newBotTestStore(t)
	known := KnownChatFunc(store)

	uid, err := store.EnsureUserByTelegramID(ctx, 4242, "alice", "Alice Example")
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if uid == 0 {
		t.Fatal("seed returned user id 0")
	}

	t.Run("known chat", func(t *testing.T) {
		ok, err := known(ctx, 4242)
		if err != nil {
			t.Fatalf("err = %v", err)
		}
		if !ok {
			t.Error("a signed-in client's chat was reported unknown; their messages would be dropped")
		}
	})

	t.Run("unknown chat is not an error", func(t *testing.T) {
		// Anyone can message a public bot, so this is the ordinary case and
		// must not surface as an error -- an error would leave the update
		// pending and retry it forever.
		ok, err := known(ctx, 999999)
		if err != nil {
			t.Fatalf("err = %v, want nil for an ordinary unknown sender", err)
		}
		if ok {
			t.Error("an unknown chat was reported known")
		}
	})

	t.Run("non-positive chat ids", func(t *testing.T) {
		// Group and channel ids are negative; 0 is not a chat. The login bot
		// is a 1:1 surface, so neither is a chat we act on.
		for _, id := range []int64{0, -1, -1001234567890} {
			ok, err := known(ctx, id)
			if err != nil {
				t.Errorf("chat %d: err = %v, want nil", id, err)
			}
			if ok {
				t.Errorf("chat %d reported known; the bot would act on a group", id)
			}
		}
	})

	t.Run("ambiguous identity is not treated as known", func(t *testing.T) {
		// Two users carrying the same Telegram id is a data problem. Acting on
		// it would mean guessing which account the message belongs to.
		other, err := store.EnsureUser(ctx, "bob", "", "test")
		if err != nil {
			t.Fatalf("seed second user: %v", err)
		}
		if _, err := store.DB.ExecContext(ctx,
			`INSERT INTO telegram_accounts(user_id, telegram_user_id, session_encrypted)
			 VALUES($1,$2,$3)`, other, 4242, []byte("blob"),
		); err != nil {
			t.Fatalf("seed ambiguity: %v", err)
		}

		// Confirm the store really does report ambiguity, so this test cannot
		// pass for the wrong reason.
		if _, err := store.UserIDByTelegramID(ctx, 4242); err == nil {
			t.Skip("store no longer reports this shape as ambiguous")
		} else if !strings.Contains(err.Error(), "ambiguous") {
			t.Skipf("store reported %v, not ambiguity", err)
		}

		ok, err := known(ctx, 4242)
		if err != nil {
			t.Errorf("err = %v, want nil -- ambiguity is a drop, not a retry loop", err)
		}
		if ok {
			t.Error("an ambiguous telegram id was reported known")
		}
	})

	t.Run("a real database error propagates", func(t *testing.T) {
		// Distinct from "unknown": a failing lookup must not be silently read
		// as an unknown sender, or a database outage would drop every inbound
		// update and count them as spam.
		broken := newBotTestStore(t)
		if _, err := broken.DB.Exec(`DROP TABLE telegram_accounts`); err != nil {
			t.Fatalf("drop: %v", err)
		}
		if _, err := broken.DB.Exec(`DROP TABLE users`); err != nil {
			t.Fatalf("drop users: %v", err)
		}
		if _, err := KnownChatFunc(broken)(ctx, 4242); err == nil {
			t.Error("a broken lookup reported a clean unknown instead of an error")
		}
	})
}

// TestNewMetricsCounter_NilRegistry: the receiver must tolerate running without
// metrics rather than panicking on a nil registry.
func TestNewMetricsCounter_NilRegistry(t *testing.T) {
	if c := NewMetricsCounter(nil); c != nil {
		t.Errorf("NewMetricsCounter(nil) = %v, want nil", c)
	}
	// And a receiver with a nil counter does not panic when counting.
	r := NewReceiver(newBotTestStore(t), NewRegistry(nil), nil, "", Options{})
	r.count(db.KindMessage, db.OutcomeHandled)
}
