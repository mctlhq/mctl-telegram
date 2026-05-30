package telegram

import (
	"testing"

	"github.com/gotd/td/tg"
)

// TestSeedPeerCache verifies that dialog entities are cached under the canonical
// peer specs WITH their access_hash — the core of the get_messages
// PEER_ID_INVALID / CHANNEL_INVALID fix.
func TestSeedPeerCache(t *testing.T) {
	users := map[int64]*tg.User{
		42: {ID: 42, AccessHash: 1111},
	}
	chats := map[int64]tg.ChatClass{
		100: &tg.Channel{ID: 100, AccessHash: 2222},
		200: &tg.Chat{ID: 200}, // basic group: no access hash
	}

	pc := NewPeerCache()
	seedPeerCache(pc, 7, users, chats)

	t.Run("user carries access hash", func(t *testing.T) {
		got, ok := pc.Get(7, "user:42")
		if !ok {
			t.Fatal("expected cache hit for user:42")
		}
		u, ok := got.(*tg.InputPeerUser)
		if !ok {
			t.Fatalf("got %T, want *tg.InputPeerUser", got)
		}
		if u.UserID != 42 || u.AccessHash != 1111 {
			t.Errorf("got {UserID:%d AccessHash:%d}, want {42 1111}", u.UserID, u.AccessHash)
		}
	})

	t.Run("channel carries access hash", func(t *testing.T) {
		got, ok := pc.Get(7, "channel:100")
		if !ok {
			t.Fatal("expected cache hit for channel:100")
		}
		ch, ok := got.(*tg.InputPeerChannel)
		if !ok {
			t.Fatalf("got %T, want *tg.InputPeerChannel", got)
		}
		if ch.ChannelID != 100 || ch.AccessHash != 2222 {
			t.Errorf("got {ChannelID:%d AccessHash:%d}, want {100 2222}", ch.ChannelID, ch.AccessHash)
		}
	})

	t.Run("basic group needs no access hash", func(t *testing.T) {
		got, ok := pc.Get(7, "chat:200")
		if !ok {
			t.Fatal("expected cache hit for chat:200")
		}
		if _, ok := got.(*tg.InputPeerChat); !ok {
			t.Fatalf("got %T, want *tg.InputPeerChat", got)
		}
	})
}

// TestSeedPeerCache_SkipsZeroHash verifies that zero-access-hash entities are
// not seeded and never overwrite a valid hash already in the cache.
func TestSeedPeerCache_SkipsZeroHash(t *testing.T) {
	pc := NewPeerCache()
	// Pre-seed valid hashes as if resolved earlier via username.
	pc.Set(7, "user:42", &tg.InputPeerUser{UserID: 42, AccessHash: 9999})
	pc.Set(7, "channel:100", &tg.InputPeerChannel{ChannelID: 100, AccessHash: 8888})

	// A dialog scan returns "min" objects with no access hash.
	users := map[int64]*tg.User{42: {ID: 42, AccessHash: 0}}
	chats := map[int64]tg.ChatClass{100: &tg.Channel{ID: 100, AccessHash: 0}}
	seedPeerCache(pc, 7, users, chats)

	if got, _ := pc.Get(7, "user:42"); got.(*tg.InputPeerUser).AccessHash != 9999 {
		t.Errorf("user hash overwritten by zero-hash min object: %v", got)
	}
	if got, _ := pc.Get(7, "channel:100"); got.(*tg.InputPeerChannel).AccessHash != 8888 {
		t.Errorf("channel hash overwritten by zero-hash min object: %v", got)
	}
}

// TestSeedPeerCache_SkipsMin verifies that "min" entities — whose access hash is
// non-zero but unusable for messages.* APIs — are not seeded and never overwrite
// a valid hash already in the cache.
func TestSeedPeerCache_SkipsMin(t *testing.T) {
	pc := NewPeerCache()
	pc.Set(7, "user:42", &tg.InputPeerUser{UserID: 42, AccessHash: 9999})
	pc.Set(7, "channel:100", &tg.InputPeerChannel{ChannelID: 100, AccessHash: 8888})

	// Min objects with a (non-zero) limited-context access hash.
	users := map[int64]*tg.User{42: {ID: 42, Min: true, AccessHash: 1234}}
	chats := map[int64]tg.ChatClass{100: &tg.Channel{ID: 100, Min: true, AccessHash: 5678}}
	seedPeerCache(pc, 7, users, chats)

	if got, _ := pc.Get(7, "user:42"); got.(*tg.InputPeerUser).AccessHash != 9999 {
		t.Errorf("min user overwrote a valid cached hash: %v", got)
	}
	if got, _ := pc.Get(7, "channel:100"); got.(*tg.InputPeerChannel).AccessHash != 8888 {
		t.Errorf("min channel overwrote a valid cached hash: %v", got)
	}
}

func TestSeedPeerCache_NoOp(t *testing.T) {
	users := map[int64]*tg.User{42: {ID: 42, AccessHash: 1}}

	// nil cache must not panic.
	seedPeerCache(nil, 7, users, nil)

	// userID == 0 must not seed (no caller identity).
	pc := NewPeerCache()
	seedPeerCache(pc, 0, users, nil)
	if _, ok := pc.Get(0, "user:42"); ok {
		t.Error("expected no seeding when userID is 0")
	}
}
