//go:build livetg

// Live integration tests against real Telegram (issue #854). They are behind
// the livetg build tag and run only from the live-telegram workflow
// (.github/workflows/live-telegram.yml), on demand and after each release,
// never on a schedule or on pull requests:
//
//	TG_LIVE_API_ID=... TG_LIVE_API_HASH=... TG_LIVE_SESSION="$(cat DIR/session.json)" \
//	  go test -tags livetg -run TestLive -v ./internal/telegram/
//
// They run as one dedicated service account whose session was created once
// with cmd/ci-anchor and is kept in the TG_LIVE_SESSION secret; nothing logs
// in per run. The plan was Telegram's test datacenters, but in 2026 those
// stopped provisioning 99966XYYYY numbers and no longer deliver login codes
// to real ones, so the tests use the production DCs and touch nothing but the
// account's own Saved Messages: every message they create they also delete.
package telegram

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	gotdtelegram "github.com/gotd/td/telegram"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

type liveCreds struct {
	apiID   int
	apiHash string
	session []byte
}

func liveCredsFromEnv(t *testing.T) liveCreds {
	t.Helper()
	idStr, hash, sess := os.Getenv("TG_LIVE_API_ID"), os.Getenv("TG_LIVE_API_HASH"), os.Getenv("TG_LIVE_SESSION")
	if idStr == "" || hash == "" || sess == "" {
		t.Skip("TG_LIVE_API_ID / TG_LIVE_API_HASH / TG_LIVE_SESSION not set")
	}
	id, err := strconv.Atoi(idStr)
	if err != nil {
		t.Fatalf("TG_LIVE_API_ID: %v", err)
	}
	return liveCreds{apiID: id, apiHash: hash, session: []byte(sess)}
}

func randomSuffix(t *testing.T) string {
	t.Helper()
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("random suffix: %v", err)
	}
	return hex.EncodeToString(b)
}

// newLiveStore is an in-memory store stamped for the production DCs, holding
// the anchor session the way a hosted login leaves it. The store lives only
// for the test, so whatever the pool writes back never reaches the secret.
func newLiveStore(t *testing.T, creds liveCreds) (*db.Store, int64) {
	t.Helper()
	ctx := context.Background()
	store := newBorrowTestStore(t)
	if err := store.EnsureDCMode(ctx, db.DCModeProduction); err != nil {
		t.Fatalf("EnsureDCMode: %v", err)
	}
	uid, err := store.EnsureUser(ctx, "live-ci-"+randomSuffix(t), "", "local-dev")
	if err != nil {
		t.Fatalf("EnsureUser: %v", err)
	}
	// The Telegram id and names are filled from the session's own Self call
	// below; SaveSession only needs a non-zero id to mark the row connected.
	if err := store.SaveSession(ctx, uid, creds.session, 1, "", ""); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}
	return store, uid
}

// TestLive_MessageToolsRoundTrip runs send, edit, forward and delete through
// the client pool against the account's own Saved Messages, checking each step
// with GetMessages. The peer is the account's own @username, so it goes
// through the same ResolvePeer path a user's request does.
func TestLive_MessageToolsRoundTrip(t *testing.T) {
	creds := liveCredsFromEnv(t)
	// The repository is public and so are its Actions logs. The pool and the
	// gotd client log user and peer ids, so their output is dropped here; a
	// failure is reported through t.Fatal with message ids only.
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer slog.SetDefault(prev)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	store, uid := newLiveStore(t, creds)
	pool := NewClientPool(creds.apiID, creds.apiHash, time.Minute, store)
	defer pool.Shutdown()
	cache := NewPeerCache()
	text := "mctl live ci " + randomSuffix(t)

	// Whatever happens below, nothing the test sent may stay in Saved
	// Messages: the account is shared with the production canary. Each id is
	// deleted on its own because DeleteMessages fails closed: one id that is
	// already gone would cancel the whole batch and leave the rest behind.
	var created []int
	var peer string
	defer func() {
		if len(created) == 0 || peer == "" {
			return
		}
		cctx, ccancel := context.WithTimeout(context.Background(), time.Minute)
		defer ccancel()
		if err := pool.Borrow(cctx, uid, func(ctx context.Context, c *gotdtelegram.Client) error {
			for _, id := range created {
				if _, err := DeleteMessages(ctx, c, peer, []int{id}, cache, uid); err != nil {
					t.Logf("cleanup: message %d: %v", id, err)
				}
			}
			return nil
		}); err != nil {
			t.Errorf("cleanup: could not borrow a client to delete messages %v: %v", created, err)
		}
	}()

	err := pool.Borrow(ctx, uid, func(ctx context.Context, c *gotdtelegram.Client) error {
		self, err := c.Self(ctx)
		if err != nil {
			return fmt.Errorf("self: %w", err)
		}
		if self.Username == "" {
			return fmt.Errorf("the live account has no @username; set one so the test can address its Saved Messages")
		}
		peer = "@" + self.Username

		sent, err := SendMessage(ctx, c, peer, text, true, "", cache, uid)
		if err != nil {
			return fmt.Errorf("send: %w", err)
		}
		if !sent.Sent || sent.MessageID == 0 {
			return fmt.Errorf("send: got %+v, want a real send with a message id", sent)
		}
		created = append(created, sent.MessageID)
		if got, err := messageText(ctx, c, peer, sent.MessageID, cache, uid); err != nil || got != text {
			return fmt.Errorf("after send: text %q, err %v; want %q", got, err, text)
		}

		edited := text + " edited"
		if _, err := EditMessage(ctx, c, peer, sent.MessageID, edited, cache, uid); err != nil {
			return fmt.Errorf("edit: %w", err)
		}
		if got, err := messageText(ctx, c, peer, sent.MessageID, cache, uid); err != nil || !strings.Contains(got, edited) {
			return fmt.Errorf("after edit: text %q, err %v; want it to contain %q", got, err, edited)
		}

		fwd, err := ForwardMessages(ctx, c, peer, peer, []int{sent.MessageID}, cache, uid)
		if err != nil {
			return fmt.Errorf("forward: %w", err)
		}
		if !fwd.Forwarded || fwd.Count != 1 {
			return fmt.Errorf("forward: got %+v, want one forwarded message", fwd)
		}
		msgs, _, _, err := GetMessages(ctx, c, peer, 10, 0, cache, uid, BroadcastContentRefused)
		if err != nil {
			return fmt.Errorf("get after forward: %w", err)
		}
		var ids []int
		for _, m := range msgs {
			if strings.Contains(m.Text, edited) {
				ids = append(ids, m.ID)
			}
		}
		for _, id := range ids {
			if !slices.Contains(created, id) {
				created = append(created, id)
			}
		}
		if len(ids) != 2 {
			return fmt.Errorf("after forward: %d messages carry the text, want the original and the copy", len(ids))
		}

		del, err := DeleteMessages(ctx, c, peer, ids, cache, uid)
		if err != nil {
			return fmt.Errorf("delete: %w", err)
		}
		if !del.Deleted {
			return fmt.Errorf("delete: got %+v", del)
		}
		msgs, _, _, err = GetMessages(ctx, c, peer, 10, 0, cache, uid, BroadcastContentRefused)
		if err != nil {
			return fmt.Errorf("get after delete: %w", err)
		}
		for _, m := range msgs {
			if strings.Contains(m.Text, text) {
				return fmt.Errorf("after delete: message %d is still there", m.ID)
			}
		}
		created = nil
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// messageText returns the text of message id in peer, from the newest page.
func messageText(ctx context.Context, c *gotdtelegram.Client, peer string, id int, cache *PeerCache, uid int64) (string, error) {
	msgs, _, _, err := GetMessages(ctx, c, peer, 10, 0, cache, uid, BroadcastContentRefused)
	if err != nil {
		return "", err
	}
	for _, m := range msgs {
		if m.ID == id {
			return m.Text, nil
		}
	}
	return "", fmt.Errorf("message %d not on the newest page", id)
}
