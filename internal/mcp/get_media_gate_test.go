package mcp

import (
	"context"
	"strings"
	"testing"
	"time"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/telegram"
)

const getMediaGateTestTGID = int64(730500001) // synthetic; not a real account

// newGetMediaGateTestServer builds a *Server with a real (in-memory) audit
// store — toolGetMedia's handler audits through s.Store.LogToolCall on every
// path, including the gate-refusal one this test exercises.
func newGetMediaGateTestServer(t *testing.T) (*Server, int64) {
	t.Helper()
	ctx := context.Background()
	conn, err := db.Open(ctx, "file:"+strings.ReplaceAll(t.Name(), "/", "_")+"?mode=memory&cache=shared", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := db.Migrate(ctx, conn); err != nil {
		t.Fatal(err)
	}
	store := db.NewStore(conn, nil)
	uid, err := store.EnsureUserByTelegramCapture(ctx, db.TelegramIdentityCapture{
		TelegramID: getMediaGateTestTGID, Username: "gatetestuser", Source: "telegram_oidc", CapturedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		Store:                 store,
		Confirms:              NewConfirmStore(),
		MediaStore:            NewMediaStore(),
		MediaDownloadMaxBytes: 1000,
	}
	return s, uid
}

// TestGetMedia_GateRefusalPreservesConfirmation (T7) verifies that when the
// media admission gate is full, get_media refuses without starting a
// download, releases the confirmation via Unclaim (not Finalize/Delete) so
// the confirmation_id remains usable, and leaves the MediaStore ref intact —
// a retry with the same confirmation_id must still find it.
func TestGetMedia_GateRefusalPreservesConfirmation(t *testing.T) {
	s, uid := newGetMediaGateTestServer(t)

	// Fill the single gate slot so get_media's own acquire times out.
	s.mediaGate = newMediaGate(1, nil)
	if err := s.mediaGate.acquire(context.Background()); err != nil {
		t.Fatalf("pre-acquiring the only slot: %v", err)
	}

	const peer = "user:12345"
	const messageID = 42
	conf, cerr := s.Confirms.Issue(uid, "media", HashMediaPayload(peer, int64(messageID)))
	if cerr != nil {
		t.Fatalf("Confirms.Issue: %v", cerr)
	}
	ref := &MediaDownloadRef{
		Peer:      peer,
		MessageID: messageID,
		MediaType: "document",
		Size:      100,
		Location:  telegram.MediaFileLocation{IsDocument: true, DocID: 1, AccessHash: 1},
	}
	s.MediaStore.Set(conf.ID, ref)

	id := &auth.Identity{UserID: uid, TelegramID: getMediaGateTestTGID, Scopes: []string{"telegram:messages:read"}}
	tool, handler := s.toolGetMedia()
	args := map[string]any{
		"peer":            peer,
		"message_id":      float64(messageID),
		"confirmation_id": conf.ID,
	}
	res, err := handler(auth.With(context.Background(), id), mcplib.CallToolRequest{Params: mcplib.CallToolParams{Name: tool.Name, Arguments: args}})
	if err != nil {
		t.Fatalf("handler returned a Go error: %v", err)
	}

	text := resultText(res)
	if !strings.Contains(text, "at capacity") {
		t.Errorf("result text = %q, want the media-capacity refusal message", text)
	}

	// The confirmation must have been released via Unclaim (not consumed):
	// a retry Claim with the same id/payload must succeed.
	if _, cerr := s.Confirms.Claim(conf.ID, uid, HashMediaPayload(peer, int64(messageID))); cerr != nil {
		t.Errorf("retry Claim after gate refusal = %v, want nil (confirmation_id must remain usable)", cerr)
	}

	// The MediaStore ref must still be present (never deleted on a gate
	// refusal — only Unclaim, which does not touch MediaStore).
	if s.MediaStore.Get(conf.ID) == nil {
		t.Error("MediaStore ref was deleted on gate refusal; it must survive for a retry")
	}
}
