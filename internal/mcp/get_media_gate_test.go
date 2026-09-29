package mcp

import (
	"context"
	"strings"
	"testing"
	"time"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/metrics"
	"github.com/mctlhq/mctl-telegram/internal/telegram"
	"github.com/prometheus/client_golang/prometheus/testutil"
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
	withMediaGateWait(t, 50*time.Millisecond)

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

// TestGetMedia_GateCancelledContextIsNotCapacity pins that a caller whose
// context ends while waiting for a gate slot is not reported, counted or
// audited as a capacity refusal: MediaGateRejectionsTotal must measure
// saturation, not client disconnects. The confirmation must still survive.
func TestGetMedia_GateCancelledContextIsNotCapacity(t *testing.T) {
	s, uid := newGetMediaGateTestServer(t)
	reg := metrics.New()
	s.Metrics = reg

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
	s.MediaStore.Set(conf.ID, &MediaDownloadRef{
		Peer:      peer,
		MessageID: messageID,
		MediaType: "document",
		Size:      100,
		Location:  telegram.MediaFileLocation{IsDocument: true, DocID: 1, AccessHash: 1},
	})

	id := &auth.Identity{UserID: uid, TelegramID: getMediaGateTestTGID, Scopes: []string{"telegram:messages:read"}}
	ctx, cancel := context.WithCancel(auth.With(context.Background(), id))
	cancel()
	tool, handler := s.toolGetMedia()
	res, err := handler(ctx, mcplib.CallToolRequest{Params: mcplib.CallToolParams{Name: tool.Name, Arguments: map[string]any{
		"peer":            peer,
		"message_id":      float64(messageID),
		"confirmation_id": conf.ID,
	}}})
	if err != nil {
		t.Fatalf("handler returned a Go error: %v", err)
	}
	if !res.IsError {
		t.Fatal("expected an error result for a cancelled context")
	}
	if text := resultText(res); strings.Contains(text, "at capacity") {
		t.Errorf("result text = %q; a cancelled caller must not be told the gate is at capacity", text)
	}
	if got := testutil.ToFloat64(reg.MediaGateRejectionsTotal.WithLabelValues("get_media")); got != 0 {
		t.Errorf("MediaGateRejectionsTotal{get_media} = %v, want 0 for a cancelled caller", got)
	}
	if _, cerr := s.Confirms.Claim(conf.ID, uid, HashMediaPayload(peer, int64(messageID))); cerr != nil {
		t.Errorf("retry Claim after cancelled wait = %v, want nil (confirmation_id must remain usable)", cerr)
	}
}

// TestMediaGateRefused_PerToolLabels covers the refusal path shared by all
// three gated tools (get_media is exercised end to end above; get_messages
// and get_unread_messages reach the gate only after a live history fetch, so
// their handlers call this same function and it is pinned here directly):
// errMediaBusy is counted under the tool's own label and reported as
// capacity; a context error is neither counted nor reported as capacity.
func TestMediaGateRefused_PerToolLabels(t *testing.T) {
	for _, tool := range []string{"get_messages", "get_unread_messages", "get_media"} {
		t.Run(tool, func(t *testing.T) {
			s, uid := newGetMediaGateTestServer(t)
			reg := metrics.New()
			s.Metrics = reg
			id := &auth.Identity{UserID: uid, TelegramID: getMediaGateTestTGID}
			ctx := auth.With(context.Background(), id)

			res := s.mediaGateRefused(ctx, id, tool, "user:<redacted>", errMediaBusy, time.Now())
			if !res.IsError || !strings.Contains(resultText(res), "at capacity") {
				t.Errorf("busy refusal = %q, want the capacity message", resultText(res))
			}
			if got := testutil.ToFloat64(reg.MediaGateRejectionsTotal.WithLabelValues(tool)); got != 1 {
				t.Errorf("MediaGateRejectionsTotal{%s} after busy = %v, want 1", tool, got)
			}

			cctx, cancel := context.WithCancel(ctx)
			cancel()
			res = s.mediaGateRefused(cctx, id, tool, "user:<redacted>", cctx.Err(), time.Now())
			if !res.IsError || strings.Contains(resultText(res), "at capacity") {
				t.Errorf("cancelled refusal = %q, want an error that is not the capacity message", resultText(res))
			}
			if got := testutil.ToFloat64(reg.MediaGateRejectionsTotal.WithLabelValues(tool)); got != 1 {
				t.Errorf("MediaGateRejectionsTotal{%s} after cancel = %v, want still 1", tool, got)
			}
		})
	}
}
