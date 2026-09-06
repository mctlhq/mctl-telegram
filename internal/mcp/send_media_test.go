package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mctlhq/mctl-telegram/internal/auth"
)

// callSendMedia invokes the send_media handler with the given args/identity.
func callSendMedia(t *testing.T, srv *Server, id *auth.Identity, args map[string]any) *mcplib.CallToolResult {
	t.Helper()
	_, handler := srv.toolSendMedia()
	ctx := auth.With(context.Background(), id)
	res, err := handler(ctx, mcplib.CallToolRequest{Params: mcplib.CallToolParams{
		Name:      "send_media",
		Arguments: args,
	}})
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	return res
}

func parseSendMediaResult(t *testing.T, res *mcplib.CallToolResult) map[string]any {
	t.Helper()
	if res.IsError {
		t.Fatalf("expected success result, got tool error: %s", contentText(res))
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(contentText(res)), &out); err != nil {
		t.Fatalf("result is not JSON: %v (%s)", err, contentText(res))
	}
	return out
}

func sendMediaTestServer(t *testing.T, allowSend bool) *Server {
	t.Helper()
	return &Server{AllowSend: allowSend, Store: newToolsTestStore(t)}
}

func sendMediaScopedIdentity() *auth.Identity {
	return &auth.Identity{UserID: 1, Scopes: []string{"telegram:messages:send"}}
}

// --- Validation errors: no Telegram RPC and no HTTP fetch attempted. ---

func TestToolSendMedia_MissingPeer(t *testing.T) {
	srv := sendMediaTestServer(t, false)
	res := callSendMedia(t, srv, sendMediaScopedIdentity(), map[string]any{
		"media_type":  "photo",
		"file_base64": "aGk=",
	})
	if !res.IsError {
		t.Fatal("expected an error result for missing peer")
	}
}

func TestToolSendMedia_InvalidMediaType(t *testing.T) {
	srv := sendMediaTestServer(t, false)
	res := callSendMedia(t, srv, sendMediaScopedIdentity(), map[string]any{
		"peer":        "@x",
		"media_type":  "sticker",
		"file_base64": "aGk=",
	})
	if !res.IsError {
		t.Fatal("expected an error result for an invalid media_type")
	}
}

func TestToolSendMedia_BothSourcesSet(t *testing.T) {
	srv := sendMediaTestServer(t, false)
	res := callSendMedia(t, srv, sendMediaScopedIdentity(), map[string]any{
		"peer":        "@x",
		"media_type":  "photo",
		"file_base64": "aGk=",
		"file_url":    "https://example.com/f.jpg",
	})
	if !res.IsError {
		t.Fatal("expected an error result when both file_url and file_base64 are set")
	}
}

func TestToolSendMedia_NeitherSourceSet(t *testing.T) {
	srv := sendMediaTestServer(t, false)
	res := callSendMedia(t, srv, sendMediaScopedIdentity(), map[string]any{
		"peer":       "@x",
		"media_type": "photo",
	})
	if !res.IsError {
		t.Fatal("expected an error result when neither file_url nor file_base64 is set")
	}
}

func TestToolSendMedia_DocumentBase64RequiresFileName(t *testing.T) {
	srv := sendMediaTestServer(t, false)
	res := callSendMedia(t, srv, sendMediaScopedIdentity(), map[string]any{
		"peer":        "@x",
		"media_type":  "document",
		"file_base64": "aGk=",
	})
	if !res.IsError {
		t.Fatal("expected an error result for document+file_base64 without file_name")
	}
}

// TestToolSendMedia_MissingScope confirms the scope check fires eagerly,
// ahead of validation and any gate/I/O work.
func TestToolSendMedia_MissingScope(t *testing.T) {
	srv := sendMediaTestServer(t, false)
	id := &auth.Identity{UserID: 1, Scopes: []string{}}
	res := callSendMedia(t, srv, id, map[string]any{
		"peer":        "@x",
		"media_type":  "photo",
		"file_base64": "aGk=",
	})
	if !res.IsError {
		t.Fatal("expected an error result for missing telegram:messages:send scope")
	}
}

// --- Dry-run: gate closed -> sent=false, no fetch/decode attempted. ---

// TestToolSendMedia_GateBlockedReturnsDraftPreview_FileBase64 asserts that a
// valid file_base64 call, when the gate is closed, returns a dry-run preview
// without erroring — mirrors send_message's regression guard.
func TestToolSendMedia_GateBlockedReturnsDraftPreview_FileBase64(t *testing.T) {
	srv := sendMediaTestServer(t, false)
	out := parseSendMediaResult(t, callSendMedia(t, srv, sendMediaScopedIdentity(), map[string]any{
		"peer":        "@x",
		"media_type":  "photo",
		"file_base64": "aGVsbG8=",
	}))
	if out["sent"] != false {
		t.Errorf("sent = %v, want false", out["sent"])
	}
	if out["mode"] != "draft" {
		t.Errorf("mode = %v, want draft", out["mode"])
	}
	if out["dry_reason"] == nil || out["dry_reason"] == "" {
		t.Errorf("expected a dry_reason explaining the block, got %v", out["dry_reason"])
	}
	if out["media_type"] != "photo" {
		t.Errorf("media_type = %v, want photo", out["media_type"])
	}
}

// TestToolSendMedia_GateBlockedNeverFetchesURL is the key regression guard
// for requirement #4: a gate-denied call with file_url set must not attempt
// the HTTP fetch. A live httptest.Server records whether it was ever hit;
// the URL points straight at it (not through the guarded fetcher's SSRF
// checks, since this test only cares whether ANY request reached it).
func TestToolSendMedia_GateBlockedNeverFetchesURL(t *testing.T) {
	fetched := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetched = true
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	srv := sendMediaTestServer(t, false)
	out := parseSendMediaResult(t, callSendMedia(t, srv, sendMediaScopedIdentity(), map[string]any{
		"peer":       "@x",
		"media_type": "photo",
		"file_url":   ts.URL, // http://, would also fail scheme validation if ever reached
	}))
	if out["sent"] != false {
		t.Errorf("sent = %v, want false", out["sent"])
	}
	if fetched {
		t.Error("send_media must not fetch file_url when the send gate is closed")
	}
}

// TestToolSendMedia_ValidationNeverFetchesURL: a call that fails input
// validation (bad media_type here) must not attempt the file_url fetch
// either, regardless of gate state.
func TestToolSendMedia_ValidationNeverFetchesURL(t *testing.T) {
	fetched := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetched = true
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	srv := sendMediaTestServer(t, true)
	res := callSendMedia(t, srv, sendMediaScopedIdentity(), map[string]any{
		"peer":       "@x",
		"media_type": "not-a-real-type",
		"file_url":   ts.URL,
	})
	if !res.IsError {
		t.Fatal("expected a validation error")
	}
	if fetched {
		t.Error("a validation failure must not fetch file_url")
	}
}

func TestToolSendMedia_FilePathAndBase64Rejected(t *testing.T) {
	srv := sendMediaTestServer(t, false)
	res := callSendMedia(t, srv, sendMediaScopedIdentity(), map[string]any{
		"peer":        "@x",
		"media_type":  "photo",
		"file_base64": "aGk=",
		"file_path":   "/tmp/x.jpg",
	})
	if !res.IsError {
		t.Fatal("expected an error when file_path and file_base64 are both set")
	}
}

func TestToolSendMedia_GateBlockedNeverReadsFilePath(t *testing.T) {
	srv := sendMediaTestServer(t, false)
	out := parseSendMediaResult(t, callSendMedia(t, srv, sendMediaScopedIdentity(), map[string]any{
		"peer":       "@x",
		"media_type": "document",
		"file_path":  "/this/path/must/not/be/stat'd",
	}))
	if out["sent"] != false {
		t.Errorf("sent = %v, want false", out["sent"])
	}
	if out["mode"] != "draft" {
		t.Errorf("mode = %v, want draft", out["mode"])
	}
}

func TestToolSendMedia_HostedFilePathRefused(t *testing.T) {
	store := newToolsTestStore(t)
	uid := seedHostedAccount(t, store, 4242, true)
	srv := &Server{AllowSend: true, Store: store}
	id := &auth.Identity{UserID: uid, Scopes: []string{"telegram:messages:send"}}
	res := callSendMedia(t, srv, id, map[string]any{
		"peer":       "@x",
		"media_type": "document",
		"file_path":  "/etc/passwd",
	})
	if !res.IsError {
		t.Fatal("hosted file_path must be refused")
	}
	if !strings.Contains(contentText(res), "Local Bridge") {
		t.Fatalf("error = %q, want Local Bridge boundary", contentText(res))
	}
}

func TestToolSendMedia_VoiceTypeAcceptedOnDraft(t *testing.T) {
	srv := sendMediaTestServer(t, false)
	out := parseSendMediaResult(t, callSendMedia(t, srv, sendMediaScopedIdentity(), map[string]any{
		"peer":             "@x",
		"media_type":       "voice",
		"file_base64":      "T2dnUw==",
		"duration_seconds": 4,
	}))
	if out["media_type"] != "voice" {
		t.Errorf("media_type = %v, want voice", out["media_type"])
	}
	if out["sent"] != false {
		t.Errorf("sent = %v, want false", out["sent"])
	}
}

func TestToolSendMedia_DurationSecondsRejected(t *testing.T) {
	srv := sendMediaTestServer(t, false)
	for _, d := range []any{-5, 86401} {
		res := callSendMedia(t, srv, sendMediaScopedIdentity(), map[string]any{
			"peer":             "@x",
			"media_type":       "voice",
			"file_base64":      "T2dnUw==",
			"duration_seconds": d,
		})
		if !res.IsError {
			t.Fatalf("duration_seconds=%v must be rejected", d)
		}
		if !strings.Contains(contentText(res), "duration_seconds must be between 0 and 86400") {
			t.Fatalf("duration_seconds=%v: got %q", d, contentText(res))
		}
	}
}
