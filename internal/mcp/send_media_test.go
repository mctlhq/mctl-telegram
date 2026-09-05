package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/bridge"
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

// TestToolSendMedia_ExactlyOneOfThreeSources covers the 2-way -> 3-way
// exclusivity refactor: zero, two, or three sources set must all error
// (checked ahead of the file_path hosted-mode rejection, so combinations
// involving file_path still error here for the same reason regardless of
// account mode); exactly one of file_url/file_base64 set must pass
// validation and reach the dry-run preview (gate is closed, so no I/O is
// attempted either way). file_path-alone is exercised separately below,
// since on a hosted (non-bridge) server it is rejected for a different
// reason (Local Bridge-only), not an exclusivity failure.
func TestToolSendMedia_ExactlyOneOfThreeSources(t *testing.T) {
	cases := []struct {
		name      string
		args      map[string]any
		wantError bool
	}{
		{"none", map[string]any{}, true},
		{"url+base64", map[string]any{"file_url": "https://example.com/f.jpg", "file_base64": "aGk="}, true},
		{"url+path", map[string]any{"file_url": "https://example.com/f.jpg", "file_path": "/tmp/f.jpg"}, true},
		{"base64+path", map[string]any{"file_base64": "aGk=", "file_path": "/tmp/f.jpg"}, true},
		{"all three", map[string]any{"file_url": "https://example.com/f.jpg", "file_base64": "aGk=", "file_path": "/tmp/f.jpg"}, true},
		{"url only", map[string]any{"file_url": "https://example.com/f.jpg"}, false},
		{"base64 only", map[string]any{"file_base64": "aGk="}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := sendMediaTestServer(t, false)
			args := map[string]any{"peer": "@x", "media_type": "photo"}
			for k, v := range tc.args {
				args[k] = v
			}
			res := callSendMedia(t, srv, sendMediaScopedIdentity(), args)
			if res.IsError != tc.wantError {
				t.Errorf("IsError = %v, want %v (result: %s)", res.IsError, tc.wantError, contentText(res))
			}
		})
	}
}

// TestToolSendMedia_FilePathAloneRejectedOnHostedServer: file_path is the
// sole source, exclusivity passes, but the server has no Hub (hosted mode)
// — this must still error, for the Local-Bridge-only reason, not an
// exclusivity reason. Points file_path at a path guaranteed not to exist so
// any accidental read would surface as a different, filesystem-shaped
// error rather than this validation error.
func TestToolSendMedia_FilePathAloneRejectedOnHostedServer(t *testing.T) {
	srv := sendMediaTestServer(t, true)
	res := callSendMedia(t, srv, sendMediaScopedIdentity(), map[string]any{
		"peer":       "@x",
		"media_type": "photo",
		"file_path":  "/nonexistent/for-test-only",
	})
	if !res.IsError {
		t.Fatal("expected an error result for file_path on a hosted (non-bridge) server")
	}
}

// TestToolSendMedia_FilePathAloneAllowedForLocalBridgeAccount: same input,
// but the account resolves to Local Bridge mode — validation must pass and
// the call falls through to the (gate-closed) dry-run preview, not an
// error. The gate stays closed (AllowSend=false) so this never actually
// reaches the bridge call.
func TestToolSendMedia_FilePathAloneAllowedForLocalBridgeAccount(t *testing.T) {
	store := newToolsTestStore(t)
	uid := seedLocalAccount(t, store, 8001)
	srv := &Server{Store: store, Hub: bridge.NewHub(), AllowSend: false}
	id := &auth.Identity{UserID: uid, Scopes: []string{"telegram:messages:send"}}

	out := parseSendMediaResult(t, callSendMedia(t, srv, id, map[string]any{
		"peer":       "@x",
		"media_type": "photo",
		"file_path":  "/nonexistent/for-test-only",
	}))
	if out["sent"] != false {
		t.Errorf("sent = %v, want false", out["sent"])
	}
}

// TestToolSendMedia_FilePathDerivesFileName: when file_path is the source
// and file_name is omitted, the dry-run preview's file_name must be the
// path's basename. Uses a Local Bridge account (gate closed) so file_path
// clears the hosted-mode rejection and the call reaches the preview.
func TestToolSendMedia_FilePathDerivesFileName(t *testing.T) {
	store := newToolsTestStore(t)
	uid := seedLocalAccount(t, store, 8003)
	srv := &Server{Store: store, Hub: bridge.NewHub(), AllowSend: false}
	id := &auth.Identity{UserID: uid, Scopes: []string{"telegram:messages:send"}}

	out := parseSendMediaResult(t, callSendMedia(t, srv, id, map[string]any{
		"peer":       "@x",
		"media_type": "photo",
		"file_path":  "/nonexistent/dir/report.pdf",
	}))
	if out["file_name"] != filepath.Base("/nonexistent/dir/report.pdf") {
		t.Errorf("file_name = %v, want %q", out["file_name"], "report.pdf")
	}
}

// TestToolSendMedia_FilePathWindowsDerivesBaseName: the daemon also ships for
// windows/amd64, so file_path can be a Windows path. This server is compiled
// for Linux, where filepath.Base would leave it unsplit — the derived preview
// name must still be just the basename, never the caller's full local path.
func TestToolSendMedia_FilePathWindowsDerivesBaseName(t *testing.T) {
	store := newToolsTestStore(t)
	uid := seedLocalAccount(t, store, 8005)
	srv := &Server{Store: store, Hub: bridge.NewHub(), AllowSend: false}
	id := &auth.Identity{UserID: uid, Scopes: []string{"telegram:messages:send"}}

	out := parseSendMediaResult(t, callSendMedia(t, srv, id, map[string]any{
		"peer":       "@x",
		"media_type": "photo",
		"file_path":  `C:\Users\Alice\Pictures\cat.jpg`,
	}))
	if out["file_name"] != "cat.jpg" {
		t.Errorf("file_name = %v, want %q", out["file_name"], "cat.jpg")
	}
}

// TestToolSendMedia_FilePathDocumentNoFileNameNoLongerErrors: unlike
// file_base64, media_type=document with file_path and no file_name must
// NOT error — the basename derivation satisfies the document-name rule.
func TestToolSendMedia_FilePathDocumentNoFileNameNoLongerErrors(t *testing.T) {
	store := newToolsTestStore(t)
	uid := seedLocalAccount(t, store, 8004)
	srv := &Server{Store: store, Hub: bridge.NewHub(), AllowSend: false}
	id := &auth.Identity{UserID: uid, Scopes: []string{"telegram:messages:send"}}

	res := callSendMedia(t, srv, id, map[string]any{
		"peer":       "@x",
		"media_type": "document",
		"file_path":  "/nonexistent/dir/report.pdf",
	})
	if res.IsError {
		t.Fatalf("document+file_path without file_name should not error, got: %s", contentText(res))
	}
}

// TestToolSendMedia_GateBlockedNeverReadsFilePath is the file_path analogue
// of TestToolSendMedia_GateBlockedNeverFetchesURL: a gate-denied call with
// file_path set on a Local Bridge account must never attempt a filesystem
// read. Points file_path at a path guaranteed not to exist so any
// accidental read would surface as a different, filesystem-shaped error
// rather than the expected dry-run preview. Uses a Local Bridge account
// (rather than sendMediaTestServer's hosted/no-Hub setup) so the gate check
// — not the unrelated hosted-mode rejection — is what's under test here.
func TestToolSendMedia_GateBlockedNeverReadsFilePath(t *testing.T) {
	store := newToolsTestStore(t)
	uid := seedLocalAccount(t, store, 8002)
	srv := &Server{Store: store, Hub: bridge.NewHub(), AllowSend: false}
	id := &auth.Identity{UserID: uid, Scopes: []string{"telegram:messages:send"}}

	out := parseSendMediaResult(t, callSendMedia(t, srv, id, map[string]any{
		"peer":       "@x",
		"media_type": "photo",
		"file_path":  "/nonexistent/for-test-only",
	}))
	if out["sent"] != false {
		t.Errorf("sent = %v, want false", out["sent"])
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
