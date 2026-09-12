package mcp

import (
	"context"
	"encoding/json"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

func callGetMyIdentity(t *testing.T, srv *Server, id *auth.Identity) *mcplib.CallToolResult {
	t.Helper()
	_, handler := srv.toolGetMyIdentity()
	ctx := context.Background()
	if id != nil {
		ctx = auth.With(ctx, id)
	}
	res, err := handler(ctx, mcplib.CallToolRequest{Params: mcplib.CallToolParams{
		Name: "get_my_identity",
	}})
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	return res
}

func TestGetMyIdentity_ReturnsCallerOnly(t *testing.T) {
	store := newToolsTestStore(t)
	ctx := context.Background()
	uid, err := store.EnsureUserByTelegramID(ctx, 888, "me", "My Name")
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if _, err := store.EnsureUserByTelegramID(ctx, 999, "other", "Someone Else"); err != nil {
		t.Fatalf("ensure other: %v", err)
	}
	srv := &Server{Store: store}
	res := callGetMyIdentity(t, srv, &auth.Identity{UserID: uid, TelegramID: 888})
	if res.IsError {
		t.Fatalf("tool error: %s", contentText(res))
	}
	var out myIdentityResult
	if err := json.Unmarshal([]byte(contentText(res)), &out); err != nil {
		t.Fatalf("json: %v (%s)", err, contentText(res))
	}
	if out.TelegramID != 888 || out.Username != "me" || out.DisplayName != "My Name" {
		t.Fatalf("got %+v, want telegram_id=888 username=me display_name=My Name", out)
	}
}

// TestGetMyIdentity_CapturedUserReturnsProvenance covers T7's captured-user
// half: once CaptureTelegramIdentity has run for the row, the tool returns
// the new attributes and reports them verified/not_supplied per attribute.
func TestGetMyIdentity_CapturedUserReturnsProvenance(t *testing.T) {
	store := newToolsTestStore(t)
	ctx := context.Background()
	uid, err := store.EnsureUserByTelegramID(ctx, 777, "alice", "Alice")
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if err := store.CaptureTelegramIdentity(ctx, uid, db.TelegramIdentityAttrs{
		Username:    "alice",
		FirstName:   "Alice",
		DisplayName: "Alice",
		// LastName and LanguageCode deliberately omitted -> not_supplied.
	}); err != nil {
		t.Fatalf("capture: %v", err)
	}

	srv := &Server{Store: store}
	res := callGetMyIdentity(t, srv, &auth.Identity{UserID: uid, TelegramID: 777})
	if res.IsError {
		t.Fatalf("tool error: %s", contentText(res))
	}
	var out myIdentityResult
	if err := json.Unmarshal([]byte(contentText(res)), &out); err != nil {
		t.Fatalf("json: %v (%s)", err, contentText(res))
	}
	if out.FirstName != "Alice" {
		t.Errorf("FirstName = %q, want %q", out.FirstName, "Alice")
	}
	if out.Provenance.FirstName != db.ProvenanceVerified {
		t.Errorf("FirstName provenance = %q, want %q", out.Provenance.FirstName, db.ProvenanceVerified)
	}
	if out.Provenance.LastName != db.ProvenanceNotSupplied {
		t.Errorf("LastName provenance = %q, want %q", out.Provenance.LastName, db.ProvenanceNotSupplied)
	}
	if out.Provenance.LanguageCode != db.ProvenanceNotSupplied {
		t.Errorf("LanguageCode provenance = %q, want %q", out.Provenance.LanguageCode, db.ProvenanceNotSupplied)
	}
}

// TestGetMyIdentity_LegacyUserReadsNotCaptured covers T7's legacy-user half:
// a row that has never gone through CaptureTelegramIdentity reads
// not_captured for every optional attribute, not an empty/misleading
// not_supplied.
func TestGetMyIdentity_LegacyUserReadsNotCaptured(t *testing.T) {
	store := newToolsTestStore(t)
	ctx := context.Background()
	uid, err := store.EnsureUserByTelegramID(ctx, 778, "bob", "Bob")
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}

	srv := &Server{Store: store}
	res := callGetMyIdentity(t, srv, &auth.Identity{UserID: uid, TelegramID: 778})
	if res.IsError {
		t.Fatalf("tool error: %s", contentText(res))
	}
	var out myIdentityResult
	if err := json.Unmarshal([]byte(contentText(res)), &out); err != nil {
		t.Fatalf("json: %v (%s)", err, contentText(res))
	}
	if out.Provenance.FirstName != db.ProvenanceNotCaptured {
		t.Errorf("FirstName provenance = %q, want %q", out.Provenance.FirstName, db.ProvenanceNotCaptured)
	}
	if out.Provenance.LastName != db.ProvenanceNotCaptured {
		t.Errorf("LastName provenance = %q, want %q", out.Provenance.LastName, db.ProvenanceNotCaptured)
	}
	if out.Provenance.OnboardingCompletedAt != db.ProvenanceNotCaptured {
		t.Errorf("OnboardingCompletedAt provenance = %q, want %q", out.Provenance.OnboardingCompletedAt, db.ProvenanceNotCaptured)
	}
}

func TestGetMyIdentity_RequiresAuth(t *testing.T) {
	res := callGetMyIdentity(t, &Server{}, nil)
	if !res.IsError {
		t.Fatal("unauthenticated call must fail")
	}
}

func TestGetMyIdentity_NoIdentityIsError(t *testing.T) {
	res := callGetMyIdentity(t, &Server{}, &auth.Identity{UserID: 1})
	if !res.IsError {
		t.Fatal("session without Telegram identity must fail")
	}
}
