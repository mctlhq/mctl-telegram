package web

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/canaryguard"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

func getManageBody(t *testing.T, srv *ManageServer, id *auth.Identity) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/telegram/connect/manage", nil)
	req = req.WithContext(auth.With(req.Context(), id))
	rec := httptest.NewRecorder()
	srv.HandleManage(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d; body=%s", rec.Code, rec.Body.String())
	}
	return rec.Body.String()
}

// TestManagePage_SignedInAndClients: the page names the account it is signed
// in as and lists the AI clients holding a live grant for that account, with
// help for a client signed in as someone else (#749).
func TestManagePage_SignedInAndClients(t *testing.T) {
	ctx := context.Background()
	store := newManageTestStore(t)
	uid, err := store.EnsureUserByTelegramID(ctx, 4201, "carol", "Carol")
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	for i, tok := range []string{"carol-claude-1", "carol-claude-2"} {
		if err := store.SaveRefreshToken(ctx, tok, db.RefreshToken{
			FamilyID: tok, UserID: uid, ClientID: "claude.ai", ClientName: "Claude",
			TelegramID: 4201, ExpiresAt: time.Now().Add(time.Duration(i+1) * 24 * time.Hour),
		}); err != nil {
			t.Fatalf("save: %v", err)
		}
	}
	srv := NewManageServer(store, nil, "https://tg.test", "", "")
	body := getManageBody(t, srv, &auth.Identity{UserID: uid, TelegramID: 4201})

	for _, want := range []string{
		`id="signed-in"`, "Carol", "(@carol)",
		`id="clients"`, ">Claude<", "2 sign-ins",
		`id="wrong-account"`, "get_my_identity",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("manage page lacks %q", want)
		}
	}
	if strings.Contains(body, `id="clients-none"`) || strings.Contains(body, `id="clients-unknown"`) {
		t.Error("client list marked empty or unknown although a grant exists")
	}
}

func TestManagePage_NoClientsIsSaidPlainly(t *testing.T) {
	ctx := context.Background()
	store := newManageTestStore(t)
	uid, err := store.EnsureUserByTelegramID(ctx, 4202, "dana", "Dana")
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	body := getManageBody(t, NewManageServer(store, nil, "https://tg.test", "", ""), &auth.Identity{UserID: uid, TelegramID: 4202})
	if !strings.Contains(body, `id="clients-none"`) {
		t.Error("an account with no grants is not shown as having none")
	}
}

// An unreadable client list is unknown, never "no clients".
func TestManagePage_UnreadableClientsAreUnknown(t *testing.T) {
	ctx := context.Background()
	store := newManageTestStore(t)
	uid, err := store.EnsureUserByTelegramID(ctx, 4203, "bob", "Bob")
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if _, err := store.DB.ExecContext(ctx, `DROP TABLE oauth_refresh_tokens`); err != nil {
		t.Fatalf("drop: %v", err)
	}
	body := getManageBody(t, NewManageServer(store, nil, "https://tg.test", "", ""), &auth.Identity{UserID: uid, TelegramID: 4203})
	if !strings.Contains(body, `id="clients-unknown"`) {
		t.Error("failed client read not shown as unknown")
	}
	if strings.Contains(body, `id="clients-none"`) {
		t.Error("failed client read shown as no clients")
	}
	if !strings.Contains(body, `id="signed-in"`) {
		t.Error("a failed client read hid the sign-in identity")
	}
}

// An account without a @handle stores its display name as the username; the
// page must not show it again as a handle.
func TestManagePage_NoHandleIsNotShownAsOne(t *testing.T) {
	ctx := context.Background()
	store := newManageTestStore(t)
	uid, err := store.EnsureUserByTelegramID(ctx, 4204, "Carol", "Carol")
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	body := getManageBody(t, NewManageServer(store, nil, "https://tg.test", "", ""), &auth.Identity{UserID: uid, TelegramID: 4204})
	if !strings.Contains(body, `id="signed-in"`) || !strings.Contains(body, "Carol") {
		t.Fatal("sign-in row missing")
	}
	if strings.Contains(body, "(@Carol)") {
		t.Error("display name shown as a @handle")
	}
}

// TestManagePage_NamelessSignInFallsBackToTheID covers an identity with
// neither a display name nor a handle: the row must still say who is signed
// in rather than render empty.
func TestManagePage_NamelessSignInFallsBackToTheID(t *testing.T) {
	ctx := context.Background()
	store := newManageTestStore(t)
	uid, err := store.EnsureUserByTelegramID(ctx, 4205, "", "")
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	body := getManageBody(t, NewManageServer(store, nil, "https://tg.test", "", ""), &auth.Identity{UserID: uid, TelegramID: 4205})
	if !strings.Contains(body, `id="signed-in"`) || !strings.Contains(body, "Telegram id 4205") {
		t.Error("nameless sign-in does not fall back to the Telegram id")
	}
}

func seedGrant(t *testing.T, store *db.Store, tok string, uid int64, client string) {
	t.Helper()
	if err := store.SaveRefreshToken(context.Background(), tok, db.RefreshToken{
		FamilyID: tok, UserID: uid, ClientID: client, ClientName: client,
		TelegramID: 4299, ExpiresAt: time.Now().Add(24 * time.Hour),
	}); err != nil {
		t.Fatalf("save %s: %v", tok, err)
	}
}

func postRevokeClient(t *testing.T, srv *ManageServer, id *auth.Identity, clientID string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/telegram/connect/manage/revoke-client",
		strings.NewReader("client_id="+clientID))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(auth.With(req.Context(), id))
	rec := httptest.NewRecorder()
	srv.HandleRevokeClient(rec, req)
	return rec
}

func revokedState(t *testing.T, store *db.Store, tok string) bool {
	t.Helper()
	rt, err := store.LookupRefreshToken(context.Background(), tok)
	if err != nil {
		t.Fatalf("lookup %s: %v", tok, err)
	}
	return rt.Revoked()
}

// TestHandleRevokeClient: the browser sign-in revokes one client's grants
// for its own account only; another user's grant for the same client and
// the account's other clients stay live.
func TestHandleRevokeClient(t *testing.T) {
	ctx := context.Background()
	store := newManageTestStore(t)
	alice, _ := store.EnsureUserByTelegramID(ctx, 4211, "alice", "Alice")
	bob, _ := store.EnsureUserByTelegramID(ctx, 4212, "bob", "Bob")
	seedGrant(t, store, "alice-claude", alice, "claude.ai")
	seedGrant(t, store, "alice-gpt", alice, "chatgpt")
	seedGrant(t, store, "bob-claude", bob, "claude.ai")
	srv := NewManageServer(store, nil, "https://tg.test", "", "mctl_self_connect")
	browser := &auth.Identity{UserID: alice, TelegramID: 4211, ClientID: "mctl_self_connect"}

	rec := postRevokeClient(t, srv, browser, "claude.ai")
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "https://tg.test/telegram/connect/manage?revoked=1#clients" {
		t.Fatalf("revoke = %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if !revokedState(t, store, "alice-claude") {
		t.Error("alice's claude.ai grant still live")
	}
	if revokedState(t, store, "alice-gpt") {
		t.Error("alice's other client was revoked too")
	}
	if revokedState(t, store, "bob-claude") {
		t.Error("another user's grant for the same client was revoked")
	}

	// A client this account holds nothing for revokes nothing.
	rec = postRevokeClient(t, srv, browser, "never-connected")
	if rec.Header().Get("Location") != "https://tg.test/telegram/connect/manage?revoked=0#clients" {
		t.Fatalf("revoke of an absent client = %q", rec.Header().Get("Location"))
	}
}

// A credential that may not disconnect may not revoke either.
func TestHandleRevokeClient_RefusedWithoutOwnerCredential(t *testing.T) {
	ctx := context.Background()
	store := newManageTestStore(t)
	alice, _ := store.EnsureUserByTelegramID(ctx, 4213, "alice", "Alice")
	seedGrant(t, store, "alice-claude-2", alice, "claude.ai")
	srv := NewManageServer(store, nil, "https://tg.test", "", "mctl_self_connect")
	rec := postRevokeClient(t, srv, &auth.Identity{UserID: alice, TelegramID: 4213, ClientID: "claude.ai"}, "claude.ai")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if revokedState(t, store, "alice-claude-2") {
		t.Error("a refused revoke revoked the grant")
	}
	body := getManageBody(t, srv, &auth.Identity{UserID: alice, TelegramID: 4213, ClientID: "claude.ai"})
	if strings.Contains(body, "manage/revoke-client") {
		t.Error("revoke button offered to a credential the handler refuses")
	}
}

// The page says plainly that a revoked client keeps its current access token,
// quoting the configured lifetime.
func TestManagePage_RevokeExplainsTheAccessTokenWindow(t *testing.T) {
	ctx := context.Background()
	store := newManageTestStore(t)
	alice, _ := store.EnsureUserByTelegramID(ctx, 4214, "alice", "Alice")
	seedGrant(t, store, "alice-claude-3", alice, "claude.ai")
	srv := NewManageServer(store, nil, "https://tg.test", "", "mctl_self_connect").WithAccessTokenTTL(30 * time.Minute)
	body := getManageBody(t, srv, &auth.Identity{UserID: alice, TelegramID: 4214, ClientID: "mctl_self_connect"})
	for _, want := range []string{`action="/telegram/connect/manage/revoke-client"`, `value="claude.ai"`, `id="revoke-effect"`, "for up to 30 minutes"} {
		if !strings.Contains(body, want) {
			t.Errorf("manage page lacks %q", want)
		}
	}
	if got := NewManageServer(store, nil, "", "", "").accessTokenTTLText(); got != "1 hour" {
		t.Errorf("default TTL text = %q, want 1 hour", got)
	}
}

func latestManageAuditTool(t *testing.T, store *db.Store, uid int64) string {
	t.Helper()
	var tool string
	err := store.DB.QueryRowContext(context.Background(),
		`SELECT tool_name FROM audit_logs WHERE user_id = $1 ORDER BY id DESC LIMIT 1`, uid).Scan(&tool)
	if err != nil && err != sql.ErrNoRows {
		t.Fatalf("latest audit: %v", err)
	}
	return tool
}

// TestHandleRevokeClient_CanaryAsksFirst: on the monitoring canary, the first
// Revoke only asks again; the confirmed one revokes and is audited as an
// override, like Disconnect (#961).
func TestHandleRevokeClient_CanaryAsksFirst(t *testing.T) {
	ctx := context.Background()
	store := newManageTestStore(t)
	dana, _ := store.EnsureUserByTelegramID(ctx, 4215, "dana", "Dana")
	seedGrant(t, store, "dana-claude", dana, "claude.ai")
	srv := NewManageServer(store, nil, "https://tg.test", "", "mctl_self_connect").
		WithCanaryGuard(canaryguard.Set{4215: {}})
	browser := &auth.Identity{UserID: dana, TelegramID: 4215, ClientID: "mctl_self_connect"}

	rec := postRevokeClient(t, srv, browser, "claude.ai")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `name="confirm_canary" value="1"`) ||
		!strings.Contains(rec.Body.String(), `name="client_id" value="claude.ai"`) {
		t.Fatalf("first press: status %d, want the confirmation form; body=%s", rec.Code, rec.Body.String())
	}
	if revokedState(t, store, "dana-claude") {
		t.Fatal("the first press revoked the canary's client")
	}
	if tool := latestManageAuditTool(t, store, dana); strings.HasPrefix(tool, "POST /telegram/connect/manage/revoke-client") {
		t.Fatalf("the first press was audited as a revoke: %q", tool)
	}

	req := httptest.NewRequest(http.MethodPost, "/telegram/connect/manage/revoke-client",
		strings.NewReader("client_id=claude.ai&confirm_canary=1"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(auth.With(req.Context(), browser))
	rec = httptest.NewRecorder()
	srv.HandleRevokeClient(rec, req)
	if rec.Code != http.StatusFound || !revokedState(t, store, "dana-claude") {
		t.Fatalf("confirmed press: status %d, revoked=%v", rec.Code, revokedState(t, store, "dana-claude"))
	}
	if tool := latestManageAuditTool(t, store, dana); tool != "POST /telegram/connect/manage/revoke-client"+canaryguard.OverrideSuffix {
		t.Fatalf("audit tool = %q, want the override recorded", tool)
	}
}
