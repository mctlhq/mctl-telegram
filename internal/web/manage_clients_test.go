package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/auth"
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
