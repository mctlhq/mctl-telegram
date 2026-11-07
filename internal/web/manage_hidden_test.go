package web

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/auth"
)

const hiddenTestConnect = "mctl_self_connect"

func postHidden(t *testing.T, srv *ManageServer, id *auth.Identity, hide bool, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	path, h := "/telegram/connect/manage/show-chat", srv.HandleShowChat
	if hide {
		path, h = "/telegram/connect/manage/hide-chat", srv.HandleHideChat
	}
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(auth.With(req.Context(), id))
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

func getPicker(t *testing.T, srv *ManageServer, id *auth.Identity) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/telegram/connect/manage/hidden-chats", nil)
	req = req.WithContext(auth.With(req.Context(), id))
	rec := httptest.NewRecorder()
	srv.HandleHiddenChats(rec, req)
	return rec
}

// TestHiddenChats_BrowserHidesAndShows: the browser sign-in hides a chat,
// sees it listed by name, and shows it again.
func TestHiddenChats_BrowserHidesAndShows(t *testing.T) {
	ctx := context.Background()
	store := newManageTestStore(t)
	alice, _ := store.EnsureUserByTelegramID(ctx, 4231, "alice", "Alice")
	srv := NewManageServer(store, nil, "https://tg.test", "", hiddenTestConnect)
	browser := &auth.Identity{UserID: alice, TelegramID: 4231, ClientID: hiddenTestConnect}

	rec := postHidden(t, srv, browser, true, url.Values{"peer": {"channel:777"}, "title": {"Bob's channel"}})
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "https://tg.test/telegram/connect/manage?hidden=hidden#hidden" {
		t.Fatalf("hide = %d %q", rec.Code, rec.Header().Get("Location"))
	}
	rows, err := store.ListHiddenDialogs(ctx, alice)
	if err != nil || len(rows) != 1 || rows[0].Peer != "channel:777" {
		t.Fatalf("hidden rows = %+v, %v", rows, err)
	}
	body := getManageBody(t, srv, browser)
	if !strings.Contains(body, `id="hidden"`) || !strings.Contains(body, "Bob&#39;s channel") {
		t.Errorf("manage page does not list the hidden chat:\n%s", body)
	}
	if strings.Contains(body, `id="hidden-none"`) {
		t.Error("a hidden chat exists but the page says none")
	}

	rec = postHidden(t, srv, browser, false, url.Values{"peer": {"channel:777"}, "back": {"picker"}})
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "https://tg.test/telegram/connect/manage/hidden-chats" {
		t.Fatalf("show = %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if rows, _ := store.ListHiddenDialogs(ctx, alice); len(rows) != 0 {
		t.Fatalf("still hidden after show: %+v", rows)
	}
	rec = postHidden(t, srv, browser, false, url.Values{"peer": {"channel:777"}})
	if got := rec.Header().Get("Location"); got != "https://tg.test/telegram/connect/manage?hidden=unchanged#hidden" {
		t.Fatalf("show of a visible chat = %q", got)
	}
}

// TestHiddenChats_AIClientCannotReadOrChange: an AI client's bearer token
// reaches the manage routes, but it may neither see which chats are hidden
// from it nor show them again.
func TestHiddenChats_AIClientCannotReadOrChange(t *testing.T) {
	ctx := context.Background()
	store := newManageTestStore(t)
	alice, _ := store.EnsureUserByTelegramID(ctx, 4232, "alice", "Alice")
	if err := store.HideDialog(ctx, alice, "chat:55", "Secret group"); err != nil {
		t.Fatalf("hide: %v", err)
	}
	srv := NewManageServer(store, nil, "https://tg.test", "", hiddenTestConnect)
	client := &auth.Identity{UserID: alice, TelegramID: 4232, ClientID: "claude.ai", Scopes: []string{"account:manage"}}

	body := getManageBody(t, srv, client)
	if strings.Contains(body, "Secret group") || strings.Contains(body, "chat:55") {
		t.Error("an AI client sees the hidden chat")
	}
	if !strings.Contains(body, `id="hidden-browser-only"`) {
		t.Error("an AI client is not told hidden chats are browser-only")
	}
	if rec := getPicker(t, srv, client); rec.Code != http.StatusForbidden || strings.Contains(rec.Body.String(), "Secret group") {
		t.Errorf("picker for an AI client = %d", rec.Code)
	}
	if rec := postHidden(t, srv, client, false, url.Values{"peer": {"chat:55"}}); rec.Code != http.StatusForbidden {
		t.Errorf("show by an AI client = %d", rec.Code)
	}
	if rec := postHidden(t, srv, client, true, url.Values{"peer": {"chat:56"}}); rec.Code != http.StatusForbidden {
		t.Errorf("hide by an AI client = %d", rec.Code)
	}
	rows, _ := store.ListHiddenDialogs(ctx, alice)
	if len(rows) != 1 || rows[0].Peer != "chat:55" {
		t.Fatalf("an AI client changed the hidden list: %+v", rows)
	}
}

// TestHiddenChats_PickerListsVisibleChats: the picker offers the account's
// chats minus the hidden ones, and a failed listing still offers the id form.
func TestHiddenChats_PickerListsVisibleChats(t *testing.T) {
	ctx := context.Background()
	store := newManageTestStore(t)
	carol, _ := store.EnsureUserByTelegramID(ctx, 4233, "carol", "Carol")
	if err := store.HideDialog(ctx, carol, "user:901", "Dana"); err != nil {
		t.Fatalf("hide: %v", err)
	}
	browser := &auth.Identity{UserID: carol, TelegramID: 4233, ClientID: hiddenTestConnect}
	var asked int64
	srv := NewManageServer(store, nil, "https://tg.test", "", hiddenTestConnect).WithDialogLister(func(_ context.Context, uid int64) ([]ManageDialog, error) {
		asked = uid
		return []ManageDialog{{ID: "user:901", Type: "user", Title: "Dana"}, {ID: "chat:902", Type: "chat", Title: "Book club"}}, nil
	})
	rec := getPicker(t, srv, browser)
	body := rec.Body.String()
	if rec.Code != http.StatusOK || asked != carol {
		t.Fatalf("picker = %d, lister asked for %d", rec.Code, asked)
	}
	if !strings.Contains(body, `value="chat:902"`) || !strings.Contains(body, "Book club") {
		t.Error("picker does not offer a visible chat")
	}
	if strings.Count(body, `value="user:901"`) != 1 {
		t.Error("a hidden chat is offered for hiding again, or not listed as hidden")
	}

	srv.WithDialogLister(func(context.Context, int64) ([]ManageDialog, error) { return nil, errors.New("no session") })
	body = getPicker(t, srv, browser).Body.String()
	if !strings.Contains(body, `id="picker-note"`) || !strings.Contains(body, `name="peer" placeholder`) {
		t.Error("a failed listing does not leave the id form with a note")
	}
}

func TestHiddenChats_RejectsMalformedPeer(t *testing.T) {
	ctx := context.Background()
	store := newManageTestStore(t)
	bob, _ := store.EnsureUserByTelegramID(ctx, 4234, "bob", "Bob")
	srv := NewManageServer(store, nil, "https://tg.test", "", hiddenTestConnect)
	browser := &auth.Identity{UserID: bob, TelegramID: 4234, ClientID: hiddenTestConnect}
	for _, peer := range []string{"", "@someone", "channel:abc", "group:5", "user:-3"} {
		if rec := postHidden(t, srv, browser, true, url.Values{"peer": {peer}}); rec.Code != http.StatusBadRequest {
			t.Errorf("hide %q = %d, want 400", peer, rec.Code)
		}
	}
	if rows, _ := store.ListHiddenDialogs(ctx, bob); len(rows) != 0 {
		t.Fatalf("malformed peer stored: %+v", rows)
	}
}

// An unreadable hidden list is unknown, never "no chat is hidden".
func TestHiddenChats_UnreadableListIsUnknown(t *testing.T) {
	ctx := context.Background()
	store := newManageTestStore(t)
	dana, _ := store.EnsureUserByTelegramID(ctx, 4235, "dana", "Dana")
	if _, err := store.DB.ExecContext(ctx, `DROP TABLE hidden_dialogs`); err != nil {
		t.Fatalf("drop: %v", err)
	}
	srv := NewManageServer(store, nil, "https://tg.test", "", hiddenTestConnect)
	body := getManageBody(t, srv, &auth.Identity{UserID: dana, TelegramID: 4235, ClientID: hiddenTestConnect})
	if !strings.Contains(body, `id="hidden-unknown"`) || strings.Contains(body, `id="hidden-none"`) {
		t.Error("a failed hidden-list read is not shown as unknown")
	}
}
