package web

// manage_hidden.go is the manage page's editor for hidden chats
// (mctl-telegram#1152): the owner hides dialogs from every connected client,
// or shows them again. Enforcement lives in internal/mcp/hidden.go.
//
// Only the browser Telegram sign-in may see or change the list. The manage
// routes also accept an AI client's bearer token, and a client holding
// account:manage must not be able to read which chats were hidden from it,
// or show them again: that would let it widen its own scope. Cross-site
// submission is refused by the SameSite=Lax connect-session cookie, as for
// the other manage forms.

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

// ManageDialog is one chat the picker offers.
type ManageDialog struct {
	ID    string
	Type  string
	Title string
}

// DialogLister lists the account's recent dialogs for the picker, without
// the hidden-chat filter. It fails for an account without a hosted session.
type DialogLister func(ctx context.Context, userID int64) ([]ManageDialog, error)

// WithDialogLister sets the picker's dialog source. Without one the picker
// offers only the chat-id form.
func (s *ManageServer) WithDialogLister(fn DialogLister) *ManageServer {
	s.dialogs = fn
	return s
}

const msgHiddenBrowserOnly = "Hidden chats can be seen and changed only after signing in to this page with Telegram in a browser, so an AI client cannot change what it may see."

// hiddenSectionView is the hidden-chat block on the manage page.
type hiddenSectionView struct {
	// CanEdit is false for any credential but the browser sign-in; Rows
	// is then not loaded at all.
	CanEdit bool
	// Unknown marks a failed read: the list is not shown as empty.
	Unknown bool
	Rows    []db.HiddenDialog
	Notice  string
}

func hiddenNotice(v string) string {
	switch v {
	case "hidden":
		return "Chat hidden. Connected AI clients no longer see it."
	case "shown":
		return "Chat shown again. Connected AI clients can see it."
	case "unchanged":
		return "That chat was not hidden."
	}
	return ""
}

func (s *ManageServer) buildHiddenSection(r *http.Request, id *auth.Identity) *hiddenSectionView {
	v := &hiddenSectionView{CanEdit: isBrowserSignIn(id, s.connectClient), Notice: hiddenNotice(r.URL.Query().Get("hidden"))}
	if !v.CanEdit {
		return v
	}
	rows, err := s.store.ListHiddenDialogs(r.Context(), id.UserID)
	if err != nil {
		slog.Warn("manage: list hidden dialogs", "err", err)
		v.Unknown = true
		return v
	}
	v.Rows = rows
	return v
}

// hiddenPickerData feeds the picker page.
type hiddenPickerData struct {
	Hidden []db.HiddenDialog
	// Dialogs are the visible chats offered for hiding.
	Dialogs []ManageDialog
	// ListNote explains why no chat list is shown, when none is.
	ListNote string
}

// HandleHiddenChats renders the picker: the hidden chats with a Show button
// and the account's recent chats with a Hide button.
func (s *ManageServer) HandleHiddenChats(w http.ResponseWriter, r *http.Request) {
	id := auth.From(r.Context())
	if id == nil {
		s.WriteUnauthorized(w, r, http.StatusUnauthorized, auth.MsgAuthRequired)
		return
	}
	if !isBrowserSignIn(id, s.connectClient) {
		renderManage(w, http.StatusForbidden, manageErrorTemplate, manageErrorData{Message: msgHiddenBrowserOnly})
		return
	}
	hidden, err := s.store.ListHiddenDialogs(r.Context(), id.UserID)
	if err != nil {
		slog.Warn("manage: list hidden dialogs", "err", err)
		renderManageError(w, "Could not load your hidden chats. Please try again.")
		return
	}
	data := hiddenPickerData{Hidden: hidden}
	isHidden := make(map[string]bool, len(hidden))
	for _, h := range hidden {
		isHidden[h.Peer] = true
	}
	switch mode, err := s.store.GetAccountMode(r.Context(), id.UserID); {
	case err != nil:
		slog.Warn("manage: account mode", "err", err)
		data.ListNote = "Your chat list could not be loaded right now. You can still hide a chat by its id."
	case mode == "local":
		data.ListNote = "This account runs through Local Bridge, so this page cannot list its chats. Hide a chat by the id list_dialogs shows for it."
	case s.dialogs == nil:
		data.ListNote = "This server cannot list your chats here. Hide a chat by its id."
	default:
		dialogs, err := s.dialogs(r.Context(), id.UserID)
		if err != nil {
			slog.Warn("manage: list dialogs for picker", "err", err)
			data.ListNote = "Your chat list could not be loaded right now (is your Telegram session connected?). You can still hide a chat by its id."
			break
		}
		for _, d := range dialogs {
			if !isHidden[d.ID] {
				data.Dialogs = append(data.Dialogs, d)
			}
		}
	}
	renderManage(w, http.StatusOK, manageHiddenPickerTemplate, data)
}

// HandleHideChat hides one chat.
func (s *ManageServer) HandleHideChat(w http.ResponseWriter, r *http.Request) {
	s.handleHiddenChange(w, r, true)
}

// HandleShowChat shows one hidden chat again.
func (s *ManageServer) HandleShowChat(w http.ResponseWriter, r *http.Request) {
	s.handleHiddenChange(w, r, false)
}

func (s *ManageServer) handleHiddenChange(w http.ResponseWriter, r *http.Request, hide bool) {
	tool := "POST /telegram/connect/manage/show-chat"
	if hide {
		tool = "POST /telegram/connect/manage/hide-chat"
	}
	id := auth.From(r.Context())
	if id == nil {
		s.WriteUnauthorized(w, r, http.StatusUnauthorized, auth.MsgAuthRequired)
		return
	}
	if !isBrowserSignIn(id, s.connectClient) {
		auditScopeDenied(r, s.store, id, tool)
		renderManage(w, http.StatusForbidden, manageErrorTemplate, manageErrorData{Message: msgHiddenBrowserOnly})
		return
	}
	peer, ok := db.CanonicalDialogRef(r.PostFormValue("peer"))
	if !ok {
		renderManage(w, http.StatusBadRequest, manageErrorTemplate, manageErrorData{Message: `That is not a chat id. Use the form "user:<id>", "chat:<id>" or "channel:<id>".`})
		return
	}
	flag := "hidden"
	var err error
	if hide {
		err = s.store.HideDialog(r.Context(), id.UserID, peer, r.PostFormValue("title"))
	} else {
		var removed bool
		removed, err = s.store.UnhideDialog(r.Context(), id.UserID, peer)
		flag = "shown"
		if err == nil && !removed {
			flag = "unchanged"
		}
	}
	s.auditManage(r, id, tool, err)
	if errors.Is(err, db.ErrTooManyHiddenDialogs) {
		renderManage(w, http.StatusBadRequest, manageErrorTemplate, manageErrorData{Message: "You have hidden the maximum number of chats. Show one again before hiding another."})
		return
	}
	if err != nil {
		slog.Warn("manage: change hidden chat", "hide", hide, "err", err)
		renderManageError(w, "Saving your hidden chats failed. Please try again.")
		return
	}
	target := s.issuer + "/telegram/connect/manage?hidden=" + flag + "#hidden"
	if strings.TrimSpace(r.PostFormValue("back")) == "picker" {
		target = s.issuer + "/telegram/connect/manage/hidden-chats"
	}
	http.Redirect(w, r, target, http.StatusFound)
}

// manageHiddenSection is the block on the manage page.
const manageHiddenSection = `
    <h2 class="notif-heading" id="hidden">Hidden chats</h2>
    <p class="meta">A hidden chat is invisible to every AI client connected to this account: it is left out of chat lists and search, and reading or sending to it is refused. New chats are visible until you hide them.</p>
    {{with .Hidden}}{{if .Notice}}<p class="meta" id="hidden-notice">{{.Notice}}</p>{{end}}
    {{if not .CanEdit}}<p class="meta" id="hidden-browser-only">` + msgHiddenBrowserOnly + `</p>
    {{else if .Unknown}}<p class="meta" id="hidden-unknown">We could not load your hidden chats right now. This does not mean none are hidden.</p>
    {{else}}{{range .Rows}}<div class="field-row"><span class="field-label">{{if .Title}}{{.Title}}{{else}}{{.Peer}}{{end}}</span><span class="field-value">
      <form method="POST" action="/telegram/connect/manage/show-chat" style="display:inline"><input type="hidden" name="peer" value="{{.Peer}}"><button type="submit" class="btn-secondary">Show</button></form></span></div>
    {{else}}<p class="meta" id="hidden-none">No chat is hidden.</p>{{end}}
    <p class="meta"><a href="/telegram/connect/manage/hidden-chats">Choose chats to hide</a></p>{{end}}{{end}}
`

var manageHiddenPickerTemplate = newManageTemplate("manageHiddenPicker", manageHead+`    <h1>Hidden chats</h1>
    <p class="meta">A hidden chat is invisible to every AI client connected to this account. An AI client that already read it keeps what it read.</p>
    <h2 class="notif-heading">Hidden now</h2>
    {{range .Hidden}}<div class="field-row"><span class="field-label">{{if .Title}}{{.Title}}{{else}}{{.Peer}}{{end}}</span><span class="field-value">
      <form method="POST" action="/telegram/connect/manage/show-chat" style="display:inline"><input type="hidden" name="peer" value="{{.Peer}}"><input type="hidden" name="back" value="picker"><button type="submit" class="btn-secondary">Show</button></form></span></div>
    {{else}}<p class="meta" id="picker-none-hidden">No chat is hidden.</p>{{end}}
    <h2 class="notif-heading">Your chats</h2>
    {{if .ListNote}}<p class="meta" id="picker-note">{{.ListNote}}</p>{{end}}
    {{range .Dialogs}}<div class="field-row"><span class="field-label">{{.Title}}</span><span class="field-value">{{.Type}}
      <form method="POST" action="/telegram/connect/manage/hide-chat" style="display:inline"><input type="hidden" name="peer" value="{{.ID}}"><input type="hidden" name="title" value="{{.Title}}"><input type="hidden" name="back" value="picker"><button type="submit" class="btn-secondary">Hide</button></form></span></div>
    {{end}}
    <h2 class="notif-heading">Hide by chat id</h2>
    <form method="POST" action="/telegram/connect/manage/hide-chat">
      <input type="hidden" name="back" value="picker">
      <label>Chat id <input type="text" name="peer" placeholder="channel:123456" required></label>
      <label>Name (optional) <input type="text" name="title" maxlength="256"></label>
      <button type="submit" class="btn-secondary">Hide</button>
    </form>
    <p class="meta"><a href="/telegram/connect/manage#hidden">Back</a></p>
`+manageFoot)
