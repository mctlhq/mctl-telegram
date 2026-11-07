package telegram

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/gotd/td/telegram"
	"github.com/gotd/td/tg"
)

// Folder is one of the user's chat folders (Telegram "dialog filters"),
// described without listing its members (mctl-telegram#1155).
type Folder struct {
	ID    int    `json:"id"`
	Title string `json:"title"`
	// Kind is "folder" for a folder the user built, "shared" for a chat
	// list joined through an invite link.
	Kind string `json:"kind"`
	// IncludedPeers counts the chats added to the folder by hand (pinned
	// ones included); ExcludedPeers the ones removed by hand.
	IncludedPeers int `json:"included_peers"`
	ExcludedPeers int `json:"excluded_peers"`
	// IncludeRules are the chat types the folder includes as a rule:
	// contacts, non_contacts, groups, channels, bots.
	IncludeRules []string `json:"include_rules,omitempty"`
	// ExcludeRules drop rule-matched chats that are muted, read or
	// archived. Chats added by hand are kept regardless, as in the
	// Telegram apps.
	ExcludeRules []string `json:"exclude_rules,omitempty"`
}

// FolderScan says how much of the dialog list a folder filter looked at.
// Complete is false when Telegram reported more dialogs than were scanned,
// so a member of the folder may be missing from the result.
type FolderScan struct {
	Scanned  int  `json:"scanned"`
	Complete bool `json:"complete"`
}

// ErrFolderNotFound is returned when no folder has the requested id.
var ErrFolderNotFound = errors.New("folder not found")

// folderScanMain and folderScanArchive bound how many dialogs a folder
// filter reads from the main list and the archive.
const (
	folderScanMain    = 200
	folderScanArchive = 100
)

// ListFolders returns the user's chat folders. The built-in "All chats"
// entry is not a folder and is left out.
func ListFolders(ctx context.Context, c *telegram.Client) ([]Folder, error) {
	res, err := c.API().MessagesGetDialogFilters(ctx)
	if err != nil {
		return nil, fmt.Errorf("MessagesGetDialogFilters: %w", err)
	}
	return foldersFromFilters(res.Filters), nil
}

func foldersFromFilters(filters []tg.DialogFilterClass) []Folder {
	out := make([]Folder, 0, len(filters))
	for _, fc := range filters {
		switch f := fc.(type) {
		case *tg.DialogFilter:
			out = append(out, Folder{
				ID:            f.ID,
				Title:         f.Title.Text,
				Kind:          "folder",
				IncludedPeers: len(f.PinnedPeers) + len(f.IncludePeers),
				ExcludedPeers: len(f.ExcludePeers),
				IncludeRules:  folderIncludeRules(f),
				ExcludeRules:  folderExcludeRules(f),
			})
		case *tg.DialogFilterChatlist:
			out = append(out, Folder{
				ID:            f.ID,
				Title:         f.Title.Text,
				Kind:          "shared",
				IncludedPeers: len(f.PinnedPeers) + len(f.IncludePeers),
			})
		}
	}
	return out
}

func folderIncludeRules(f *tg.DialogFilter) []string {
	var r []string
	for _, x := range []struct {
		on   bool
		name string
	}{{f.Contacts, "contacts"}, {f.NonContacts, "non_contacts"}, {f.Groups, "groups"}, {f.Broadcasts, "channels"}, {f.Bots, "bots"}} {
		if x.on {
			r = append(r, x.name)
		}
	}
	return r
}

func folderExcludeRules(f *tg.DialogFilter) []string {
	var r []string
	for _, x := range []struct {
		on   bool
		name string
	}{{f.ExcludeMuted, "muted"}, {f.ExcludeRead, "read"}, {f.ExcludeArchived, "archived"}} {
		if x.on {
			r = append(r, x.name)
		}
	}
	return r
}

// folderSpec is a folder's membership rule in a form that can be evaluated
// against a dialog without further API calls.
type folderSpec struct {
	include, exclude map[string]bool
	contacts         bool
	nonContacts      bool
	groups           bool
	broadcasts       bool
	bots             bool
	excludeMuted     bool
	excludeRead      bool
	excludeArchived  bool
	// defaultMuted holds the account-wide notification defaults by peer
	// kind ("users", "chats", "broadcasts"). A chat without its own
	// mute_until follows the default for its kind, as in the Telegram apps.
	// Read only when the folder excludes muted chats.
	defaultMuted map[string]bool
}

func specFromFilter(fc tg.DialogFilterClass) (folderSpec, bool) {
	spec := folderSpec{include: map[string]bool{}, exclude: map[string]bool{}}
	add := func(m map[string]bool, peers []tg.InputPeerClass) {
		for _, p := range peers {
			if k := inputPeerKey(p); k != "" {
				m[k] = true
			}
		}
	}
	switch f := fc.(type) {
	case *tg.DialogFilter:
		add(spec.include, f.PinnedPeers)
		add(spec.include, f.IncludePeers)
		add(spec.exclude, f.ExcludePeers)
		spec.contacts, spec.nonContacts, spec.groups, spec.broadcasts, spec.bots =
			f.Contacts, f.NonContacts, f.Groups, f.Broadcasts, f.Bots
		spec.excludeMuted, spec.excludeRead, spec.excludeArchived = f.ExcludeMuted, f.ExcludeRead, f.ExcludeArchived
		return spec, true
	case *tg.DialogFilterChatlist:
		add(spec.include, f.PinnedPeers)
		add(spec.include, f.IncludePeers)
		return spec, true
	}
	return spec, false
}

func inputPeerKey(p tg.InputPeerClass) string {
	switch v := p.(type) {
	case *tg.InputPeerSelf:
		return "self"
	case *tg.InputPeerUser:
		return fmt.Sprintf("user:%d", v.UserID)
	case *tg.InputPeerUserFromMessage:
		return fmt.Sprintf("user:%d", v.UserID)
	case *tg.InputPeerChat:
		return fmt.Sprintf("chat:%d", v.ChatID)
	case *tg.InputPeerChannel:
		return fmt.Sprintf("channel:%d", v.ChannelID)
	case *tg.InputPeerChannelFromMessage:
		return fmt.Sprintf("channel:%d", v.ChannelID)
	}
	return ""
}

// contains reports whether d belongs to the folder, by the rules the
// Telegram apps apply: a chat excluded by hand is out; a chat added by hand
// is in; otherwise it must match an include rule and survive the exclude
// rules.
func (f folderSpec) contains(d *tg.Dialog, users map[int64]*tg.User, chats map[int64]tg.ChatClass, archived bool, now time.Time) bool {
	key := peerClassKey(d.Peer)
	if key == "" {
		return false
	}
	self := false
	if p, ok := d.Peer.(*tg.PeerUser); ok {
		if u, ok := users[p.UserID]; ok && u.Self {
			self = true
		}
	}
	if f.exclude[key] || (self && f.exclude["self"]) {
		return false
	}
	if f.include[key] || (self && f.include["self"]) {
		return true
	}
	if !f.matchesRule(d.Peer, users, chats) {
		return false
	}
	// Telegram Desktop's ChatFilter::contains keeps a muted chat with an
	// unread mention while it is in the main list, and a read chat that
	// still has an unread mention.
	mention := d.UnreadMentionsCount > 0
	if f.excludeMuted && f.muted(d, chats, now) && !(mention && !archived) {
		return false
	}
	if f.excludeRead && d.UnreadCount == 0 && !d.UnreadMark && !mention {
		return false
	}
	if f.excludeArchived && archived {
		return false
	}
	return true
}

func (f folderSpec) muted(d *tg.Dialog, chats map[int64]tg.ChatClass, now time.Time) bool {
	if until, ok := d.NotifySettings.GetMuteUntil(); ok {
		return int64(until) > now.Unix()
	}
	return f.defaultMuted[notifyKind(d.Peer, chats)]
}

// notifyKind names the account-wide notification default a peer follows.
func notifyKind(p tg.PeerClass, chats map[int64]tg.ChatClass) string {
	switch v := p.(type) {
	case *tg.PeerUser:
		return "users"
	case *tg.PeerChat:
		return "chats"
	case *tg.PeerChannel:
		if ch, ok := chats[v.ChannelID].(*tg.Channel); ok && ch.Broadcast {
			return "broadcasts"
		}
		return "chats"
	}
	return ""
}

func (f folderSpec) matchesRule(p tg.PeerClass, users map[int64]*tg.User, chats map[int64]tg.ChatClass) bool {
	switch v := p.(type) {
	case *tg.PeerUser:
		u, ok := users[v.UserID]
		if !ok {
			return false
		}
		if u.Bot {
			return f.bots
		}
		if u.Contact || u.MutualContact {
			return f.contacts
		}
		return f.nonContacts
	case *tg.PeerChat:
		return f.groups
	case *tg.PeerChannel:
		ch, ok := chats[v.ChannelID].(*tg.Channel)
		if !ok {
			return false
		}
		if ch.Broadcast {
			return f.broadcasts
		}
		return f.groups
	}
	return false
}

// ListDialogsInFolder returns the dialogs of folder folderID among the most
// recent dialogs of the main list and the archive, filtered by query and cut
// to limit. Telegram has no call that lists a folder's members, so the
// folder is evaluated here; the returned FolderScan says whether every
// dialog was looked at.
func ListDialogsInFolder(ctx context.Context, c *telegram.Client, folderID, limit int, query string, cache *PeerCache, userID int64) ([]Dialog, FolderScan, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	api := c.API()
	spec, err := loadFolderSpec(ctx, api, folderID)
	if err != nil {
		return nil, FolderScan{}, err
	}
	res, err := scanFolder(folderFetch(ctx, api, cache, userID), spec, time.Now(), query)
	if err != nil {
		return nil, FolderScan{}, err
	}
	out := dropHiddenDialogs(ctx, res.dialogs)
	if len(out) > limit {
		out = out[:limit]
	}
	return out, res.scan, nil
}

// folderFetch reads one page of a dialog list for a folder scan and seeds
// the peer cache with the users and chats it carries.
func folderFetch(ctx context.Context, api *tg.Client, cache *PeerCache, userID int64) func(*tg.MessagesGetDialogsRequest) (tg.MessagesDialogsClass, error) {
	return func(req *tg.MessagesGetDialogsRequest) (tg.MessagesDialogsClass, error) {
		res, err := api.MessagesGetDialogs(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("MessagesGetDialogs: %w", err)
		}
		users, chats, _ := decodeDialogsResult(res)
		seedPeerCache(cache, userID, users, chats)
		return res, nil
	}
}

// folderSpecInvoker is the part of the Telegram API loadFolderSpec uses.
type folderSpecInvoker interface {
	MessagesGetDialogFilters(ctx context.Context) (*tg.MessagesDialogFilters, error)
	AccountGetNotifySettings(ctx context.Context, peer tg.InputNotifyPeerClass) (*tg.PeerNotifySettings, error)
}

// loadFolderSpec reads folder folderID's rules, and the account's mute
// defaults when the folder excludes muted chats. A folder that does not
// exist is ErrFolderNotFound.
func loadFolderSpec(ctx context.Context, api folderSpecInvoker, folderID int) (folderSpec, error) {
	filters, err := api.MessagesGetDialogFilters(ctx)
	if err != nil {
		return folderSpec{}, fmt.Errorf("MessagesGetDialogFilters: %w", err)
	}
	var spec folderSpec
	found := false
	for _, fc := range filters.Filters {
		id := -1
		switch f := fc.(type) {
		case *tg.DialogFilter:
			id = f.ID
		case *tg.DialogFilterChatlist:
			id = f.ID
		}
		if id != folderID {
			continue
		}
		spec, found = specFromFilter(fc)
		break
	}
	if !found {
		return folderSpec{}, fmt.Errorf("%w: %d", ErrFolderNotFound, folderID)
	}
	if spec.excludeMuted {
		// An unread default would silently decide "not muted", so a failed
		// read fails the listing.
		spec.defaultMuted = map[string]bool{}
		now := time.Now()
		for kind, peer := range map[string]tg.InputNotifyPeerClass{
			"users": &tg.InputNotifyUsers{}, "chats": &tg.InputNotifyChats{}, "broadcasts": &tg.InputNotifyBroadcasts{},
		} {
			ns, err := api.AccountGetNotifySettings(ctx, peer)
			if err != nil {
				return folderSpec{}, fmt.Errorf("AccountGetNotifySettings(%s): %w", kind, err)
			}
			if until, ok := ns.GetMuteUntil(); ok && int64(until) > now.Unix() {
				spec.defaultMuted[kind] = true
			}
		}
	}
	return spec, nil
}

// folderMembers is what a folder scan found: the members as listed dialogs
// (filtered by the query), every member as a raw Telegram dialog (archive
// last; the query does not apply), and the users and chats the scanned
// pages carried.
type folderMembers struct {
	dialogs []Dialog
	raw     []*tg.Dialog
	users   map[int64]*tg.User
	chats   map[int64]tg.ChatClass
	scan    FolderScan
}

// scanFolder evaluates spec over the most recent dialogs of the main list
// and, when the folder can hold archived chats, the archive.
func newFolderMembers() *folderMembers {
	return &folderMembers{users: map[int64]*tg.User{}, chats: map[int64]tg.ChatClass{}}
}

func scanFolder(fetch func(*tg.MessagesGetDialogsRequest) (tg.MessagesDialogsClass, error), spec folderSpec, now time.Time, query string) (*folderMembers, error) {
	out := newFolderMembers()
	if err := scanFolderList(fetch, 0, folderScanMain, spec, false, now, query, out); err != nil {
		return nil, err
	}
	// The archive can only add members when archived chats are not excluded
	// as a rule, or when a chat was added by hand.
	if !spec.excludeArchived || len(spec.include) > 0 {
		main := out.scan
		out.scan = FolderScan{}
		if err := scanFolderList(fetch, 1, folderScanArchive, spec, true, now, query, out); err != nil {
			return nil, err
		}
		out.scan = FolderScan{Scanned: main.Scanned + out.scan.Scanned, Complete: main.Complete && out.scan.Complete}
	}
	return out, nil
}

// folderPageSize is what one messages.getDialogs call returns at most.
const folderPageSize = 100

// scanFolderList pages through one dialog list (folder 0 = main, 1 =
// archive) up to max dialogs and keeps the folder's members. The scan is
// complete only when the list is known to have ended within the pages read.
// Members are appended to acc; acc.scan is set to this list's coverage.
func scanFolderList(fetch func(*tg.MessagesGetDialogsRequest) (tg.MessagesDialogsClass, error), list, max int, spec folderSpec, archived bool, now time.Time, query string, acc *folderMembers) error {
	scan := &acc.scan
	req := &tg.MessagesGetDialogsRequest{OffsetPeer: &tg.InputPeerEmpty{}}
	if list != 0 {
		req.SetFolderID(list)
	}
	for scan.Scanned < max {
		req.Limit = folderPageSize
		if left := max - scan.Scanned; left < folderPageSize {
			req.Limit = left
		}
		res, err := fetch(req)
		if err != nil {
			return err
		}
		page := folderPageOf(res, spec, archived, now, query)
		if page.total < 0 {
			// Nothing observable came back: the scan cannot claim an end.
			return nil
		}
		acc.dialogs = append(acc.dialogs, page.members...)
		acc.raw = append(acc.raw, page.raw...)
		for id, u := range page.users {
			acc.users[id] = u
		}
		for id, ch := range page.chats {
			acc.chats[id] = ch
		}
		scan.Scanned += page.scanned
		if scan.Scanned >= page.total {
			scan.Complete = true
			return nil
		}
		if page.scanned == 0 {
			// An empty page short of the reported total: the rest of the
			// list was not observed.
			return nil
		}
		next, ok := page.next()
		if !ok {
			return nil
		}
		next.Limit = req.Limit
		if list != 0 {
			next.SetFolderID(list)
		}
		req = next
	}
	return nil
}

// folderPage is one messages.getDialogs answer evaluated against a folder.
// total is the size of the whole list as Telegram reported it, or -1 when
// the answer carried no dialogs to evaluate (NotModified or an unknown
// shape).
type folderPage struct {
	members []Dialog
	raw     []*tg.Dialog
	users   map[int64]*tg.User
	chats   map[int64]tg.ChatClass
	scanned int
	total   int
	next    func() (*tg.MessagesGetDialogsRequest, bool)
}

func folderPageOf(res tg.MessagesDialogsClass, spec folderSpec, archived bool, now time.Time, query string) folderPage {
	total := -1
	switch v := res.(type) {
	case *tg.MessagesDialogs:
		total = len(v.Dialogs)
	case *tg.MessagesDialogsSlice:
		total = v.Count
	default:
		return folderPage{total: -1, next: func() (*tg.MessagesGetDialogsRequest, bool) { return nil, false }}
	}
	users, chats, dialogs := decodeDialogsResult(res)
	messages := dialogsTopMessages(res)
	var members []tg.DialogClass
	var raw []*tg.Dialog
	var last *tg.Dialog
	for _, dc := range dialogs {
		d, ok := dc.(*tg.Dialog)
		if !ok {
			continue
		}
		last = d
		if spec.contains(d, users, chats, archived, now) {
			members = append(members, d)
			raw = append(raw, d)
		}
	}
	out := dialogEntries(members, users, chats, messages, query)
	for i := range out {
		out[i].Archived = archived
	}
	return folderPage{
		members: out,
		raw:     raw,
		users:   users,
		chats:   chats,
		scanned: len(dialogs),
		total:   total,
		next: func() (*tg.MessagesGetDialogsRequest, bool) {
			// The next page starts after the last dialog's top message, as
			// the Telegram apps page the list.
			if last == nil {
				return nil, false
			}
			ts, ok := lastMessageDateFor(last, topMessageDates(messages))
			peer := inputPeerFromPeer(last.Peer, users, chats)
			if !ok || peer == nil {
				return nil, false
			}
			return &tg.MessagesGetDialogsRequest{
				OffsetDate: int(ts.Unix()),
				OffsetID:   last.TopMessage,
				OffsetPeer: peer,
			}, true
		},
	}
}
