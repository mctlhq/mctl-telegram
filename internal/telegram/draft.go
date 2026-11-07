package telegram

import (
	"context"
	"errors"
	"fmt"
	"unicode/utf16"

	gotdtelegram "github.com/gotd/td/telegram"
	"github.com/gotd/td/tg"
)

// ErrDraftExists is returned by SaveDraft when the chat already holds an
// unsent draft the caller did not write, and overwrite was not asked for. A
// draft is the user's own unsent text: replacing it silently would lose it,
// so only an explicit overwrite replaces it (mctl-telegram#1175).
var ErrDraftExists = errors.New("chat already holds an unsent draft")

// DraftConflict carries the size of the draft SaveDraft refused to replace.
// The text itself is never returned: the caller learns that a draft is there
// and how long it is, which is enough to ask the user, and nothing else.
type DraftConflict struct {
	// ExistingUnits is the existing draft's length in UTF-16 units, the
	// unit Telegram counts message text in.
	ExistingUnits int
	// HasAttachment is true when the draft also holds something other than
	// text: media, a reply target, a suggested post or rich content. Such a
	// draft can have no text at all and is still the user's.
	HasAttachment bool
}

func (e *DraftConflict) Error() string {
	if e.HasAttachment {
		return fmt.Sprintf("%s (%d UTF-16 units of text plus an attachment or reply)", ErrDraftExists.Error(), e.ExistingUnits)
	}
	return fmt.Sprintf("%s (%d UTF-16 units)", ErrDraftExists.Error(), e.ExistingUnits)
}

func (e *DraftConflict) Unwrap() error { return ErrDraftExists }

// existingDraft is what the chat holds before SaveDraft writes.
type existingDraft struct {
	Text string
	// Other is true when the draft carries anything besides text (see
	// DraftConflict.HasAttachment). A draft is empty only when both Text
	// is "" and Other is false.
	Other bool
}

func (e existingDraft) empty() bool { return e.Text == "" && !e.Other }

// DraftResult is what SaveDraft did.
type DraftResult struct {
	// Ref is the canonical ref of the chat the draft was saved in.
	Ref string
	// TopicID and TopicTitle name the forum topic the draft was saved in,
	// 0 and "" when the call named none.
	TopicID    int
	TopicTitle string
	// Cleared is true when text was empty, so the draft was removed.
	Cleared bool
	// ReplacedExisting is true when a different non-empty draft was there
	// before and overwrite allowed replacing it.
	ReplacedExisting bool
	// Unchanged is true when the chat already held exactly this text, so
	// nothing was written.
	Unchanged bool
}

// decideDraft applies the no-overwrite rule to the draft currently in the
// chat. It is separate from SaveDraft so the rule is testable without a
// Telegram session.
func decideDraft(existing existingDraft, text string, overwrite bool) (DraftResult, error) {
	switch {
	case existing.empty() && text == "":
		return DraftResult{Unchanged: true, Cleared: true}, nil
	case !existing.Other && existing.Text == text:
		return DraftResult{Unchanged: true}, nil
	case existing.empty():
		return DraftResult{}, nil
	case !overwrite:
		return DraftResult{}, &DraftConflict{
			ExistingUnits: len(utf16.Encode([]rune(existing.Text))),
			HasAttachment: existing.Other,
		}
	default:
		return DraftResult{Cleared: text == "", ReplacedExisting: true}, nil
	}
}

// draftFromDialogs picks the chat's own dialog out of a getPeerDialogs
// answer and reads its draft. The answer can also carry folder entries for
// an archived chat or one in a folder, and their order is not documented,
// so the chat's dialog is searched for rather than assumed to come first.
func draftFromDialogs(dialogs []tg.DialogClass) (existingDraft, error) {
	if len(dialogs) == 0 {
		// A chat with no dialog row has no draft either; saving one
		// creates it. This is Telegram's documented absence, not a
		// failed read.
		return existingDraft{}, nil
	}
	for _, dc := range dialogs {
		if d, ok := dc.(*tg.Dialog); ok {
			return draftFrom(d.Draft, 0), nil
		}
	}
	// Only folders or unknown dialog types came back: the chat's own row
	// is missing from a non-empty answer. Refuse rather than guess that it
	// holds no draft.
	return existingDraft{}, fmt.Errorf("MessagesGetPeerDialogs: no dialog for the chat among %d entries (first is %T)", len(dialogs), dialogs[0])
}

// draftFrom reads one draft field, the dialog's or a forum topic's.
// topicID is the forum topic the draft belongs to (0 for the chat's own
// draft): a topic draft carries a reply header naming the topic itself,
// which places the draft rather than replying to anything, so it does not
// count as content besides text.
func draftFrom(dc tg.DraftMessageClass, topicID int) existingDraft {
	dm, ok := dc.(*tg.DraftMessage)
	if !ok {
		// draftMessageEmpty, or no draft field at all.
		return existingDraft{}
	}
	_, media := dm.GetMedia()
	rt, reply := dm.GetReplyTo()
	if reply && isTopicHeader(rt, topicID) {
		reply = false
	}
	_, post := dm.GetSuggestedPost()
	_, rich := dm.GetRichMessage()
	return existingDraft{Text: dm.Message, Other: media || reply || post || rich}
}

// isTopicHeader reports whether rt is only the reply header that puts a
// draft into forum topic topicID: a reply to the topic's opening message
// with no quote, no other peer and no checklist item. A reply to a message
// inside the topic, or a quote, is real content.
func isTopicHeader(rt tg.InputReplyToClass, topicID int) bool {
	if topicID <= generalTopicID {
		return false
	}
	m, ok := rt.(*tg.InputReplyToMessage)
	if !ok || m.ReplyToMsgID != topicID {
		return false
	}
	if top, ok := m.GetTopMsgID(); ok && top != topicID {
		return false
	}
	if _, ok := m.GetReplyToPeerID(); ok {
		return false
	}
	if _, ok := m.GetQuoteText(); ok {
		return false
	}
	if _, ok := m.GetMonoforumPeerID(); ok {
		return false
	}
	if _, ok := m.GetTodoItemID(); ok {
		return false
	}
	return true
}

// draftInvoker is the subset of *tg.Client SaveDraft uses, so the topic
// handling can be tested without a live MTProto client.
type draftInvoker interface {
	topicByIDInvoker
	MessagesGetPeerDialogs(ctx context.Context, peers []tg.InputDialogPeerClass) (*tg.MessagesPeerDialogs, error)
	MessagesSaveDraft(ctx context.Context, req *tg.MessagesSaveDraftRequest) (bool, error)
}

// SaveDraft stores text as the unsent draft of peerSpec in the user's own
// account, where every one of their Telegram clients shows it in the input
// box. Nothing is sent and nobody else sees it. An empty text clears the
// draft.
//
// A different non-empty draft already in the chat is replaced only when
// overwrite is true; otherwise the call returns a *DraftConflict. The read
// and the write are two calls, so a draft typed in between is a race this
// cannot close; it narrows the window to the call's own latency.
//
// A non-zero topicID saves the draft in that forum topic, which has a draft
// of its own: the topic must exist and be open, and the no-overwrite rule
// is applied to the topic's draft, not the chat's. Topic 1, General, is the
// chat's own draft.
func SaveDraft(ctx context.Context, c *gotdtelegram.Client, peerSpec, text string, overwrite bool, topicID int, cache *PeerCache, userID int64) (DraftResult, error) {
	inputPeer, err := ResolvePeerCached(ctx, c, peerSpec, cache, userID)
	if err != nil {
		return DraftResult{}, fmt.Errorf("resolve peer: %w", err)
	}
	return saveDraftWith(ctx, c.API(), inputPeer, peerSpec, text, overwrite, topicID)
}

func saveDraftWith(ctx context.Context, api draftInvoker, inputPeer tg.InputPeerClass, peerSpec, text string, overwrite bool, topicID int) (DraftResult, error) {
	ref := inputPeerRef(inputPeer)
	if ref == "" {
		return DraftResult{}, fmt.Errorf("resolve peer: %q names no chat", peerSpec)
	}
	var (
		existing   existingDraft
		topicTitle string
		haveDraft  bool
	)
	if topicID != 0 {
		t, err := lookupTopic(ctx, api, peerSpec, inputPeer, topicID)
		if err != nil {
			return DraftResult{}, err
		}
		if t.Closed {
			return DraftResult{}, ErrTopicClosed
		}
		topicTitle = t.Title
		if topicID > generalTopicID {
			existing, haveDraft = draftFrom(t.Draft, topicID), true
		}
	}
	if !haveDraft {
		res, err := api.MessagesGetPeerDialogs(ctx, []tg.InputDialogPeerClass{&tg.InputDialogPeer{Peer: inputPeer}})
		if err != nil {
			return DraftResult{}, fmt.Errorf("MessagesGetPeerDialogs: %w", err)
		}
		if existing, err = draftFromDialogs(res.Dialogs); err != nil {
			return DraftResult{}, err
		}
	}
	out, err := decideDraft(existing, text, overwrite)
	if err != nil {
		return DraftResult{}, err
	}
	out.Ref = ref
	if topicID != 0 {
		out.TopicID, out.TopicTitle = topicID, topicTitle
	}
	if out.Unchanged {
		return out, nil
	}
	req := &tg.MessagesSaveDraftRequest{Peer: inputPeer, Message: text}
	if replyTo := replyToFor(topicID); replyTo != nil {
		req.SetReplyTo(replyTo)
	}
	if _, err := api.MessagesSaveDraft(ctx, req); err != nil {
		return DraftResult{}, fmt.Errorf("MessagesSaveDraft: %w", err)
	}
	return out, nil
}
