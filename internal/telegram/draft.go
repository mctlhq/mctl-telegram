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

// existingDraft is what the chat holds before SaveDraft writes.
type existingDraft struct {
	Text string
	// Other is true when the draft carries anything besides text (see
	// DraftConflict.HasAttachment). A draft is empty only when both Text
	// is "" and Other is false.
	Other bool
}

func (e existingDraft) empty() bool { return e.Text == "" && !e.Other }

func (e *DraftConflict) Unwrap() error { return ErrDraftExists }

// DraftResult is what SaveDraft did.
type DraftResult struct {
	// Ref is the canonical ref of the chat the draft was saved in.
	Ref string
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

// currentDraft returns the unsent draft in peer, the zero value when there
// is none. The draft lives on the dialog, so it is read with
// messages.getPeerDialogs for this one chat.
func currentDraft(ctx context.Context, api *tg.Client, peer tg.InputPeerClass) (existingDraft, error) {
	res, err := api.MessagesGetPeerDialogs(ctx, []tg.InputDialogPeerClass{&tg.InputDialogPeer{Peer: peer}})
	if err != nil {
		return existingDraft{}, fmt.Errorf("MessagesGetPeerDialogs: %w", err)
	}
	return draftFromDialogs(res.Dialogs)
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
		d, ok := dc.(*tg.Dialog)
		if !ok {
			continue
		}
		dm, ok := d.Draft.(*tg.DraftMessage)
		if !ok {
			// draftMessageEmpty, or no draft field at all.
			return existingDraft{}, nil
		}
		_, media := dm.GetMedia()
		_, reply := dm.GetReplyTo()
		_, post := dm.GetSuggestedPost()
		_, rich := dm.GetRichMessage()
		return existingDraft{Text: dm.Message, Other: media || reply || post || rich}, nil
	}
	// Only folders or unknown dialog types came back: the chat's own row
	// is missing from a non-empty answer. Refuse rather than guess that it
	// holds no draft.
	return existingDraft{}, fmt.Errorf("MessagesGetPeerDialogs: no dialog for the chat among %d entries (first is %T)", len(dialogs), dialogs[0])
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
func SaveDraft(ctx context.Context, c *gotdtelegram.Client, peerSpec, text string, overwrite bool, cache *PeerCache, userID int64) (DraftResult, error) {
	inputPeer, err := ResolvePeerCached(ctx, c, peerSpec, cache, userID)
	if err != nil {
		return DraftResult{}, fmt.Errorf("resolve peer: %w", err)
	}
	ref := inputPeerRef(inputPeer)
	if ref == "" {
		return DraftResult{}, fmt.Errorf("resolve peer: %q names no chat", peerSpec)
	}
	existing, err := currentDraft(ctx, c.API(), inputPeer)
	if err != nil {
		return DraftResult{}, err
	}
	out, err := decideDraft(existing, text, overwrite)
	if err != nil {
		return DraftResult{}, err
	}
	out.Ref = ref
	if out.Unchanged {
		return out, nil
	}
	if _, err := c.API().MessagesSaveDraft(ctx, &tg.MessagesSaveDraftRequest{Peer: inputPeer, Message: text}); err != nil {
		return DraftResult{}, fmt.Errorf("MessagesSaveDraft: %w", err)
	}
	return out, nil
}
