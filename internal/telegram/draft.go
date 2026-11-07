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
}

func (e *DraftConflict) Error() string {
	return fmt.Sprintf("%s (%d UTF-16 units)", ErrDraftExists.Error(), e.ExistingUnits)
}

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
func decideDraft(existing, text string, overwrite bool) (DraftResult, error) {
	switch {
	case existing == text:
		return DraftResult{Unchanged: true, Cleared: text == ""}, nil
	case existing == "":
		return DraftResult{Cleared: text == ""}, nil
	case !overwrite:
		return DraftResult{}, &DraftConflict{ExistingUnits: len(utf16.Encode([]rune(existing)))}
	default:
		return DraftResult{Cleared: text == "", ReplacedExisting: true}, nil
	}
}

// currentDraft returns the text of the unsent draft in peer, "" when there
// is none. The draft lives on the dialog, so it is read with
// messages.getPeerDialogs for this one chat.
func currentDraft(ctx context.Context, api *tg.Client, peer tg.InputPeerClass) (string, error) {
	res, err := api.MessagesGetPeerDialogs(ctx, []tg.InputDialogPeerClass{&tg.InputDialogPeer{Peer: peer}})
	if err != nil {
		return "", fmt.Errorf("MessagesGetPeerDialogs: %w", err)
	}
	if len(res.Dialogs) == 0 {
		// A chat with no dialog row has no draft either; saving one
		// creates it. This is Telegram's documented absence, not a
		// failed read.
		return "", nil
	}
	if d, ok := res.Dialogs[0].(*tg.Dialog); ok {
		if dm, ok := d.Draft.(*tg.DraftMessage); ok {
			return dm.Message, nil
		}
		return "", nil
	}
	// A folder or any other dialog type is not a chat this tool can write
	// a draft in; refuse rather than guess that it holds no draft.
	return "", fmt.Errorf("MessagesGetPeerDialogs: unexpected dialog type %T", res.Dialogs[0])
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
