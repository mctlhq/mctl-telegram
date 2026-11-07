package telegram

import (
	"context"
	"errors"
	"fmt"

	"github.com/gotd/td/tg"
)

// HiddenPeers is the set of dialogs the account owner hid from every
// connected client (mctl-telegram#1152), keyed by the canonical peer ref
// "user:<id>", "chat:<id>" or "channel:<id>" that Dialog.ID uses.
type HiddenPeers map[string]bool

// ErrPeerHidden is returned for a call that names, or resolves to, a dialog
// the account owner hid on the manage page.
var ErrPeerHidden = errors.New("this chat is hidden from connected clients")

type hiddenPeersKey struct{}

// WithHiddenPeers returns ctx carrying the account's hidden dialogs. Every
// peer resolution and dialog scan made with the returned context refuses or
// skips those dialogs. A nil or empty set hides nothing.
func WithHiddenPeers(ctx context.Context, set HiddenPeers) context.Context {
	return context.WithValue(ctx, hiddenPeersKey{}, set)
}

// HiddenPeersFrom returns the set WithHiddenPeers stored, or nil.
func HiddenPeersFrom(ctx context.Context) HiddenPeers {
	set, _ := ctx.Value(hiddenPeersKey{}).(HiddenPeers)
	return set
}

// isHidden reports whether the canonical ref is hidden in ctx.
func isHidden(ctx context.Context, ref string) bool {
	if ref == "" {
		return false
	}
	return HiddenPeersFrom(ctx)[ref]
}

// inputPeerRef returns the canonical ref of an input peer, or "" for a peer
// that names no dialog (self, empty).
func inputPeerRef(p tg.InputPeerClass) string {
	switch v := p.(type) {
	case *tg.InputPeerUser:
		return fmt.Sprintf("user:%d", v.UserID)
	case *tg.InputPeerChat:
		return fmt.Sprintf("chat:%d", v.ChatID)
	case *tg.InputPeerChannel:
		return fmt.Sprintf("channel:%d", v.ChannelID)
	case *tg.InputPeerUserFromMessage:
		return fmt.Sprintf("user:%d", v.UserID)
	case *tg.InputPeerChannelFromMessage:
		return fmt.Sprintf("channel:%d", v.ChannelID)
	default:
		return ""
	}
}

// refuseHidden returns ErrPeerHidden when input resolves to a hidden dialog.
func refuseHidden(ctx context.Context, input tg.InputPeerClass) error {
	if isHidden(ctx, inputPeerRef(input)) {
		return ErrPeerHidden
	}
	return nil
}

// widenForHidden returns the page size to ask Telegram for so that limit
// visible entries can remain after hidden ones are dropped, capped at max.
func widenForHidden(ctx context.Context, limit, max int) int {
	n := limit + len(HiddenPeersFrom(ctx))
	if n > max {
		return max
	}
	return n
}

// dropHiddenDialogs removes hidden dialogs from a listing, in place.
func dropHiddenDialogs(ctx context.Context, in []Dialog) []Dialog {
	set := HiddenPeersFrom(ctx)
	if len(set) == 0 {
		return in
	}
	out := in[:0]
	for _, d := range in {
		if !set[d.ID] {
			out = append(out, d)
		}
	}
	return out
}

// dropHiddenMessages removes messages whose canonical peer is hidden, in
// place. A message whose Peer is not canonical (a per-peer read echoes the
// caller's spelling) was already checked when that peer was resolved.
func dropHiddenMessages(ctx context.Context, in []Message) []Message {
	set := HiddenPeersFrom(ctx)
	if len(set) == 0 {
		return in
	}
	out := in[:0]
	for _, m := range in {
		if !set[m.Peer] {
			out = append(out, m)
		}
	}
	return out
}

// IsPeerHidden reports whether the canonical ref is hidden in ctx. It is for
// callers that hold a ref resolved earlier, such as a stored reply draft.
func IsPeerHidden(ctx context.Context, ref string) bool { return isHidden(ctx, ref) }
