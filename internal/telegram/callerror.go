package telegram

import (
	"errors"
	"fmt"

	"github.com/gotd/td/tgerr"
)

// ErrPeerNotAccessible marks a Telegram 400 peer refusal (PEER_ID_INVALID,
// CHANNEL_INVALID) that a helper re-phrased for the caller instead of
// returning the raw RPC error. Match it with errors.Is.
var ErrPeerNotAccessible = errors.New("telegram: peer not accessible")

// peerNotAccessibleError is the re-phrased refusal GetMessages returns when a
// peer cannot be resolved. Its text is the actionable guidance clients rely
// on ("call list_dialogs ..."), so it deliberately does NOT unwrap to the
// underlying *tgerr.Error: a caller that renders MTProto errors from a
// catalog would otherwise replace that guidance. It only answers errors.Is
// for ErrPeerNotAccessible, which is what IsCallerRefusal needs.
type peerNotAccessibleError struct {
	peer, code string
}

func (e *peerNotAccessibleError) Error() string {
	return fmt.Sprintf("peer %q could not be accessed (%s): it is not in your dialog list; "+
		"call list_dialogs and use an id exactly as returned there", e.peer, e.code)
}

func (e *peerNotAccessibleError) Is(target error) bool {
	return target == ErrPeerNotAccessible
}

// IsCallerRefusal reports whether err is Telegram answering a request and
// refusing it as the caller's mistake: an MTProto 400 or 403 reply (an
// unknown peer, a missing permission), or ErrPeerNotAccessible. Such a reply
// proves the session and the service work, so availability SLIs must not
// count it as a failure.
//
// It is the single definition both SLIs use — borrowCallResult for the
// session-borrow SLI and the MCP layer for the tool-availability SLI — so the
// two cannot disagree on what a caller error is.
//
// False for everything else, on purpose: a session-auth rejection (even one
// Telegram sends as a 400, such as SESSION_PASSWORD_NEEDED), PEER_FLOOD and
// any other rate limit, a Telegram 5xx, a transport failure, a cancelled or
// timed-out context, ErrPoolFull, and any error that is not an MTProto reply.
func IsCallerRefusal(err error) bool {
	if err == nil || sessionErrorFor(err) != nil {
		return false
	}
	if errors.Is(err, ErrPeerNotAccessible) {
		return true
	}
	var te *tgerr.Error
	if !errors.As(err, &te) || te.Message == "PEER_FLOOD" {
		return false
	}
	return te.Code == 400 || te.Code == 403
}
