package telegram

import (
	"errors"
	"fmt"
	"strings"

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

// deploymentFaultCodes are MTProto 400s that say this deployment, not the
// caller, is broken: wrong or banned TG_API_ID/TG_API_HASH, or a layer the
// server failed to set up (for example after a gotd/td layer bump). Every
// call would fail with one of them, and since caller_error leaves both sides
// of the availability ratio, counting them as caller refusals would erase
// the outage from the SLI instead of burning it. The CONNECTION_* family is
// matched by prefix instead (see isDeploymentFault).
var deploymentFaultCodes = map[string]bool{
	"API_ID_INVALID":         true,
	"API_ID_PUBLISHED_FLOOD": true,
	"INPUT_METHOD_INVALID":   true,
	"INPUT_LAYER_INVALID":    true,
}

// isDeploymentFault reports whether an MTProto error message says this
// deployment is broken. Every CONNECTION_* error (CONNECTION_NOT_INITED,
// CONNECTION_LAYER_INVALID, CONNECTION_SYSTEM_EMPTY,
// CONNECTION_DEVICE_MODEL_EMPTY, CONNECTION_LANG_PACK_INVALID, ...) rejects
// the initConnection this server sent, which no caller argument can
// influence, so the whole family is matched by prefix rather than listed.
func isDeploymentFault(msg string) bool {
	return deploymentFaultCodes[msg] || strings.HasPrefix(msg, "CONNECTION_")
}

// IsCallerRefusal reports whether err is Telegram answering a request and
// refusing it as the caller's mistake: an MTProto 400 or 403 reply (an
// unknown peer, a missing permission), ErrPeerNotAccessible, or one of the
// draft_reply refusals ErrNoExistingDialog, ErrCannotPost and ErrPeerDeleted.
// Such a reply proves the session and the service work, so availability SLIs
// must not count it as a failure.
//
// It is the single definition both SLIs use — borrowCallResult for the
// session-borrow SLI and the MCP layer for the tool-availability SLI — so the
// two cannot disagree on what a caller error is.
//
// False for everything else, on purpose: a session-auth rejection (even one
// Telegram sends as a 400, such as SESSION_PASSWORD_NEEDED), PEER_FLOOD and
// any other rate limit, a 400 that means this deployment is broken
// (isDeploymentFault), a Telegram 5xx, a transport failure, a cancelled or
// timed-out context, ErrPoolFull, and any error that is not an MTProto reply.
func IsCallerRefusal(err error) bool {
	if err == nil || sessionErrorFor(err) != nil {
		return false
	}
	// ErrNoExistingDialog, ErrCannotPost and ErrPeerDeleted are this
	// server's own policy refusals, read off a getPeerDialogs reply that
	// succeeded: the session worked, and the caller picked a conversation
	// draft_reply will not use.
	if errors.Is(err, ErrPeerNotAccessible) || errors.Is(err, ErrNoExistingDialog) || errors.Is(err, ErrCannotPost) || errors.Is(err, ErrPeerDeleted) {
		return true
	}
	var te *tgerr.Error
	if !errors.As(err, &te) || IsPeerFlood(err) || isDeploymentFault(te.Message) {
		return false
	}
	return te.Code == 400 || te.Code == 403
}
