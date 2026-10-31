package telegram

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gotd/td/telegram"
	"github.com/gotd/td/tg"
	"github.com/gotd/td/tgerr"
)

// SendToInputPeer sends a plain text message to an already-resolved peer and
// returns the new Telegram message id. Unlike SendMessage it takes an
// InputPeerClass directly — the communication agent's executor derives the
// peer from the conversation row (never from model output), and the owner
// notifier targets InputPeerSelf, so neither has a peer string to resolve.
func SendToInputPeer(ctx context.Context, c *telegram.Client, userID int64, peer tg.InputPeerClass, text string) (int, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	randomID := int64(binary.LittleEndian.Uint64(b[:]))
	return SendToInputPeerWithRandomID(ctx, c, userID, peer, text, randomID)
}

// SendToInputPeerWithRandomID is SendToInputPeer's always-real-send path with
// a caller-supplied random_id instead of one generated internally — the
// executor's crash-recovery counterpart to SendMessageWithRandomID in
// send.go (same rationale: persist random_id before the RPC, retry with the
// identical id after a crash, rely on MTProto's server-side dedup).
func SendToInputPeerWithRandomID(ctx context.Context, c *telegram.Client, userID int64, peer tg.InputPeerClass, text string, randomID int64) (int, error) {
	if text == "" {
		return 0, fmt.Errorf("text required")
	}
	if randomID == 0 {
		return 0, fmt.Errorf("random id required")
	}
	updates, err := c.API().MessagesSendMessage(ctx, &tg.MessagesSendMessageRequest{
		Peer:     peer,
		Message:  text,
		RandomID: randomID,
		// Suppress link-preview expansion, matching SendMessage in send.go.
		// Owner notifications and agent replies are plain text; an unfurled
		// preview of a URL in the body is noise and a minor SSRF surface.
		NoWebpage: true,
	})
	if err != nil {
		return 0, classifySendError(err)
	}
	messageID := extractMessageID(updates)
	// Mark the server-assigned id before returning, matching SendMessage in
	// send.go: the communication listener consumes this marker when Telegram
	// echoes the outgoing message, so an executor reply sent to a recruiter
	// through this path is not misread as a manual owner takeover.
	notifyAgentSent(userID, int64(messageID))
	return messageID, nil
}

// ErrRandomIDDuplicate marks a send Telegram refused because its random_id
// was already used: an earlier send with that id was delivered (#1029).
var ErrRandomIDDuplicate = errors.New("random_id already used")

// classifySendError wraps a messages.sendMessage failure, tagging
// RANDOM_ID_DUPLICATE with ErrRandomIDDuplicate so callers can tell "already
// delivered" apart from a failed send.
func classifySendError(err error) error {
	if tgerr.Is(err, "RANDOM_ID_DUPLICATE") {
		return fmt.Errorf("send: %w: %w", ErrRandomIDDuplicate, err)
	}
	return fmt.Errorf("send: %w", err)
}

// SendToSelf sends a message to the account's own Saved Messages. This is the
// owner-notification path: a bot token cannot post into Saved Messages, so
// summaries and approval requests go through the owner's own MTProto session.
// It also marks its message id via notifyAgentSent like any other agent
// send; the listener only ever consumes marks for the peer whose echo it is
// actually watching, so a Saved Messages mark is simply never looked up —
// harmless, and keeping one code path avoids a userID==0 special case here.
func SendToSelf(ctx context.Context, c *telegram.Client, userID int64, text string) (int, error) {
	return SendToInputPeer(ctx, c, userID, &tg.InputPeerSelf{}, text)
}

// SendToSelfWithRandomID is SendToSelf's crash-safe counterpart: the caller
// supplies a random_id it has already persisted (see
// Store.ClaimOwnerNotification) instead of one generated fresh here, so a
// retry after a crash between this RPC succeeding and the caller recording
// it can reuse the SAME id — MTProto dedups on it server-side, exactly like
// SendToInputPeerWithRandomID's identical rationale for executor sends.
func SendToSelfWithRandomID(ctx context.Context, c *telegram.Client, userID, randomID int64, text string) (int, error) {
	return SendToInputPeerWithRandomID(ctx, c, userID, &tg.InputPeerSelf{}, text, randomID)
}

// locateHistoryLimit is how far back LocateOwnOutgoing looks in the chat.
// The send it looks for was reserved minutes earlier, so it is near the top
// unless the chat has been unusually busy since, in which case the id simply
// stays unknown.
const locateHistoryLimit = 50

// LocateOwnOutgoing finds the id of a message this account already sent to
// peer but whose send result was lost: Telegram refused a resend with
// RANDOM_ID_DUPLICATE, which carries no message (#1029). Messages do not
// expose random_id, so the match is on content: exactly one outgoing message
// with this text (whitespace-trimmed) dated at or after since. None or
// several is "not found". A found id is marked as an agent send, like a
// normal send's, so its echo is not read as the owner taking over.
func LocateOwnOutgoing(ctx context.Context, c *telegram.Client, userID int64, peer tg.InputPeerClass, text string, since time.Time) (int, bool, error) {
	hist, err := c.API().MessagesGetHistory(ctx, &tg.MessagesGetHistoryRequest{
		Peer:  peer,
		Limit: locateHistoryLimit,
	})
	if err != nil {
		return 0, false, fmt.Errorf("get history: %w", err)
	}
	modified, ok := hist.AsModified()
	if !ok {
		return 0, false, nil
	}
	id, found := uniqueOutgoingMatch(modified.GetMessages(), text, since)
	if found {
		notifyAgentSent(userID, int64(id))
	}
	return id, found, nil
}

// uniqueOutgoingMatch returns the id of the single outgoing message in msgs
// whose text equals text (both trimmed) and whose date is not before since.
// A second match makes the answer ambiguous, so it reports not found.
func uniqueOutgoingMatch(msgs []tg.MessageClass, text string, since time.Time) (int, bool) {
	want := strings.TrimSpace(text)
	if want == "" {
		return 0, false
	}
	// Telegram dates are whole seconds; the reservation time is not.
	floor := since.Truncate(time.Second).Unix()
	id, n := 0, 0
	for _, raw := range msgs {
		m, ok := raw.(*tg.Message)
		if !ok || !m.Out || int64(m.Date) < floor {
			continue
		}
		if strings.TrimSpace(m.Message) != want {
			continue
		}
		id, n = m.ID, n+1
	}
	return id, n == 1
}
