package telegram

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/gotd/td/telegram"
	"github.com/gotd/td/tg"
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
		return 0, fmt.Errorf("send: %w", err)
	}
	messageID := extractMessageID(updates)
	// Mark the server-assigned id before returning, matching SendMessage in
	// send.go: the communication listener consumes this marker when Telegram
	// echoes the outgoing message, so an executor reply sent to a recruiter
	// through this path is not misread as a manual owner takeover.
	notifyAgentSent(userID, int64(messageID))
	return messageID, nil
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
