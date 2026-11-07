package mcp

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	gotdtelegram "github.com/gotd/td/telegram"
	mcplib "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"

	"github.com/mctlhq/mctl-telegram/internal/audit"
	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/telegram"
)

// readLimiterPrefix separates the mark_read budget's buckets from the send,
// cleanup and draft budgets for the same peer, so marking a chat read never
// spends what a reply to it needs, and the other way round.
const readLimiterPrefix = "read|"

// evaluateReadLimiter debits the per-(identity, peer) mark_read budget. A
// PEER_FLOOD pause stops it like any other write that reaches the other
// side.
func evaluateReadLimiter(limiter *audit.RateLimiter, id *auth.Identity, peer string) (blocked bool, reason string) {
	if limiter == nil {
		return false, ""
	}
	if id != nil {
		if left := limiter.WriteHold(id.UserID); left > 0 {
			return true, peerFloodHoldMessage(left)
		}
	}
	d := limiter.DecidePeer(id, readLimiterPrefix+telegram.PeerLimitKey(peer), 1, audit.PeerSendCap, audit.PeerWindow)
	return peerLimitRefusal(d, fmt.Sprintf("per-peer mark_read rate limit reached (%d/hour to one chat)", audit.PeerSendCap), "")
}

type markReadResult struct {
	Peer   string `json:"peer"`
	MaxID  int    `json:"max_id"`
	Marked bool   `json:"marked"`
	// TopicID and TopicTitle name the forum topic marked read, when the
	// call named one.
	TopicID    int    `json:"topic_id,omitempty"`
	TopicTitle string `json:"topic_title,omitempty"`
	Notice     string `json:"notice"`
}

// markReadFn is the Telegram call of mark_read; tests replace it through
// Server.readMark.
func (s *Server) markReadFn(ctx context.Context, userID int64, peer string, maxID, topicID int) (telegram.MarkReadResult, error) {
	if s.readMark != nil {
		return s.readMark(ctx, userID, peer, maxID, topicID)
	}
	var out telegram.MarkReadResult
	err := s.borrowWithRetry(ctx, "mark_read", userID, func(ctx context.Context, c *gotdtelegram.Client) error {
		var err error
		out, err = telegram.MarkRead(ctx, c, peer, maxID, topicID, s.PeerCache, userID)
		return err
	})
	return out, err
}

func (s *Server) toolMarkRead() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("mark_read",
		mcplib.WithTitleAnnotation("Mark Telegram Chat Read"),
		// The other side of a private chat sees the read receipt, and it
		// cannot be taken back message by message.
		mcplib.WithReadOnlyHintAnnotation(false),
		mcplib.WithDestructiveHintAnnotation(true),
		mcplib.WithOpenWorldHintAnnotation(true),
		outputSchema[markReadResult](),
		mcplib.WithDescription(`Mark the messages of one Telegram chat as read, up to and including max_id.

The other side of a private chat sees that you read them (the double tick),
and the chat's unread counter drops in every Telegram app of this account.
It cannot be undone message by message, so it needs real sending enabled for
the account, like a send. Pass the id of the newest message the user has
actually seen (get_messages or get_unread_messages show the ids); messages
after it stay unread.

If real sending is not enabled for this account, this is an error that says
why. Nothing is marked.

In a forum supergroup each topic has its own unread counter: pass topic_id
(list_topics shows the ids) to mark only that topic read, up to max_id. The
topic must exist; a closed topic can still be marked read.

Inputs (required):
  peer   — "@username", "user:<id>", "chat:<id>", or "channel:<id>", as
           list_dialogs shows it.
  max_id — integer id of the newest message to mark read.
Inputs (optional):
  topic_id — forum topic to mark read (forum supergroups only).`),
		mcplib.WithString("peer", mcplib.Required(), mcplib.Description("Chat to mark read.")),
		mcplib.WithNumber("max_id", mcplib.Required(), mcplib.Description("ID of the newest message to mark read; later messages stay unread.")),
		mcplib.WithNumber("topic_id", mcplib.Description("Forum topic to mark read; forum supergroups only.")),
	)
	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		startedAt := time.Now()
		id := auth.From(ctx)
		args := req.GetArguments()
		peer := strings.TrimSpace(stringArg(args, "peer", ""))
		maxID, ok := messageIDArg(args, "max_id")
		if peer == "" || !ok {
			return mcplib.NewToolResultError("peer and a positive integer max_id (at most 2147483647) are required"), nil
		}
		topicID, bad := optionalTopicArg(args)
		if bad != nil {
			return bad, nil
		}
		// The full send gate, send_enabled included: a read receipt is
		// visible to the other side (owner decision on #1175).
		canSend, reason := evaluateSendGate(ctx, s.Store, id, s.AllowSend, s.reviewerGateFor("mark_read", peer))
		if !canSend {
			return mcplib.NewToolResultError("mark_read blocked: " + s.withSendDisabledHint(id, reason)), nil
		}
		peerRedacted := telegram.RedactPeer(peer)
		if blocked, r := evaluateReadLimiter(s.Limiter, id, peer); blocked {
			s.auditRefusal(ctx, id, "mark_read:rate_limited", peerRedacted, errors.New(r), startedAt, limiterRefusalReason(r))
			return mcplib.NewToolResultError(r), nil
		}
		if s.isLocalBridgeAccount(ctx, id.UserID) {
			return mcplib.NewToolResultError("mark_read is not yet supported for local-bridge accounts"), nil
		}
		res, err := s.markReadFn(ctx, id.UserID, peer, maxID, topicID)
		if isTopicRefusal(err) {
			s.auditRefusal(ctx, id, "mark_read:topic", peerRedacted, err, startedAt, ReasonRefused)
			return topicRefusalResult("mark_read", topicID, peer, err), nil
		}
		s.audit(ctx, id, "mark_read", peerRedacted, err, startedAt)
		if err != nil {
			return borrowErrResult(ctx, "mark_read", err), nil
		}
		notice := fmt.Sprintf("Marked read up to message %d; later messages stay unread.", maxID)
		if res.TopicID != 0 {
			notice = fmt.Sprintf("Marked topic %q read up to message %d; later messages and other topics stay unread.", res.TopicTitle, maxID)
		}
		return jsonResult(markReadResult{
			Peer:       peer,
			MaxID:      maxID,
			Marked:     true,
			TopicID:    res.TopicID,
			TopicTitle: res.TopicTitle,
			Notice:     notice,
		})
	}
	return tool, handler
}

// messageIDArg reads a Telegram message id: a positive whole number that
// fits the int32 the wire carries. A larger value would be truncated on
// the wire and mark a different message read than the one named, and a
// fraction would be silently rounded, so both are refused.
func messageIDArg(args map[string]any, key string) (int, bool) {
	var f float64
	switch v := args[key].(type) {
	case float64:
		f = v
	case int:
		f = float64(v)
	case int64:
		f = float64(v)
	default:
		return 0, false
	}
	if f <= 0 || f > math.MaxInt32 || f != math.Trunc(f) {
		return 0, false
	}
	return int(f), true
}

// optionalTopicArg reads an optional topic_id. Absent means no topic; a
// value that is not a positive whole message id is refused rather than
// rounded into a topic the caller did not name.
func optionalTopicArg(args map[string]any) (int, *mcplib.CallToolResult) {
	if _, given := args["topic_id"]; !given {
		return 0, nil
	}
	id, ok := messageIDArg(args, "topic_id")
	if !ok {
		return 0, mcplib.NewToolResultError("topic_id must be a positive topic id (a whole number, as list_topics shows it)")
	}
	return id, nil
}

// isTopicRefusal reports the topic errors that are Telegram's own answer
// about the named topic, as opposed to a failed call.
func isTopicRefusal(err error) bool {
	return errors.Is(err, telegram.ErrNotAForum) || errors.Is(err, telegram.ErrTopicNotFound) || errors.Is(err, telegram.ErrTopicClosed)
}

func topicRefusalResult(tool string, topicID int, peer string, err error) *mcplib.CallToolResult {
	return mcplib.NewToolResultError(fmt.Sprintf("%s blocked: topic_id %d in %s: %s; list_topics shows the topics of a forum", tool, topicID, peer, err.Error()))
}
