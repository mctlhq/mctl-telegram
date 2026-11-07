package mcp

import (
	"context"
	"errors"
	"fmt"
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
	Notice string `json:"notice"`
}

// markReadFn is the Telegram call of mark_read; tests replace it through
// Server.readMark.
func (s *Server) markReadFn(ctx context.Context, userID int64, peer string, maxID int) error {
	if s.readMark != nil {
		return s.readMark(ctx, userID, peer, maxID)
	}
	return s.borrowWithRetry(ctx, "mark_read", userID, func(ctx context.Context, c *gotdtelegram.Client) error {
		_, err := telegram.MarkRead(ctx, c, peer, maxID, s.PeerCache, userID)
		return err
	})
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

Inputs (required):
  peer   — "@username", "user:<id>", "chat:<id>", or "channel:<id>", as
           list_dialogs shows it.
  max_id — integer id of the newest message to mark read.`),
		mcplib.WithString("peer", mcplib.Required(), mcplib.Description("Chat to mark read.")),
		mcplib.WithNumber("max_id", mcplib.Required(), mcplib.Description("ID of the newest message to mark read; later messages stay unread.")),
	)
	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		startedAt := time.Now()
		id := auth.From(ctx)
		args := req.GetArguments()
		peer := strings.TrimSpace(stringArg(args, "peer", ""))
		maxID := intArg(args, "max_id", 0)
		if peer == "" || maxID <= 0 {
			return mcplib.NewToolResultError("peer and a positive max_id are required"), nil
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
		err := s.markReadFn(ctx, id.UserID, peer, maxID)
		s.audit(ctx, id, "mark_read", peerRedacted, err, startedAt)
		if err != nil {
			return borrowErrResult(ctx, "mark_read", err), nil
		}
		return jsonResult(markReadResult{
			Peer:   peer,
			MaxID:  maxID,
			Marked: true,
			Notice: fmt.Sprintf("Marked read up to message %d; later messages stay unread.", maxID),
		})
	}
	return tool, handler
}
