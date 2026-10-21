package mcp

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	gotdtelegram "github.com/gotd/td/telegram"
	mcplib "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/telegram"
)

// draft_reply and send_reply are the core-reply profile's write path
// (docs/design/core-profiles.md). They are profile-only tools
// (toolprofile.ProfileOnly): a caller without a profile never sees them, and
// send_message keeps its own contract unchanged.
//
// draft_reply sends nothing. It resolves the peer to a conversation that
// already exists, keeps the resolved recipient and the exact text on the
// server, and returns a one-shot confirmation_id. send_reply takes only that
// id and delivers what was drafted, to whom it was drafted, once. A closed
// send gate is an error there, never a preview: the preview was the draft.

// maxReplyText is Telegram's limit on one text message.
const maxReplyText = 4096

type draftReplyResult struct {
	ConfirmationID string    `json:"confirmation_id"`
	Recipient      string    `json:"recipient"`
	RecipientTitle string    `json:"recipient_title,omitempty"`
	Text           string    `json:"text"`
	ExpiresAt      time.Time `json:"expires_at"`
	// SendGateOpen says whether send_reply would deliver right now. It is
	// reported, not enforced here: send_reply evaluates the gate again.
	SendGateOpen   bool   `json:"send_gate_open"`
	SendGateReason string `json:"send_gate_reason,omitempty"`
	Notice         string `json:"notice"`
}

// resolveReplyTarget and deliverReply are the Telegram half of the two
// tools. Tests replace them through the Server's replyResolve and
// replyDeliver fields; nil means the client pool.
func (s *Server) resolveReplyTarget(ctx context.Context, userID int64, peer string) (*telegram.ReplyTarget, error) {
	if s.replyResolve != nil {
		return s.replyResolve(ctx, userID, peer)
	}
	var target *telegram.ReplyTarget
	err := s.borrowWithRetry(ctx, "draft_reply", userID, func(ctx context.Context, c *gotdtelegram.Client) error {
		var inner error
		target, inner = telegram.ResolveExistingDialog(ctx, c, peer, s.PeerCache, userID)
		return inner
	})
	return target, err
}

func (s *Server) deliverReply(ctx context.Context, userID int64, target *telegram.ReplyTarget, text string) (*telegram.SendResult, error) {
	if s.replyDeliver != nil {
		return s.replyDeliver(ctx, userID, target, text)
	}
	var result *telegram.SendResult
	err := s.borrowWithRetry(ctx, "send_reply", userID, func(ctx context.Context, c *gotdtelegram.Client) error {
		var inner error
		result, inner = telegram.SendReply(ctx, c, target, text, userID)
		return inner
	})
	return result, err
}

// isLocalBridgeAccount reports a Local Bridge account. Neither reply tool
// has a bridge-side implementation in v1.
func (s *Server) isLocalBridgeAccount(ctx context.Context, userID int64) bool {
	if s.Hub == nil || s.Store == nil {
		return false
	}
	mode, err := s.Store.GetAccountMode(ctx, userID)
	return err == nil && mode == "local"
}

func (s *Server) toolDraftReply() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("draft_reply",
		mcplib.WithTitleAnnotation("Draft Telegram Reply"),
		// Nothing is sent and nothing in Telegram changes; the only state is
		// the server-side draft send_reply may later deliver. It reads the
		// conversation's history to prove it exists, so it is open-world
		// like the other Telegram reads.
		mcplib.WithReadOnlyHintAnnotation(true),
		mcplib.WithDestructiveHintAnnotation(false),
		mcplib.WithOpenWorldHintAnnotation(true),
		outputSchema[draftReplyResult](),
		mcplib.WithDescription(`Prepare a reply in an existing Telegram conversation. Nothing is sent.

Returns the exact recipient and text and a one-shot confirmation_id, valid
for 10 minutes. Show the user the recipient and the text; only after they
agree, call send_reply with the confirmation_id. To change anything, draft
again.

The peer must be a conversation that already exists in the account's
history. A username or id the account has never talked to is refused: this
tool cannot start a new conversation.

Inputs (required):
  peer — "@username", "user:<id>", "chat:<id>", or "channel:<id>", as
         list_dialogs shows it.
  text — the reply, plain text, at most 4096 characters.`),
		mcplib.WithString("peer", mcplib.Required(), mcplib.Description("Existing conversation to reply in.")),
		mcplib.WithString("text", mcplib.Required(), mcplib.Description("Reply text, plain text, at most 4096 characters.")),
	)
	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		startedAt := time.Now()
		id := auth.From(ctx)
		if id == nil {
			return mcplib.NewToolResultError("authentication required"), nil
		}
		args := req.GetArguments()
		peer := strings.TrimSpace(stringArg(args, "peer", ""))
		text := stringArg(args, "text", "")
		if peer == "" || strings.TrimSpace(text) == "" {
			return mcplib.NewToolResultError("peer and text are required"), nil
		}
		if utf8.RuneCountInString(text) > maxReplyText {
			return mcplib.NewToolResultError("text must be at most 4096 characters"), nil
		}
		if s.Replies == nil {
			return mcplib.NewToolResultError("draft_reply is not available on this server"), nil
		}
		if s.isLocalBridgeAccount(ctx, id.UserID) {
			return mcplib.NewToolResultError("draft_reply is not yet supported for local-bridge accounts"), nil
		}
		peerRedacted := telegram.RedactPeer(peer)
		target, err := s.resolveReplyTarget(ctx, id.UserID, peer)
		if errors.Is(err, telegram.ErrNoExistingDialog) {
			s.auditRefusal(ctx, id, "draft_reply:no_dialog", peerRedacted, err, startedAt, ReasonRefused)
			return mcplib.NewToolResultError("draft_reply blocked: " + peer + " is not an existing conversation of this account; draft_reply only replies in conversations that already exist"), nil
		}
		if err != nil {
			s.audit(ctx, id, "draft_reply", peerRedacted, err, startedAt)
			return borrowErrResult(ctx, "draft_reply", err), nil
		}
		d, err := s.Replies.Issue(id.UserID, id.Profile, target, text)
		if err != nil {
			s.audit(ctx, id, "draft_reply", peerRedacted, err, startedAt)
			return mcplib.NewToolResultError("could not issue a confirmation: " + err.Error()), nil
		}
		open, reason := evaluateSendGate(ctx, s.Store, id, s.AllowSend, s.DemoReviewerTGID)
		s.audit(ctx, id, "draft_reply", peerRedacted, nil, startedAt)
		out := draftReplyResult{
			ConfirmationID: d.ID,
			Recipient:      target.Ref,
			RecipientTitle: target.Title,
			Text:           text,
			ExpiresAt:      d.ExpiresAt.UTC(),
			SendGateOpen:   open,
			Notice:         "Draft only — nothing was sent. Call send_reply with this confirmation_id once the user approves this recipient and text.",
		}
		if !open {
			out.SendGateReason = s.withSendDisabledHint(id, reason)
		}
		return jsonResult(out)
	}
	return tool, handler
}

func (s *Server) toolSendReply() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("send_reply",
		mcplib.WithTitleAnnotation("Send Drafted Telegram Reply"),
		// Delivers an irreversible message, but only the one draft_reply
		// showed, to the conversation it named.
		mcplib.WithReadOnlyHintAnnotation(false),
		mcplib.WithDestructiveHintAnnotation(true),
		mcplib.WithOpenWorldHintAnnotation(true),
		outputSchema[telegram.SendResult](),
		mcplib.WithDescription(`Send a reply prepared by draft_reply.

Takes only the confirmation_id. The recipient and the text are the ones
draft_reply returned; they cannot be changed here. Each confirmation_id
sends at most once and expires after 10 minutes. An unknown, expired or
already used id is an error: call draft_reply again.

If real sending is not enabled for this account, this is an error that says
why. Nothing is sent and no preview is returned.

Inputs (required):
  confirmation_id — the id draft_reply returned.`),
		mcplib.WithString("confirmation_id", mcplib.Required(), mcplib.Description("The one-shot id draft_reply returned.")),
	)
	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		startedAt := time.Now()
		id := auth.From(ctx)
		if id == nil {
			return mcplib.NewToolResultError("authentication required"), nil
		}
		confID := strings.TrimSpace(stringArg(req.GetArguments(), "confirmation_id", ""))
		if confID == "" {
			return mcplib.NewToolResultError("confirmation_id required"), nil
		}
		if s.Replies == nil {
			return mcplib.NewToolResultError("send_reply is not available on this server"), nil
		}
		// The gate and the account mode are read before the draft is
		// consumed, so a refusal the user can fix (turning sends on) keeps
		// the draft usable for the rest of its window.
		canSend, dryReason := evaluateSendGate(ctx, s.Store, id, s.AllowSend, s.DemoReviewerTGID)
		if !canSend {
			s.auditRefusal(ctx, id, "send_reply:blocked", "", errors.New(dryReason), startedAt, ReasonRefused)
			return mcplib.NewToolResultError("send_reply blocked: " + s.withSendDisabledHint(id, dryReason)), nil
		}
		if s.isLocalBridgeAccount(ctx, id.UserID) {
			return mcplib.NewToolResultError("send_reply is not yet supported for local-bridge accounts"), nil
		}
		d, err := s.Replies.Consume(confID, id.UserID, id.Profile)
		if err != nil {
			s.auditRefusal(ctx, id, "send_reply:confirmation_rejected", "", err, startedAt, ReasonNotFound)
			return mcplib.NewToolResultError(err.Error()), nil
		}
		peerRedacted := telegram.RedactPeer(d.Target.Ref)
		if blocked, r := evaluateDirectSendLimiter(s.Limiter, id, peerRedacted); blocked {
			s.auditRefusal(ctx, id, "send_reply:rate_limited", peerRedacted, errors.New(r), startedAt, ReasonRateLimited)
			return mcplib.NewToolResultError(r + " — the draft was used up; call draft_reply again later"), nil
		}
		result, err := s.deliverReply(ctx, id.UserID, d.Target, d.Text)
		s.audit(ctx, id, "send_reply:sent", peerRedacted, err, startedAt)
		if err != nil {
			return borrowErrResult(ctx, "send_reply", err), nil
		}
		return jsonResult(result)
	}
	return tool, handler
}
