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

// draftLimiterPrefix separates the draft budget's buckets from the send and
// cleanup budgets for the same peer. A draft reaches nobody, so it must not
// spend the send budget, and a full send budget must not stop a caller from
// leaving the user a draft to send themselves.
const draftLimiterPrefix = "draft|"

// evaluateDraftLimiter debits the per-(identity, peer) draft budget.
func evaluateDraftLimiter(limiter *audit.RateLimiter, id *auth.Identity, peer string) (blocked bool, reason string) {
	if limiter == nil {
		return false, ""
	}
	d := limiter.DecidePeer(id, draftLimiterPrefix+telegram.PeerLimitKey(peer), 1, audit.PeerSendCap, audit.PeerWindow)
	return peerLimitRefusal(d, fmt.Sprintf("per-peer draft rate limit reached (%d/hour to one chat)", audit.PeerSendCap), "")
}

type saveDraftResult struct {
	Peer             string `json:"peer"`
	Saved            bool   `json:"saved"`
	Cleared          bool   `json:"cleared"`
	ReplacedExisting bool   `json:"replaced_existing"`
	Unchanged        bool   `json:"unchanged"`
	Notice           string `json:"notice"`
}

// saveDraftFn is the Telegram call of save_draft; tests replace it through
// Server.draftSave.
func (s *Server) saveDraftFn(ctx context.Context, userID int64, peer, text string, overwrite bool) (telegram.DraftResult, error) {
	if s.draftSave != nil {
		return s.draftSave(ctx, userID, peer, text, overwrite)
	}
	var out telegram.DraftResult
	err := s.borrowWithRetry(ctx, "save_draft", userID, func(ctx context.Context, c *gotdtelegram.Client) error {
		var err error
		out, err = telegram.SaveDraft(ctx, c, peer, text, overwrite, s.PeerCache, userID)
		return err
	})
	return out, err
}

func (s *Server) toolSaveDraft() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("save_draft",
		mcplib.WithTitleAnnotation("Save Telegram Draft"),
		// Nothing is sent and nobody else sees it, but it changes the
		// user's own account, and with overwrite=true it replaces text
		// the user typed.
		mcplib.WithReadOnlyHintAnnotation(false),
		mcplib.WithDestructiveHintAnnotation(true),
		mcplib.WithOpenWorldHintAnnotation(true),
		outputSchema[saveDraftResult](),
		mcplib.WithDescription(`Put text into a Telegram chat's input box as an unsent draft. Nothing is sent.

The draft appears in every Telegram app of this account, and the user sends
it themselves, edits it or deletes it there. Nobody else sees a draft.
Because nothing is delivered, this works even when real sending is not
enabled for the account.

If the chat already holds a different unsent draft, the call is refused and
says how long that draft is: it is text the user typed and would be lost.
Ask the user first; pass overwrite=true only if they want it replaced.
An empty text clears the draft, under the same rule.

Inputs (required):
  peer — "@username", "user:<id>", "chat:<id>", or "channel:<id>", as
         list_dialogs shows it.
  text — the draft, plain text, at most 4096 UTF-16 units (most emoji count
         as two); "" clears the draft.
Inputs (optional):
  overwrite — replace a different draft already in the chat (default false).`),
		mcplib.WithString("peer", mcplib.Required(), mcplib.Description("Chat to leave the draft in.")),
		mcplib.WithString("text", mcplib.Required(), mcplib.Description("Draft text, plain text, at most 4096 UTF-16 units; empty clears the draft.")),
		mcplib.WithBoolean("overwrite", mcplib.Description("Replace a different unsent draft already in the chat (default false).")),
	)
	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		startedAt := time.Now()
		id := auth.From(ctx)
		args := req.GetArguments()
		peer := strings.TrimSpace(stringArg(args, "peer", ""))
		if _, ok := args["text"].(string); !ok {
			// Omitting text must not clear the draft by default; clearing
			// is asked for with an explicit empty string.
			return mcplib.NewToolResultError("text is required (pass an empty string to clear the draft)"), nil
		}
		text := stringArg(args, "text", "")
		overwrite := boolArg(args, "overwrite", false)
		if peer == "" {
			return mcplib.NewToolResultError("peer is required"), nil
		}
		if strings.TrimSpace(text) == "" {
			text = ""
		}
		if n := replyTextUnits(text); n > maxReplyText {
			return mcplib.NewToolResultError(fmt.Sprintf("text must be at most %d UTF-16 units (it is %d; most emoji count as two)", maxReplyText, n)), nil
		}
		// The send gate without the per-account send_enabled flag: a draft
		// is delivered to nobody, so the flag that guards delivery does
		// not apply (owner decision on mctl-telegram#1175). The kill
		// switch, the scope and the reviewer rule still do.
		if decided, _, reason := evaluateWriteGateBeforeAccount(id, s.AllowSend, s.reviewerGateFor("save_draft", peer), "telegram:messages:send"); decided {
			return mcplib.NewToolResultError("draft blocked: " + reason), nil
		}
		peerRedacted := telegram.RedactPeer(peer)
		if blocked, r := evaluateDraftLimiter(s.Limiter, id, peer); blocked {
			s.auditRefusal(ctx, id, "save_draft:rate_limited", peerRedacted, errors.New(r), startedAt, ReasonRateLimited)
			return mcplib.NewToolResultError(r), nil
		}
		if s.isLocalBridgeAccount(ctx, id.UserID) {
			return mcplib.NewToolResultError("save_draft is not yet supported for local-bridge accounts"), nil
		}
		res, err := s.saveDraftFn(ctx, id.UserID, peer, text, overwrite)
		var conflict *telegram.DraftConflict
		if errors.As(err, &conflict) {
			s.auditRefusal(ctx, id, "save_draft:draft_exists", peerRedacted, err, startedAt, ReasonRefused)
			return mcplib.NewToolResultError(fmt.Sprintf("draft blocked: %s already holds a different unsent draft that the user typed (%s). Nothing was changed. Ask the user; call again with overwrite=true only if they want it replaced.", peer, draftConflictSize(conflict))), nil
		}
		s.audit(ctx, id, "save_draft", peerRedacted, err, startedAt)
		if err != nil {
			return borrowErrResult(ctx, "save_draft", err), nil
		}
		notice := "Draft saved — nothing was sent. The user sends it from their Telegram app."
		switch {
		case res.Unchanged:
			notice = "The chat already held exactly this draft; nothing was changed."
		case res.Cleared:
			notice = "Draft cleared — nothing was sent."
		}
		return jsonResult(saveDraftResult{
			Peer:             peer,
			Saved:            !res.Unchanged && !res.Cleared,
			Cleared:          res.Cleared,
			ReplacedExisting: res.ReplacedExisting,
			Unchanged:        res.Unchanged,
			Notice:           notice,
		})
	}
	return tool, handler
}

// draftConflictSize describes the refused draft by size only, never by
// content.
func draftConflictSize(c *telegram.DraftConflict) string {
	if c.HasAttachment {
		return fmt.Sprintf("%d UTF-16 units of text plus an attachment or reply", c.ExistingUnits)
	}
	return fmt.Sprintf("%d UTF-16 units", c.ExistingUnits)
}
