package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
	"github.com/mctlhq/mctl-telegram/internal/audit"
	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/mcpui"
	"github.com/mctlhq/mctl-telegram/internal/telegram"
)

// textSHA256 hashes the exact bytes of a prepared message body so the App
// can display which text a confirmation_id is bound to (alongside, not
// instead of, the confirmation itself -- HashSendPayload, not this value, is
// what send_message actually checks).
func textSHA256(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

// withUIResource returns a mcplib.ToolOption that sets a tool's _meta.ui
// link to the triage App resource (mcpui.ToolMeta), preserving any existing
// Meta.AdditionalFields and ProgressToken rather than clobbering them. It is
// applied, only when s.AppsEnabled, to the tools the App composes -- see
// addToolUI and newMCPServer. With the flag off no tool's builder ever calls
// this, so no tool carries a non-nil Meta.
//
// visibility inside mcpui.ToolMeta() is a host-side hint (which tools a
// conforming host lets the App itself invoke, versus model-only) -- it is
// never consulted by any handler in this package. requireScope and the send
// gate are the only server-side authority; see the proposal's "Open
// questions" for why.
func withUIResource() mcplib.ToolOption {
	return func(t *mcplib.Tool) {
		fields := map[string]any{}
		var progressToken mcplib.ProgressToken
		if t.Meta != nil {
			progressToken = t.Meta.ProgressToken
			for k, v := range t.Meta.AdditionalFields {
				fields[k] = v
			}
		}
		for k, v := range mcpui.ToolMeta() {
			fields[k] = v
		}
		t.Meta = &mcplib.Meta{ProgressToken: progressToken, AdditionalFields: fields}
	}
}

// prepareSendMessageResult is the success payload of prepare_send_message.
type prepareSendMessageResult struct {
	ConfirmationID string    `json:"confirmation_id"`
	PeerRedacted   string    `json:"peer_redacted"`
	Text           string    `json:"text"`
	TextSHA256     string    `json:"text_sha256"`
	WillReallySend bool      `json:"will_really_send"`
	DryReason      string    `json:"dry_reason,omitempty"`
	ExpiresAt      time.Time `json:"expires_at"`
}

// toolPrepareSendMessage registers prepare_send_message: a read-only
// snapshot of a send_message call the caller intends to confirm momentarily,
// modelled on toolPreparePinMessage. It makes no Telegram API call. The
// verdict it reports (will_really_send / dry_reason) comes from the exact
// same evaluateSendGate call send_message itself makes -- this tool reports
// that verdict, it does not decide anything, and reportsGateTools in
// portal_allowlist_test.go records that distinction for the AST-derived
// gate scan. Registered only when AppsEnabled (see newMCPServer), so the
// tool set with the flag off is unchanged.
func (s *Server) toolPrepareSendMessage() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("prepare_send_message",
		mcplib.WithTitleAnnotation("Prepare a message to send"),
		mcplib.WithReadOnlyHintAnnotation(false),
		mcplib.WithDestructiveHintAnnotation(false),
		mcplib.WithOpenWorldHintAnnotation(false),
		outputSchema[prepareSendMessageResult](),
		mcplib.WithDescription(`Snapshot a send_message call you intend to confirm momentarily.

Returns a one-shot confirmation_id valid for 10m that send_message may echo back as its optional confirmation_id argument. The pair is bound to sha256(peer, NUL, text) via HashSendPayload -- changing either value between prepare and confirm invalidates the confirmation. The prepare step makes no Telegram call.

The result also carries the send gate's current verdict (will_really_send, and dry_reason when false) computed the same way send_message itself computes it, so a caller can show "this will really send" or "preview only, because ..." before anything is confirmed. The verdict is informational: it is send_message's own evaluation at confirm time, not this call's, that is authoritative.

Inputs (required): peer, text.
Output: {confirmation_id, peer_redacted, text, text_sha256, will_really_send, dry_reason, expires_at}.`),
		mcplib.WithString("peer",
			mcplib.Required(),
			mcplib.Description("Peer to send to."),
		),
		mcplib.WithString("text",
			mcplib.Required(),
			mcplib.Description("Message text you intend to send."),
		),
	)
	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		startedAt := time.Now()
		id := auth.From(ctx)
		if id == nil {
			return mcplib.NewToolResultError("authentication required"), nil
		}
		args := req.GetArguments()
		peer := stringArg(args, "peer", "")
		text := stringArg(args, "text", "")
		if peer == "" || text == "" {
			return mcplib.NewToolResultError("peer and text are required"), nil
		}
		peerRedacted := telegram.RedactPeer(peer)
		if s.Limiter != nil && !s.Limiter.AllowPeer(id, peerRedacted, audit.PeerSendCap, audit.PeerWindow) {
			s.audit(ctx, id, "prepare_send_message:rate_limited", peerRedacted, nil, startedAt)
			return mcplib.NewToolResultError("per-peer rate limit reached (20/hour to one peer) — wait or pick a different recipient"), nil
		}
		willReallySend, dryReason := evaluateSendGate(ctx, s.Store, id, s.AllowSend, s.DemoReviewerTGID)
		c, err := s.Confirms.Issue(id.UserID, "send", HashSendPayload(peer, text))
		if err != nil {
			return toolErr("prepare_send_message: %v", err), nil
		}
		s.audit(ctx, id, "prepare_send_message", peerRedacted, nil, startedAt)
		return jsonResult(prepareSendMessageResult{
			ConfirmationID: c.ID,
			PeerRedacted:   peerRedacted,
			Text:           text,
			TextSHA256:     textSHA256(text),
			WillReallySend: willReallySend,
			DryReason:      dryReason,
			ExpiresAt:      c.ExpiresAt.UTC(),
		})
	}
	return tool, handler
}
