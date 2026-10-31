package mcp

import (
	"context"
	"strconv"
	"strings"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
	"github.com/mctlhq/mctl-telegram/internal/auth"
)

// The reviewer/demo identity (DEMO_REVIEWER_TG_ID, armed only while
// DEMO_REVIEWER_ENABLED is on) is a shared account that directory reviewers
// drive through a client that may auto-confirm writes. What it may change in
// Telegram is decided here, per tool, and fails closed:
//
//   - send_message and send_reply really deliver, but only to a peer listed
//     in DEMO_REVIEWER_WRITE_PEERS (Server.DemoReviewerWritePeers), and only
//     when the rest of the send gate is open as well;
//   - every other write is refused, as an error, never as a preview;
//   - a tool missing from reviewerWriteRules is refused, so a write tool
//     added later stays closed to the reviewer until someone decides
//     otherwise (TestReviewerWriteRules_CoverEveryRegisteredTool).
//
// Two layers enforce it. reviewerWriteGuard refuses a refused tool before
// its handler runs. Inside the handlers, the write gate (evaluateWriteGate)
// refuses the reviewer unless reviewerGateFor cleared that exact call, so a
// handler reached without the middleware is still closed.

type reviewerWriteRule int

const (
	// reviewerRefused: the reviewer may not call the tool at all.
	reviewerRefused reviewerWriteRule = iota
	// reviewerRead: a read-only tool; nothing in Telegram changes.
	reviewerRead
	// reviewerNoTelegramWrite: changes only this server's own state for the
	// caller (a confirmation, the caller's consent or notification
	// preferences), never anything in Telegram.
	reviewerNoTelegramWrite
	// reviewerAllowlistedPeer: a Telegram write the reviewer may make to a
	// peer in the allowlist, and to no other.
	reviewerAllowlistedPeer
	// reviewerAccountGuard: the handler refuses the reviewer itself
	// (demoReviewerAccountMgmtRefusal), so the existing message and audit
	// stay as they are.
	reviewerAccountGuard
)

// reviewerWriteRules classifies every registered tool for the reviewer
// identity. Absent means reviewerRefused.
var reviewerWriteRules = map[string]reviewerWriteRule{
	// Reads.
	"list_dialogs":                    reviewerRead,
	"get_unread_messages":             reviewerRead,
	"get_messages":                    reviewerRead,
	"search_messages":                 reviewerRead,
	"prepare_get_media":               reviewerRead,
	"get_media":                       reviewerRead,
	"get_my_identity":                 reviewerRead,
	"get_my_audit_log":                reviewerRead,
	"get_my_send_status":              reviewerRead,
	"get_my_notification_preferences": reviewerRead,
	"list_assistants":                 reviewerRead,
	// draft_reply stores a draft and sends nothing; send_reply decides.
	"draft_reply": reviewerRead,

	// The only Telegram writes the reviewer can make.
	"send_message": reviewerAllowlistedPeer,
	"send_reply":   reviewerAllowlistedPeer,

	// Issue a confirmation that a gated tool consumes, or change only the
	// caller's own state on this server. set_send_consent cannot widen the
	// reviewer: the reviewer rules apply whatever send_enabled says.
	"prepare_send_message":            reviewerNoTelegramWrite,
	"set_send_consent":                reviewerNoTelegramWrite,
	"set_my_notification_preferences": reviewerNoTelegramWrite,

	// Refused by their handlers with demoReviewerAccountMgmtRefusal.
	"disconnect_telegram_account": reviewerAccountGuard,
	"delete_telegram_account":     reviewerAccountGuard,

	// Telegram writes refused to the reviewer.
	"send_media":       reviewerRefused,
	"edit_message":     reviewerRefused,
	"delete_messages":  reviewerRefused,
	"forward_messages": reviewerRefused,
	"set_reaction":     reviewerRefused,
	"pin_message":      reviewerRefused,
	// The reviewer may prepare only what it may confirm. prepare_pin_message
	// also debits the per-peer send budget the allowlisted send needs.
	"prepare_pin_message": reviewerRefused,

	// An install decides whether the agent answers in Telegram as the
	// reviewer account, so it is not part of a review either.
	"install_assistant": reviewerRefused,
	"update_install":    reviewerRefused,
	// A fork is what an install would run, so it is not part of a review
	// either.
	"fork_assistant": reviewerRefused,
	"update_fork":    reviewerRefused,
	"delete_fork":    reviewerRefused,

	// Device, operator and broadcast tools: none is part of a review.
	"revoke_local_bridge_device": reviewerRefused,
	"list_telegram_identities":   reviewerRefused,
	"get_user_audit_log":         reviewerRefused,
	"set_telegram_access":        reviewerRefused,
	"set_account_send":           reviewerRefused,
	"set_account_mode":           reviewerRefused,
	"provision_local_account":    reviewerRefused,
	"revoke_telegram_session":    reviewerRefused,
	"revoke_worker_token":        reviewerRefused,
	"mint_worker_token":          reviewerRefused,
	"prepare_broadcast":          reviewerRefused,
	"list_broadcasts":            reviewerRefused,
	"get_broadcast":              reviewerRefused,
	"cancel_broadcast":           reviewerRefused,
}

// reasonReviewerWriteRefused is the write gate's reason when it refuses the
// reviewer. Handlers that answer other gate reasons with a dry-run preview
// (send_message, send_media) compare against it to answer with an error
// instead.
const reasonReviewerWriteRefused = "reviewer/demo account — real writes are limited to send_message and send_reply to a test chat listed in DEMO_REVIEWER_WRITE_PEERS (as user:<id>, chat:<id> or channel:<id>); nothing was sent"

// reviewerGate is what the write gate needs to know about the reviewer for
// one call: who the reviewer is, and whether reviewerGateFor cleared this
// call. The zero value clears nothing.
type reviewerGate struct {
	tgID    int64
	cleared bool
}

// reviewerGateFor decides one call: tool is the tool name and peer the
// recipient as the call names it. Only an allowlisted-peer tool aimed at a
// listed peer is cleared. A peer that is not in canonical typed form
// (an @username, a bare number, a malformed id) is never cleared: the
// allowlist holds ids, and resolving a name first would let the check and
// the delivery disagree.
func (s *Server) reviewerGateFor(tool, peer string) reviewerGate {
	g := reviewerGate{tgID: s.DemoReviewerTGID}
	if reviewerWriteRules[tool] != reviewerAllowlistedPeer {
		return g
	}
	if key, ok := canonicalPeerRef(peer); ok && s.DemoReviewerWritePeers[key] {
		g.cleared = true
	}
	return g
}

// canonicalPeerRef returns peer as "user:<id>", "chat:<id>" or
// "channel:<id>" when it is one of those forms with a positive id, which is
// how telegram.ResolvePeer reads it. Anything else is not comparable with
// the allowlist.
func canonicalPeerRef(peer string) (string, bool) {
	kind, num, ok := strings.Cut(strings.TrimSpace(peer), ":")
	if !ok {
		return "", false
	}
	switch kind {
	case "user", "chat", "channel":
	default:
		return "", false
	}
	n, err := strconv.ParseInt(num, 10, 64)
	if err != nil || n <= 0 {
		return "", false
	}
	return kind + ":" + strconv.FormatInt(n, 10), true
}

// reviewerWriteGuard is tool-handler middleware: a call by the reviewer to a
// tool classified reviewerRefused, or to a tool not classified at all, is
// refused before its handler runs. Every other call passes through, and the
// allowlisted tools still meet the peer check in their write gate.
func (s *Server) reviewerWriteGuard(next mcpserver.ToolHandlerFunc) mcpserver.ToolHandlerFunc {
	return func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		id := auth.From(ctx)
		if !isDemoReviewer(id, s.DemoReviewerTGID) {
			return next(ctx, req)
		}
		name := req.Params.Name
		if rule, ok := reviewerWriteRules[name]; ok && rule != reviewerRefused {
			return next(ctx, req)
		}
		hintReason(ctx, ReasonRefused)
		return mcplib.NewToolResultError(reviewerRefusalText(name)), nil
	}
}

// reviewerRefusalText is the error a refused reviewer write returns. The
// " blocked: " infix is what classifyToolResultReason reads as a refusal.
func reviewerRefusalText(tool string) string {
	return tool + " blocked: " + reasonReviewerWriteRefused
}

// reviewerWritePeerSet builds Server.DemoReviewerWritePeers from the config
// list, keeping only entries canonicalPeerRef accepts.
func reviewerWritePeerSet(peers []string) map[string]bool {
	out := make(map[string]bool, len(peers))
	for _, p := range peers {
		if key, ok := canonicalPeerRef(p); ok {
			out[key] = true
		}
	}
	return out
}
