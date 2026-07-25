package main

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/mctlhq/mctl-telegram/internal/audit"
	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/telegram"
)

var errAgentSendGateDenied = errors.New("agent send gate denied")

// agentSendGate mirrors the direct MCP send boundary for background executor
// sends. The executor has no request Identity, so it reconstructs the owner's
// effective telegram:messages:send scope from the same admin/client tier
// inputs used by oauth.Server.ResolveScopes.
type agentSendGate struct {
	store              *db.Store
	allowSend          bool
	demoReviewerTGID   int64
	adminTelegramIDs   map[int64]bool
	clientTelegramIDs  map[int64]bool
	autoApproveClients bool
	limiter            *audit.RateLimiter
}

func (g *agentSendGate) Allow(ctx context.Context, userID, peerTGID int64) error {
	if !g.allowSend {
		return fmt.Errorf("%w: ALLOW_SEND=false", errAgentSendGateDenied)
	}
	tgID, err := g.store.GetTelegramID(ctx, userID)
	if err != nil {
		return fmt.Errorf("%w: resolve owner identity: %v", errAgentSendGateDenied, err)
	}
	if tgID == 0 {
		return fmt.Errorf("%w: owner has no active Telegram identity", errAgentSendGateDenied)
	}
	if g.demoReviewerTGID != 0 && tgID == g.demoReviewerTGID {
		return fmt.Errorf("%w: reviewer account is preview-only", errAgentSendGateDenied)
	}
	hasScope, err := g.hasSendScope(ctx, tgID)
	if err != nil {
		return fmt.Errorf("%w: resolve owner scope: %v", errAgentSendGateDenied, err)
	}
	if !hasScope {
		return fmt.Errorf("%w: owner lacks telegram:messages:send scope", errAgentSendGateDenied)
	}
	enabled, err := g.store.IsSendEnabled(ctx, userID)
	if err != nil {
		return fmt.Errorf("%w: check send_enabled: %v", errAgentSendGateDenied, err)
	}
	if !enabled {
		return fmt.Errorf("%w: send_enabled=false", errAgentSendGateDenied)
	}
	if g.limiter != nil {
		id := &auth.Identity{UserID: userID, Subject: "tg:" + strconv.FormatInt(tgID, 10), TelegramID: tgID}
		peer := telegram.RedactPeer("user:" + strconv.FormatInt(peerTGID, 10))
		if !g.limiter.AllowPeer(id, peer, audit.PeerSendCap, audit.PeerWindow) {
			return fmt.Errorf("%w: per-peer send rate limit reached", errAgentSendGateDenied)
		}
	}
	return nil
}

func (g *agentSendGate) hasSendScope(ctx context.Context, tgID int64) (bool, error) {
	if g.adminTelegramIDs[tgID] {
		return true, nil
	}
	tier, err := g.store.GetAccessTier(ctx, tgID)
	if err != nil {
		return false, err
	}
	switch tier {
	case db.TierClient:
		return true, nil
	case db.TierNone:
		return false, nil
	default:
		return g.autoApproveClients || g.clientTelegramIDs[tgID], nil
	}
}

func telegramIDSet(ids []int64) map[int64]bool {
	out := make(map[int64]bool, len(ids))
	for _, id := range ids {
		if id > 0 {
			out[id] = true
		}
	}
	return out
}
