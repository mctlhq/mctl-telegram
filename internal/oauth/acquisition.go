package oauth

import (
	"context"
	"net/http"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/acquisition"
	"github.com/mctlhq/mctl-telegram/internal/connectfunnel"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

// heardFromQuestionWindow limits the connect screen question to accounts
// created this recently, so an existing user who reconnects is not asked.
const heardFromQuestionWindow = 24 * time.Hour

// acquisitionFromRequest builds the JSON snapshot for a new pending-auth
// entry. It holds only the bounded mcp_client label.
func (s *Server) acquisitionFromRequest(redirectURI string) string {
	return acquisition.Marshal(acquisition.New(connectfunnel.ClientLabel(redirectURI), s.clock()))
}

// toDBAcquisition converts a snapshot to the persisted shape. The source is
// unknown until the person answers the connect screen question, if they do.
func toDBAcquisition(a acquisition.Snapshot) *db.Acquisition {
	return &db.Acquisition{
		State:      db.AcquisitionUnknown,
		MCPClient:  a.MCPClient,
		CapturedAt: a.CapturedAt,
	}
}

// shouldAskHeardFrom reports whether to show the optional question. A failed
// read hides it: the question is never worth a failed or noisy sign-in.
func (s *Server) shouldAskHeardFrom(ctx context.Context, uid int64) bool {
	ask, err := s.store.HeardFromUnanswered(ctx, uid, s.clock().Add(-heardFromQuestionWindow))
	if err != nil {
		s.logger().Warn("oauth: heard_from lookup failed", "err", err)
		return false
	}
	return ask
}

// recordHeardFrom stores the optional answer sent with the phone step, once.
// A missing or unlisted value stores nothing, and a failed write never blocks
// the sign-in. The caller holds es.lock.
func (s *Server) recordHeardFrom(r *http.Request, es *enableSession) {
	if !es.askHeardFrom {
		return
	}
	es.askHeardFrom = false
	answer := r.FormValue("heard_from")
	if !acquisition.ValidHeardFrom(answer) {
		return
	}
	if err := s.store.RecordHeardFrom(r.Context(), es.uid, answer); err != nil {
		s.logger().Warn("oauth: heard_from write failed", "err", err)
	}
}
