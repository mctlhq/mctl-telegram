package oauth

import (
	"net/http"

	"github.com/mctlhq/mctl-telegram/internal/acquisition"
	"github.com/mctlhq/mctl-telegram/internal/connectfunnel"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

// acquisitionMetrics is the optional metrics surface for acquisition capture;
// asserted on s.metrics so other metricsIface implementations need not carry it.
type acquisitionMetrics interface {
	CountAcquisitionCapture(state, reason string)
}

// acquisitionFromRequest builds the JSON acquisition snapshot for a new
// pending-auth entry from the mctl_acq cookie. A missing, forged, malformed,
// oversized or expired cookie yields state unknown, never direct. The
// bounded mcp_client label is always set.
func (s *Server) acquisitionFromRequest(r *http.Request, redirectURI string) string {
	now := s.clock()
	client := connectfunnel.ClientLabel(redirectURI)
	snap := acquisition.Unknown(client, now)
	reason := "missing"
	if c, err := r.Cookie(acquisition.CookieName); err == nil {
		dec, derr := acquisition.Decode(s.acqKey, c.Value, now)
		switch derr {
		case nil:
			snap = dec
			snap.MCPClient = acquisition.Clean(client, 40)
			reason = "ok"
		case acquisition.ErrExpired:
			reason = "expired"
		default:
			reason = "invalid"
		}
	}
	if m, ok := s.metrics.(acquisitionMetrics); ok && m != nil {
		m.CountAcquisitionCapture(snap.State, reason)
	}
	return acquisition.Marshal(snap)
}

// toDBAcquisition converts a snapshot to the persisted shape.
func toDBAcquisition(a acquisition.Snapshot) *db.Acquisition {
	return &db.Acquisition{
		State:        a.State,
		ReferrerHost: a.ReferrerHost,
		UTMSource:    a.UTMSource,
		UTMMedium:    a.UTMMedium,
		UTMCampaign:  a.UTMCampaign,
		UTMContent:   a.UTMContent,
		UTMTerm:      a.UTMTerm,
		LandingPath:  a.LandingPath,
		MCPClient:    a.MCPClient,
		CapturedAt:   a.CapturedAt,
	}
}
