// Package agentapi is the restricted HTTP surface the communication agent's
// worker (whatever process invokes Claude — a headless Option-C worker today,
// an experimental Channels bridge later) talks to. It is the ONLY way agent
// code reaches mctl-telegram data or Telegram sends: there is no generic
// send/query tool, and every state-changing call still passes through the
// server-side policy engine (internal/agent/policy) before anything is
// authorized. Callers authenticate with a JWT carrying aud="agent", minted
// only by an admin via POST /api/agent/token (see tokenhandler.go).
package agentapi

import (
	"net/http"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/agent/queue"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/metrics"
)

// defaultLongPollTimeout bounds GET /events. Kept comfortably under the
// router's 60s middleware.Timeout (see cmd/server/main.go) so a slow claim
// loop is cut off by us, not by the framework returning a bare 503.
const defaultLongPollTimeout = 20 * time.Second

// OwnerProfileProvider supplies the owner's public profile for GET
// /recruiters/{peer}. It is a narrow interface (rather than a concrete type)
// so this package does not depend on internal/agent/profile, which is not
// part of this PR (see A-PR7, mctlhq/mctl-telegram#297) — Server works with a
// nil provider today and returns 501 for that one endpoint until #297 wires a
// real implementation in.
type OwnerProfileProvider interface {
	// PublicProfile returns the fields safe to hand to the agent — the
	// implementation is responsible for stripping anything marked
	// restricted/approval_required in the source profile. The peerTGID of
	// the requesting recruiter is passed through in case a future
	// implementation wants to vary the response per-peer; today's callers
	// can ignore it.
	PublicProfile(peerTGID int64) (map[string]any, error)
}

// Server holds the dependencies every handler needs. Construct with New,
// mount with Register.
type Server struct {
	Store   *db.Store
	Queue   *queue.Queue
	Profile OwnerProfileProvider
	// GlobalKill mirrors config.Config.AgentKillSwitch — the env-only kill
	// switch policy.Evaluate checks on every action. A public field (set
	// directly by main.go, matching e.g. mcpSrv.MediaDownloadMaxBytes
	// elsewhere in this codebase) rather than a constructor arg, since it can
	// change across a config reload without needing a new Server.
	GlobalKill bool

	longPollTimeout time.Duration
	jobVisibility   time.Duration
	m               *metrics.Registry
}

// New constructs a Server. m may be nil (tests). jobVisibility should match
// the sweeper's AGENT_JOB_VISIBILITY — it is only used to compute the
// advisory "deadline" field returned on a claimed job so the worker knows
// roughly how long it holds the claim before RequeueStaleAgentJobs reclaims
// it; the sweeper remains the actual enforcement.
func New(store *db.Store, q *queue.Queue, jobVisibility time.Duration, m *metrics.Registry) *Server {
	if jobVisibility <= 0 {
		jobVisibility = 5 * time.Minute
	}
	return &Server{
		Store:           store,
		Queue:           q,
		longPollTimeout: defaultLongPollTimeout,
		jobVisibility:   jobVisibility,
		m:               m,
	}
}

// WithProfile attaches an OwnerProfileProvider. Returns s for chaining.
func (s *Server) WithProfile(p OwnerProfileProvider) *Server {
	s.Profile = p
	return s
}

// WithLongPollTimeout overrides the GET /events hold time. Returns s for
// chaining. Exposed mainly so tests can use a short timeout.
func (s *Server) WithLongPollTimeout(d time.Duration) *Server {
	if d > 0 {
		s.longPollTimeout = d
	}
	return s
}

// registrar is the narrow router interface Register binds to — the same
// pattern internal/web.AccountHandlers.Register uses, so this package never
// imports chi directly.
type registrar interface {
	Get(pattern string, fn http.HandlerFunc)
	Post(pattern string, fn http.HandlerFunc)
}

// Register binds every /api/agent/v1 route onto mux. Paths are relative —
// mount at "/api/agent/v1" (behind the aud=agent auth middleware; see
// cmd/server/main.go's selectAgentProvider) and the effective URLs become
// e.g. "/api/agent/v1/events".
func (s *Server) Register(mux registrar) {
	mux.Get("/events", s.handleEvents)
	mux.Get("/event/{eventID}", s.handleGetEvent)
	mux.Get("/conversations/{id}/context", s.handleConversationContext)
	mux.Get("/recruiters/{peer}", s.handleRecruiterProfile)
	mux.Get("/leads/{id}", s.handleGetLead)
	mux.Get("/policy", s.handlePolicy)
	mux.Post("/actions/propose_reply", s.handleProposeReply)
	mux.Post("/leads", s.handleSaveLead)
	mux.Post("/actions/request_owner_approval", s.handleRequestOwnerApproval)
	mux.Post("/notify/summary", s.handleNotifySummary)
	mux.Post("/autopilot/pause", s.handleAutopilotPause)
	mux.Post("/jobs/{id}/complete", s.handleJobComplete)
}
