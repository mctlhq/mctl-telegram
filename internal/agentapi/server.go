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
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/agent/queue"
	"github.com/mctlhq/mctl-telegram/internal/assistant"
	"github.com/mctlhq/mctl-telegram/internal/auth/localjwt"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/metrics"
)

// defaultLongPollTimeout bounds POST /jobs/claim. Kept comfortably under the
// router's 60s middleware.Timeout (see cmd/server/main.go) so a slow claim
// loop is cut off by us, not by the framework returning a bare 503.
const defaultLongPollTimeout = 20 * time.Second

// OwnerProfileProvider supplies the owner's profile for GET
// /recruiters/{peer} and the disclosure check on propose_reply (#953). It is
// a narrow interface so this package does not depend on
// internal/agent/profile; Server works with a nil provider and returns 501
// for that endpoint.
type OwnerProfileProvider interface {
	// PublicProfile returns the fields the agent may see in a conversation
	// whose owner-engagement state is engaged. The implementation strips
	// the restricted section, never fields, and after_owner_engaged fields
	// unless engaged.
	PublicProfile(ctx context.Context, userID int64, engaged bool) (map[string]any, error)
	// MatchProtected reports the strongest field the agent may not disclose
	// right now whose value appears in text; never is true for a field the
	// owner marked never. Only the field path is returned. inbound is the
	// peer's text in the turn being answered (#992).
	MatchProtected(ctx context.Context, userID int64, text, inbound string, engaged bool) (key string, never, matched bool, err error)
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
	// AllowLegacyJobCompletion is a temporary rolling-upgrade bridge for
	// workers that predate exact result linkage. Keep false normally; enable
	// only while old worker pods are draining, then disable after the new
	// workers are confirmed healthy.
	AllowLegacyJobCompletion bool

	// jobTokenSigner mints the per-job "agent-job" credential returned by
	// POST /jobs/claim. Nil leaves job_token out of the response.
	jobTokenSigner *localjwt.Issuer
	// catalog resolves an account's assistant to the instructions returned
	// by POST /jobs/claim. Nil leaves instructions out of the response.
	catalog *assistant.Catalog
	// registryGate applies registry lifecycles to claims (#1020): a pinned
	// definition that is disabled, or whose lifecycle is unknown, takes no
	// new jobs. Set by WithRegistryLifecycle when ASSISTANT_REGISTRY_ENABLED.
	registryGate bool
	// forksEnabled is ASSISTANT_FORKS_ENABLED (#1043): off, an account
	// that runs a private fork takes no new jobs.
	forksEnabled bool
	// now is the clock for the lifecycle gate; nil is time.Now.
	now func() time.Time
	// snapshots caches parsed registry definitions by digest.
	snapshotMu sync.Mutex
	snapshots  map[string]*assistant.Entry

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

// WithProfile attaches the tenant-aware OwnerProfileProvider. Returns s for
// chaining.
func (s *Server) WithProfile(p OwnerProfileProvider) *Server {
	s.Profile = p
	return s
}

// WithJobTokenSigner enables per-job credentials: every claimed job then
// carries a job_token bound to its job, attempt and conversation. Returns s
// for chaining.
func (s *Server) WithJobTokenSigner(i *localjwt.Issuer) *Server {
	s.jobTokenSigner = i
	return s
}

// WithCatalog makes POST /jobs/claim return each job's assistant
// instructions from c. Returns s for chaining.
func (s *Server) WithCatalog(c *assistant.Catalog) *Server {
	s.catalog = c
	return s
}

// WithRegistryLifecycle makes claims honor the registry lifecycle of each
// account's pinned definition (assistantregistry.LifecycleGate). Returns s
// for chaining.
func (s *Server) WithRegistryLifecycle() *Server {
	s.registryGate = true
	return s
}

// WithForks lets accounts run their private assistant forks
// (ASSISTANT_FORKS_ENABLED). Returns s for chaining.
func (s *Server) WithForks() *Server {
	s.forksEnabled = true
	return s
}

func (s *Server) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

// WithLongPollTimeout overrides the job-claim hold time. Returns s for
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
// e.g. "/api/agent/v1/jobs/claim". Every route passes through toolGate,
// which refuses a route serving a tool outside the caller's tool set
// (tools.Endpoints) and leaves the others alone.
func (s *Server) Register(mux registrar) {
	get := func(p string, h http.HandlerFunc) { mux.Get(p, s.toolGate("GET "+p, h)) }
	post := func(p string, h http.HandlerFunc) { mux.Post(p, s.toolGate("POST "+p, h)) }
	get("/events", s.handleLegacyEvents)
	get("/event/{eventID}", s.handleGetEvent)
	get("/conversations/{id}/context", s.handleConversationContext)
	get("/conversations/{id}/leads", s.handleConversationLeads)
	get("/recruiters/{peer}", s.handleRecruiterProfile)
	get("/leads/{id}", s.handleGetLead)
	get("/policy", s.handlePolicy)
	get("/jobs/{id}", s.handleGetJob)
	post("/actions/propose_reply", s.handleProposeReply)
	post("/leads", s.handleSaveLead)
	post("/actions/request_owner_approval", s.handleRequestOwnerApproval)
	post("/notify/summary", s.handleNotifySummary)
	post("/autopilot/pause", s.handleAutopilotPause)
	post("/jobs/claim", s.handleClaimJobs)
	post("/jobs/{id}/complete", s.handleJobComplete)
	// Worker-only cost report — deliberately absent from allowedTools and
	// NewMCPServer's tool list (internal/agentworker) so the model can never
	// assert its own spend. See handleReportJobCost's doc comment.
	post("/jobs/{id}/cost", s.handleReportJobCost)
}
