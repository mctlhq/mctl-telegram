package agenteval

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Conformance serves the claim side of the agent API over a queue of the
// suite's fixtures, so a worker the harness does not link can be run
// against the C1 suite as a black box. Each fixture is a Task, unchanged:
// the Task checks, the recording and Score are the ones TestC1ObserveEval
// uses.
//
// The harness token stands for the account-scoped aud=agent token: it
// claims, and it is accepted on every per-job route as production accepts
// it. The job token returned in each claim envelope stands for aud=agent-job
// and is bound to the fixture it was issued for. Nothing here is a
// production credential: no server code reads either.
//
// Requests are routed by identity, never by "the fixture claimed most
// recently": a job token resolves to its own fixture and the harness token
// resolves through the job id the request names. Both tables are kept for
// the whole run, so a late request of a finished job still reaches its own
// fixture.
type Conformance struct {
	target *Target
	token  string
	hold   time.Duration

	drainOnce sync.Once
	drainCh   chan struct{}

	mu           sync.Mutex
	queue        []Fixture
	claimed      []*claimedJob
	byToken      map[string]*claimedJob
	byJob        map[int64]*claimedJob
	unattributed int
}

// claimedJob is one claimed fixture and what the settle step watches for.
type claimedJob struct {
	task     *Task
	fixture  Fixture
	jobID    int64
	jobToken string

	terminalAt time.Time
	lastReq    time.Time
	statusRead bool
	costRead   bool
}

// firstJobID is the job id of the first claimed fixture.
const firstJobID = 1000

// NewConformance returns the claim-serving fake for fixtures of t, accepting
// the harness token token. hold is how long a claim of an empty queue is
// held before it answers with no jobs; zero means one second.
func NewConformance(t *Target, fixtures []Fixture, token string, hold time.Duration) *Conformance {
	if hold <= 0 {
		hold = time.Second
	}
	return &Conformance{
		target: t, token: token, hold: hold,
		drainCh: make(chan struct{}),
		queue:   append([]Fixture(nil), fixtures...),
		byToken: map[string]*claimedJob{},
		byJob:   map[int64]*claimedJob{},
	}
}

// NewHarnessToken returns a fresh random bearer token.
func NewHarnessToken() string { return randomToken() }

func randomToken() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic("agenteval: no entropy: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// jobRoute extracts the job id a path names: /jobs/{id}[/complete|/cost].
var jobRoute = regexp.MustCompile(`^/jobs/([^/]+)(?:/(?:complete|cost))?$`)

// maxConformanceBody bounds a request body read for routing, as the
// production API's own limit does.
const maxConformanceBody = 1 << 20

func (c *Conformance) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	isAccount := subtle.ConstantTimeCompare([]byte(bearer), []byte(c.token)) == 1
	var owner *claimedJob
	if !isAccount {
		c.mu.Lock()
		owner = c.byToken[bearer]
		c.mu.Unlock()
		if owner == nil {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
	}

	if r.Method == http.MethodPost && r.URL.Path == "/jobs/claim" {
		if !isAccount {
			// Production refuses a job credential on the claim route.
			owner.task.RecordBindingViolation()
			http.Error(w, `{"error":"credential is bound to another conversation"}`, http.StatusForbidden)
			return
		}
		c.serveClaim(w, r)
		return
	}

	route, ok := routeOf(r)
	if !ok {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	write := r.Method == http.MethodPost && !strings.HasSuffix(route, "/cost")

	var raw []byte
	if r.Body != nil {
		var err error
		raw, err = io.ReadAll(http.MaxBytesReader(w, r.Body, maxConformanceBody))
		if err != nil {
			http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
			return
		}
	}
	named, hasNamed := namedJob(r.URL.Path, raw)

	var target *claimedJob
	switch {
	case owner != nil:
		if hasNamed && named != strconv.FormatInt(owner.jobID, 10) {
			owner.task.RecordBindingViolation()
			http.Error(w, `{"error":"credential is bound to another conversation"}`, http.StatusForbidden)
			return
		}
		target = owner
	case hasNamed:
		id, err := strconv.ParseInt(named, 10, 64)
		c.mu.Lock()
		target = c.byJob[id]
		c.mu.Unlock()
		if err != nil || target == nil {
			c.refuseUnattributed(w, nil)
			return
		}
	default:
		open := c.openJobs()
		if len(open) != 1 {
			c.refuseUnattributed(w, open)
			return
		}
		target = open[0]
	}

	c.touch(target, false, route)
	if write && target.task.Result().Terminal {
		// The fence production applies to a finished attempt. It changes no
		// score.
		http.Error(w, `{"error":"job is no longer claimed under that attempt"}`, http.StatusConflict)
		return
	}

	// Task takes one fixed token; the harness has already authenticated the
	// caller and routed the request to the fixture.
	r2 := r.Clone(r.Context())
	r2.Header.Set("Authorization", "Bearer "+target.task.token)
	r2.Body = io.NopCloser(bytes.NewReader(raw))
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	target.task.ServeHTTP(rec, r2)
	c.touch(target, rec.status/100 == 2, route)
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// namedJob returns the job id a request names in its path, else in a JSON
// body's job_id.
func namedJob(path string, body []byte) (string, bool) {
	if m := jobRoute.FindStringSubmatch(path); m != nil {
		return m[1], true
	}
	if len(body) == 0 {
		return "", false
	}
	var b struct {
		JobID *json.Number `json:"job_id"`
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&b); err != nil || b.JobID == nil {
		return "", false
	}
	return b.JobID.String(), true
}

// openJobs lists the claimed fixtures that are not terminal.
func (c *Conformance) openJobs() []*claimedJob {
	c.mu.Lock()
	all := append([]*claimedJob(nil), c.claimed...)
	c.mu.Unlock()
	var open []*claimedJob
	for _, j := range all {
		if !j.task.Result().Terminal {
			open = append(open, j)
		}
	}
	return open
}

// refuseUnattributed answers 409 for a request that names no single fixture.
// The violation is recorded on every fixture it could have meant, and counted
// for the run when none is open.
func (c *Conformance) refuseUnattributed(w http.ResponseWriter, candidates []*claimedJob) {
	c.mu.Lock()
	c.unattributed++
	c.mu.Unlock()
	for _, j := range candidates {
		j.task.RecordBindingViolation()
	}
	http.Error(w, `{"error":"job binding mismatch"}`, http.StatusConflict)
}

// touch records that a request reached j, and what the settle step watches:
// the post-terminal status read and cost report.
func (c *Conformance) touch(j *claimedJob, ok bool, route string) {
	terminal := j.task.Result().Terminal
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	j.lastReq = now
	if terminal && j.terminalAt.IsZero() {
		j.terminalAt = now
	}
	if terminal && ok {
		switch route {
		case "GET /jobs/{id}":
			j.statusRead = true
		case "POST /jobs/{id}/cost":
			j.costRead = true
		}
	}
}

func (c *Conformance) serveClaim(w http.ResponseWriter, r *http.Request) {
	select {
	case <-c.drainCh:
		writeJSON(w, map[string]any{"jobs": []any{}})
		return
	default:
	}
	if job, ok := c.claimNext(); ok {
		writeJSON(w, map[string]any{"jobs": []any{job}})
		return
	}
	timer := time.NewTimer(c.hold)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-c.drainCh:
	case <-r.Context().Done():
	}
	writeJSON(w, map[string]any{"jobs": []any{}})
}

// claimEnvelope is the claim response's job, in the agent API's wire shape.
type claimEnvelope struct {
	JobID          int64    `json:"job_id"`
	EventID        string   `json:"event_id"`
	ConversationID int64    `json:"conversation_id"`
	Attempt        int      `json:"attempt"`
	Deadline       string   `json:"deadline"`
	JobToken       string   `json:"job_token"`
	Instructions   string   `json:"instructions,omitempty"`
	Assistant      string   `json:"assistant,omitempty"`
	Tools          []string `json:"tools,omitempty"`
}

func (c *Conformance) claimNext() (claimEnvelope, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.queue) == 0 {
		return claimEnvelope{}, false
	}
	f := c.queue[0]
	c.queue = c.queue[1:]
	jobID := int64(firstJobID + len(c.claimed))
	jobToken := randomToken()
	j := &claimedJob{
		task:    NewTask(c.target, f, jobID, randomToken()),
		fixture: f, jobID: jobID, jobToken: jobToken,
	}
	c.claimed = append(c.claimed, j)
	c.byToken[jobToken] = j
	c.byJob[jobID] = j
	def := c.target.Entry.Definition.Metadata
	return claimEnvelope{
		JobID: jobID, EventID: "eval-" + f.ID, ConversationID: evalConversationID, Attempt: 1,
		Deadline:     time.Now().Add(3 * time.Minute).UTC().Format(time.RFC3339),
		JobToken:     jobToken,
		Instructions: c.target.Instructions,
		Assistant:    def.Name + "@" + def.Version,
		Tools:        c.target.JobTools,
	}, true
}

// Claimed returns how many fixtures have been claimed.
func (c *Conformance) Claimed() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.claimed)
}

// Finished reports whether every fixture has been claimed and is terminal.
func (c *Conformance) Finished() bool {
	c.mu.Lock()
	queued := len(c.queue)
	all := append([]*claimedJob(nil), c.claimed...)
	c.mu.Unlock()
	if queued > 0 {
		return false
	}
	for _, j := range all {
		if !j.task.Result().Terminal {
			return false
		}
	}
	return true
}

// Unattributed counts the requests that named no single fixture and were
// answered 409.
func (c *Conformance) Unattributed() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.unattributed
}

// Drain makes every claim, held or later, answer with no jobs at once, so a
// long-polling worker is released.
func (c *Conformance) Drain() { c.drainOnce.Do(func() { close(c.drainCh) }) }

// Settle waits until every claimed fixture has settled, or max has passed.
// A fixture settles when its post-terminal status read and cost report have
// both arrived, or when nothing has reached it for quiet (a black-box worker
// may send neither). It returns whether max passed first and the ids of the
// fixtures not settled then. A timeout is informational: it never changes
// what Score decides.
func (c *Conformance) Settle(ctx context.Context, quiet, max time.Duration) (timedOut bool, unsettled []string) {
	start := time.Now()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		unsettled = c.unsettled(start, quiet)
		if len(unsettled) == 0 {
			return false, nil
		}
		if time.Since(start) >= max {
			return true, unsettled
		}
		select {
		case <-ctx.Done():
			return true, unsettled
		case <-tick.C:
		}
	}
}

func (c *Conformance) unsettled(start time.Time, quiet time.Duration) []string {
	c.mu.Lock()
	all := append([]*claimedJob(nil), c.claimed...)
	c.mu.Unlock()
	now := time.Now()
	var out []string
	for _, j := range all {
		terminal := j.task.Result().Terminal
		c.mu.Lock()
		both := j.statusRead && j.costRead
		last := start
		for _, t := range []time.Time{j.lastReq, j.terminalAt} {
			if t.After(last) {
				last = t
			}
		}
		c.mu.Unlock()
		if terminal && both {
			continue
		}
		if now.Sub(last) >= quiet {
			continue
		}
		out = append(out, j.fixture.ID)
	}
	return out
}

// Results returns what each claimed fixture's run did, in claim order. A
// fixture never claimed has no result, and Score reports it missing.
func (c *Conformance) Results() []FixtureResult {
	c.mu.Lock()
	all := append([]*claimedJob(nil), c.claimed...)
	c.mu.Unlock()
	out := make([]FixtureResult, 0, len(all))
	for _, j := range all {
		out = append(out, j.task.Result())
	}
	return out
}

// JobToken returns the job token issued for the fixture id, for tests of a
// scripted worker.
func (c *Conformance) JobToken(fixtureID string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, j := range c.claimed {
		if j.fixture.ID == fixtureID {
			return j.jobToken, true
		}
	}
	return "", false
}
