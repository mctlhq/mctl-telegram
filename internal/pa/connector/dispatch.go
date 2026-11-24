// Copyright 2025 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package connector

// dispatch.go is the server-side dispatcher of PA read tools (#1315 slice
// 2, threat model T2, T4, T8, T11, T12). The worker proposes a call with
// its pa-job token; everything that decides whether the call runs, and as
// whom, is server state:
//
//  1. the pa-job token is verified (signature, audience, expiry,
//     revocation). A refused token of ours is audited in its principal's
//     chain; one that cannot be attributed is counted only;
//  2. the request is parsed: server, tool, optional connection id,
//     arguments (a JSON object);
//  3. the flags are re-read: PA_EXTERNAL_TOOLS_ENABLED and the server's
//     PA_SERVER_<NAME>_ENABLED (S1-F4); a flag that cannot be read is off;
//  4. the job row admits the call (RunLoop.AdmitToolCall): signed tool set
//     of token and row, pinned read, cap, live reservation, consent,
//     conversation. The Policy comes from that row (I2, I10);
//  5. the connection is one the run bound, on the requested server (S1-X3),
//     and its stored grant is exactly the server's allowed scope;
//  6. the connection is re-checked at the bound authority revision and its
//     access token opened server-side (I1, I4). The connection the token
//     belongs to must be on the requested server, the endpoint's: a token
//     is never sent to another provider;
//  7. the server's tools/list (cached at most catalog.ReadListingTTL per
//     connection and revision) is compared with the pin; drift, an
//     unpinned tool or a non-read is denied (I7), a failed listing is
//     unavailable, never empty (I9). The drift signal is exported,
//     aggregated over the fresh listings of every connection;
//  8. Executor.Execute audits and dispatches through egress (I8); the
//     connection and the job row are re-checked after the call, and a
//     changed connection or a job no longer running (cancelled, consent
//     withdrawn) fences the result (S1-C7).
//
// Steps 6 to 8 run under one deadline (DispatcherConfig.CallTimeout).
// Refusals are audited at most refusalAuditBurst times per principal per
// refusalAuditWindow; beyond that they are counted only, and one summary
// row records how many were left out. Security-relevant refusals
// (securityReasons) have their own, larger bound (securityAuditBurst) and
// summary row, so bad_request traffic cannot use it up; the first refusal
// of each reason in a window is always written. The bound is in memory,
// per replica.
//
// The worker gets the tool result or a fixed refusal label; never a token,
// never error text.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/pa"
	"github.com/mctlhq/mctl-telegram/internal/pa/catalog"
	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
	"github.com/mctlhq/mctl-telegram/internal/pa/jobs"
)

// RouteTool is the dispatcher's route, next to the run loop's job routes.
const RouteTool = "/api/pa/v1/jobs/tool"

// maxToolRequestBytes bounds a tool request body.
const maxToolRequestBytes = 64 << 10

// JobGate is the run loop's half of the dispatcher (*pa.RunLoop).
type JobGate interface {
	AuthenticateAttributed(r *http.Request) (pa.PAJob, pa.TokenRefusal, error)
	AdmitToolCall(ctx context.Context, job pa.PAJob, server, tool string) (pa.Policy, error)
	StillRunning(ctx context.Context, job pa.PAJob) error
	// ConversationTainted reads the run's durable taint (T5, #1321). An
	// error comes with true and the call is recorded tainted (S2-I10).
	ConversationTainted(ctx context.Context, policy pa.Policy) (bool, error)
	// RecordToolResult stores a result as external conversation state,
	// which taints the conversation, before the worker sees it. An error
	// withholds the result.
	RecordToolResult(ctx context.Context, job pa.PAJob, output []byte) error
}

// Connections is the connection manager's half (*connection.Manager).
type Connections interface {
	List(ctx context.Context, principal int64) ([]connection.Connection, error)
	BeginCall(ctx context.Context, principal int64, id string, boundRevision int64) (*connection.Call, error)
	AccessToken(ctx context.Context, principal int64, id string, boundRevision int64) (connection.Secret, connection.Connection, error)
	// RefreshAccess is the 401 path: the server rejected the access token
	// of generation rejected (see connection.Manager.RefreshAccess).
	RefreshAccess(ctx context.Context, principal int64, id string, boundRevision, rejected int64) (connection.Secret, connection.Connection, error)
}

// Flags are the switches re-read at every dispatch (threat model T11).
type Flags struct {
	ExternalTools bool
	// Writes is PA_WRITES_ENABLED: off makes every write and disclosure
	// "never" (T11). The read path does not look at it; the card path
	// (Cards.Emit) hands it to the gate, and the write executor re-reads it.
	// WritesErr is the error of reading it; when set, Writes is false and
	// the gate decides writes off (gate.Input.WritesErr). It turns off
	// writes only: reads keep their own switches (T11, S1-F1).
	Writes    bool
	WritesErr error
	// Servers is PA_SERVER_<NAME>_ENABLED per server. A server whose flag
	// cannot be read is off, with the error in ServerErrs; the other
	// servers keep their own flags (S1-F1).
	Servers    map[string]bool
	ServerErrs map[string]error
}

// MCPEndpoint is one catalog server's MCP surface. *Endpoint is the only
// production implementation: it reaches the server through
// internal/pa/egress (I8).
type MCPEndpoint interface {
	Server() string
	ListTools(ctx context.Context, token connection.Secret) ([][]byte, error)
	CallTool(ctx context.Context, token connection.Secret, tool string, args json.RawMessage) ([]byte, error)
}

// Metrics is what the dispatcher exports (*metrics.Registry).
type Metrics interface {
	PAPinObserved(server string, drift bool, denied map[string]int, reasons []string)
	PAPinUnknown(server string)
	CountPAListingFailure(server, reason string)
	// PreparePAListingFailures creates server's failure series at 0 for
	// every reason, so the first failure is an increase, not a new series.
	PreparePAListingFailures(server string, reasons []string)
	CountPADispatch(server, status, reason string)
	// CountPAWriteListingRefusal counts one write refused at dispatch
	// because of the tool's fresh listing (WriteListingRefusalReasons).
	CountPAWriteListingRefusal(server, reason string)
	// PreparePAWriteListingRefusals creates server's series at 0 for
	// every reason.
	PreparePAWriteListingRefusals(server string, reasons []string)
}

// DefaultCallTimeout bounds one dispatch from opening the token to the
// tools/call answer, the tools/list included.
const DefaultCallTimeout = 60 * time.Second

// PinObservationWindow is how long one connection's tools/list observation
// counts toward the server's drift gauges. Listings are read per connection
// (and revision); the gauges aggregate the fresh observations of all of
// them, so one connection's failure does not hide drift another one saw.
const PinObservationWindow = 5 * time.Minute

// PinRefreshInterval is how often Run ages observations out of the gauges
// when no dispatch does it.
const PinRefreshInterval = 30 * time.Second

// Refusal audit bound: a worker cannot write more than refusalAuditBurst
// general and securityAuditBurst security refusals per refusalAuditWindow
// into one principal's chain, plus the first refusal of each reason (a
// closed set). Past it, a refusal is still refused and counted (status
// refused_unaudited), and when the window closes one summary row per
// class carries the count: refusals_suppressed for general reasons,
// refusals_suppressed_security for securityReasons. The windows live in
// memory, so the bound is per replica and restarts with the process.
const (
	refusalAuditWindow     = time.Minute
	refusalAuditBurst      = 30
	securityAuditBurst     = 300
	statusRefusedUnaudited = "refused_unaudited"
)

// Reasons of mctl_pa_pin_listing_failures_total: the server refused the
// connection's token, the read failed, or the listing did not parse.
const (
	listingUnauthorized = "unauthorized"
	listingUnavailable  = "unavailable"
	listingInvalid      = "invalid"
)

// ListingFailureReasons is the closed reason label set of
// mctl_pa_pin_listing_failures_total.
var ListingFailureReasons = []string{listingUnauthorized, listingUnavailable, listingInvalid}

// maxRefusalPrincipals bounds the open windows. A new principal past it
// first closes every window that has ended, writing their summaries. A
// variable so tests can lower it.
var maxRefusalPrincipals = 4096

// securityReasons are the refusals that are evidence of a worker probing
// another principal's connections, tools outside its set, a stale job or a
// bad token. They are bounded separately (securityAuditBurst) and do not
// use the general bound, so a worker cannot spend the window on
// bad_request and then probe unrecorded; nor can it flood the chain with
// probes, which a worker can send at line rate (tool_not_in_set is decided
// before the per-run call cap, job_stale and token_* after the run).
var securityReasons = map[string]bool{
	ReasonConnectionUnbound: true,
	ReasonToolNotInSet:      true,
	ReasonJobStale:          true,
	ReasonTokenExpired:      true,
	ReasonTokenRevoked:      true,
	ReasonTokenInvalid:      true,
	ReasonTokenUnverifiable: true,
}

// DispatcherConfig wires a Dispatcher. Every field but Metrics and Now is
// required.
type DispatcherConfig struct {
	Jobs        JobGate
	Connections Connections
	Pin         *catalog.Pin
	Endpoints   map[string]MCPEndpoint
	Executor    *Executor
	// Flags is called once per request. An error refuses the call.
	Flags   func() (Flags, error)
	Metrics Metrics
	Now     func() time.Time
	// CallTimeout bounds token, tools/list and tools/call of one request;
	// 0 is DefaultCallTimeout.
	CallTimeout time.Duration
	// Cards takes the calls of approve-tier tools: such a call gets an
	// approval card and no downstream call (card.go, #1320 slice P2-S5).
	// Optional, and nil in every deployed wiring: without it the tool
	// route is the Phase 1 read path alone.
	Cards *Cards
}

// Dispatcher serves RouteTool.
type Dispatcher struct {
	cfg DispatcherConfig

	mu           sync.Mutex
	listings     map[listingKey]cachedSurface
	observations map[listingKey]pinObservation
	// pinServers are the servers whose gauges were ever published; each
	// is recomputed on every refresh, so none keeps a value no fresh
	// observation supports.
	pinServers map[string]bool
	refusals   map[int64]*auditWindow
}

// pinObservation is one connection's tools/list history: the last
// listing that was read and parsed (okAt, drift, denied) and, separately,
// the last failure. A failure never overwrites a successful listing: a
// server that alternates a drifted listing with errors keeps reporting the
// drift while the listing is fresh. Times are when the listing started,
// so a slow read that finishes late cannot replace a newer one.
type pinObservation struct {
	okAt   time.Time
	drift  bool
	denied map[string]int
	failAt time.Time
}

// auditWindow is one principal's refusal window, per class (general,
// security). seen holds the reasons already written once in it.
type auditWindow struct {
	start      time.Time
	n          [2]int
	suppressed [2]int
	seen       map[string]bool
}

const (
	classGeneral = iota
	classSecurity
)

var (
	classBurst   = [2]int{refusalAuditBurst, securityAuditBurst}
	classSummary = [2]string{ReasonRefusalsSuppressed, ReasonRefusalsSuppressedSecurity}
)

// suppressedRefusals is one principal's count of refusals of one class
// left out of its chain in a closed window.
type suppressedRefusals struct {
	principal int64
	reason    string
	n         int
}

// summaries returns w's suppressed counts still to be written.
func (w *auditWindow) summaries(principal int64) []suppressedRefusals {
	var out []suppressedRefusals
	for c, n := range w.suppressed {
		if n > 0 {
			out = append(out, suppressedRefusals{principal, classSummary[c], n})
		}
	}
	return out
}

// cachedSurface is a successful listing and when it started. Like
// pinObservation, the cache is ordered by start time: a slow read that
// finishes late neither replaces nor deletes a newer listing, so calls
// authorize against the same listing the gauges report.
type cachedSurface struct {
	s  *catalog.Surface
	at time.Time
}

type listingKey struct {
	server, connection string
	revision           int64
}

// NewDispatcher refuses an incomplete configuration, and an endpoint for a
// server the pin does not have.
func NewDispatcher(cfg DispatcherConfig) (*Dispatcher, error) {
	if cfg.Jobs == nil || cfg.Connections == nil || cfg.Pin == nil || cfg.Executor == nil ||
		cfg.Executor.Sink == nil || cfg.Flags == nil {
		return nil, errors.New("pa connector: dispatcher needs jobs, connections, a pin, an executor and flags")
	}
	for name, ep := range cfg.Endpoints {
		if _, ok := cfg.Pin.Servers[name]; !ok || ep == nil || ep.Server() != name {
			return nil, fmt.Errorf("pa connector: endpoint %q is not a catalog server", name)
		}
	}
	if cfg.Metrics != nil {
		for name := range cfg.Endpoints {
			cfg.Metrics.PreparePAListingFailures(name, ListingFailureReasons)
		}
	}
	return &Dispatcher{
		cfg: cfg, listings: map[listingKey]cachedSurface{},
		observations: map[listingKey]pinObservation{}, pinServers: map[string]bool{},
		refusals: map[int64]*auditWindow{},
	}, nil
}

// Mount registers RouteTool.
func (d *Dispatcher) Mount(mux interface{ Handle(string, http.Handler) }) {
	mux.Handle(RouteTool, d)
}

func (d *Dispatcher) now() time.Time {
	if d.cfg.Now != nil {
		return d.cfg.Now()
	}
	return time.Now()
}

func (d *Dispatcher) pinned(server string) bool {
	_, ok := d.cfg.Pin.Servers[server]
	return ok
}

// toolRequest is the worker's proposal.
type toolRequest struct {
	Server       string          `json:"server"`
	Tool         string          `json:"tool"`
	ConnectionID string          `json:"connection_id"`
	Arguments    json.RawMessage `json:"arguments"`
}

// toolResponse is the answer to an executed call. Output is the tool's
// JSON-RPC result as text, capped at jobs.MaxToolOutputBytes. It is
// external content whatever it holds (T5).
type toolResponse struct {
	Status    string `json:"status"`
	Output    string `json:"output,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
}

type refusalResponse struct {
	Stop string `json:"stop"`
}

// refusal is a decided "no": its reason and HTTP status.
type refusal struct {
	reason string
	code   int
}

func (d *Dispatcher) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	job, tr, err := d.cfg.Jobs.AuthenticateAttributed(r)
	if err != nil {
		reason, code := tr.Reason, http.StatusUnauthorized
		switch reason {
		case ReasonTokenExpired, ReasonTokenRevoked:
		case ReasonTokenUnverifiable:
			code = http.StatusServiceUnavailable
		default:
			reason = ReasonTokenInvalid
		}
		// Only a token this server minted names a chain to write to.
		d.refuse(w, r, Refusal{Principal: tr.Principal, Reason: reason}, code)
		return
	}
	principal := job.Principal()

	var req toolRequest
	body := http.MaxBytesReader(w, r.Body, maxToolRequestBytes)
	dec := json.NewDecoder(body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || !atEOF(dec) || !jsonObject(req.Arguments) {
		d.refuse(w, r, Refusal{Principal: principal, Server: req.Server, Tool: req.Tool,
			ConnectionID: req.ConnectionID, Reason: ReasonBadRequest}, http.StatusBadRequest)
		return
	}
	base := Refusal{Principal: principal, Server: req.Server, Tool: req.Tool, ConnectionID: req.ConnectionID, Args: req.Arguments}

	if !d.pinned(req.Server) {
		d.refuse(w, r, with(base, ReasonUnknownServer), http.StatusForbidden)
		return
	}
	flags, err := d.cfg.Flags()
	if err != nil || !flags.ExternalTools || !flags.Servers[req.Server] {
		d.refuse(w, r, with(base, ReasonFlagOff), http.StatusForbidden)
		return
	}

	policy, err := d.cfg.Jobs.AdmitToolCall(r.Context(), job, req.Server, req.Tool)
	if err != nil {
		ref := jobRefusal(err)
		d.refuse(w, r, with(base, ref.reason), ref.code)
		return
	}

	bound, ref := d.resolveConnection(r.Context(), policy, req.Server, req.ConnectionID)
	if ref != nil {
		d.refuse(w, r, with(base, ref.reason), ref.code)
		return
	}
	base.ConnectionID, base.AuthorityRevision = bound.ConnectionID, bound.AuthorityRevision

	ep := d.cfg.Endpoints[req.Server]
	if ep == nil || ep.Server() != req.Server {
		d.refuse(w, r, with(base, ReasonServerUnavailable), http.StatusServiceUnavailable)
		return
	}

	call, err := d.cfg.Connections.BeginCall(r.Context(), principal, bound.ConnectionID, bound.AuthorityRevision)
	if err != nil {
		ref := connectionRefusal(err)
		d.refuse(w, r, with(base, ref.reason), ref.code)
		return
	}
	dispatched := false
	defer func() {
		if !dispatched {
			call.Abandon()
		}
	}()
	ctx, cancel := context.WithTimeout(call.Ctx, d.callTimeout())
	defer cancel()
	token, conn, err := d.cfg.Connections.AccessToken(ctx, principal, bound.ConnectionID, bound.AuthorityRevision)
	if err != nil {
		ref := connectionRefusal(err)
		d.refuse(w, r, with(base, ref.reason), ref.code)
		return
	}
	// Defense in depth for S1-X3: resolveConnection only picks connections
	// on req.Server, and the token opened must belong to exactly that one.
	// A token is never sent to another provider's endpoint.
	if conn.ID != bound.ConnectionID || conn.Principal != principal || string(conn.Server) != req.Server {
		d.refuse(w, r, with(base, ReasonConnectionUnbound), http.StatusForbidden)
		return
	}

	if d.cfg.Cards != nil && d.cfg.Cards.Covers(req.Server, req.Tool) {
		// An approve-tier tool is never called from here: it gets a card,
		// or, for a write a standing permission covers, the write executor
		// sends it. The call was admitted and counted toward the run's
		// call cap above (T10).
		lowered, ref := d.cfg.Cards.Emit(ctx, CardRequest{
			Policy: policy, JobID: job.JobID(), ConnectionID: bound.ConnectionID,
			AuthorityRevision: bound.AuthorityRevision, Server: req.Server, Tool: req.Tool,
			Args: req.Arguments, Token: token, Flags: flags,
		})
		if ref != nil {
			d.refuse(w, r, with(base, ref.reason), ref.code)
			return
		}
		if lowered != nil {
			// A standing permission stood in for the card and the write
			// executor handled the call (lower.go).
			d.answerLowered(w, req.Server, *lowered)
			return
		}
		d.count(req.Server, StatusApprovalPending, "")
		writeJSON(w, http.StatusOK, toolResponse{Status: StatusApprovalPending, Output: approvalPendingOutput})
		return
	}

	// One refresh per tool request (#1318 slice C2b): a 401 on tools/list
	// or on tools/call gets exactly one refresh and one retry, and a 401
	// after it is a refusal. A 403 is never retried: the server accepted
	// the token and refused the request.
	refreshed := false
	surface, refusedErr := d.surface(ctx, ep, token, bound)
	if errors.Is(refusedErr, ErrMCPTokenRejected) {
		refreshed = true
		var ref *refusal
		token, conn, ref = d.refreshAccess(ctx, principal, req.Server, bound, conn)
		if ref != nil {
			d.refuse(w, r, with(base, ref.reason), ref.code)
			return
		}
		surface, refusedErr = d.surface(ctx, ep, token, bound)
	}
	if refusedErr != nil {
		// The server refused this connection's token on tools/list.
		d.refuse(w, r, with(base, ReasonServerRefused), http.StatusBadGateway)
		return
	}
	if surface.Server() != req.Server {
		d.refuse(w, r, with(base, ReasonConnectionUnbound), http.StatusForbidden)
		return
	}

	res, err := d.cfg.Executor.Execute(ctx, surface, Call{
		Policy:       policy,
		ConnectionID: bound.ConnectionID,
		Tool:         req.Tool,
		Args:         req.Arguments,
		Taint:        d.taint(ctx, policy),
	}, func(ctx context.Context) (res Result, err error) {
		dispatched = true
		// The post-dispatch checks run whatever the call did, a panic
		// included (the call is deregistered either way): a result that
		// arrives after the connection changed, or after the job stopped
		// running (cancelled, consent withdrawn), is discarded. So is one
		// whose recording as conversation state failed: the worker never
		// gets tool output that did not taint its conversation (#1321).
		defer func() {
			fctx := context.WithoutCancel(ctx)
			ferr := call.Finish(fctx)
			if ferr == nil {
				ferr = d.cfg.Jobs.StillRunning(fctx, job)
			}
			if ferr == nil && err == nil {
				// Recorded as the worker will see it: capped.
				out, _ := jobs.TruncateToolOutput(res.Output)
				ferr = d.cfg.Jobs.RecordToolResult(fctx, job, out)
			}
			var rr *refreshRefusal
			if ferr != nil && !errors.As(err, &rr) {
				// A failed refresh after a 401 sent nothing that ran,
				// and may itself have moved the connection (expired):
				// its reason is the truthful one, not "fenced".
				res, err = Result{}, fmt.Errorf("%w: %w", ErrDispatchFenced, ferr)
			}
		}()
		out, cerr := ep.CallTool(ctx, token, req.Tool, req.Arguments)
		if errors.Is(cerr, ErrMCPTokenRejected) && !refreshed {
			// The server rejected the token before running the call,
			// so it is sent once more with a refreshed token.
			refreshed = true
			fresh, _, ref := d.refreshAccess(ctx, principal, req.Server, bound, conn)
			if ref != nil {
				return Result{}, &refreshRefusal{ref: *ref}
			}
			out, cerr = ep.CallTool(ctx, fresh, req.Tool, req.Arguments)
		}
		if errors.Is(cerr, ErrMCPUnauthorized) {
			return Result{}, fmt.Errorf("%w: %w", ErrDispatchRefused, cerr)
		}
		if cerr != nil {
			return Result{}, cerr
		}
		isErr, perr := toolResultIsError(out)
		if perr != nil {
			return Result{}, perr
		}
		return Result{Output: out, ToolError: isErr}, nil
	})
	if err != nil {
		d.answerExecuteError(w, req.Server, err)
		return
	}
	status := StatusOK
	if res.ToolError {
		status = StatusToolError
	}
	out, truncated := jobs.TruncateToolOutput(res.Output)
	d.count(req.Server, string(status), "")
	writeJSON(w, http.StatusOK, toolResponse{Status: string(status), Output: string(out), Truncated: truncated})
}

// taint is the run's taint for the audit record: the conversation's
// durable flag, read at dispatch (T5, #1321). Only a flag read as clean is
// clean; a read error is external (S2-I10). It labels the record; no gate
// is lowered by it here.
func (d *Dispatcher) taint(ctx context.Context, policy pa.Policy) Taint {
	tainted, err := d.cfg.Jobs.ConversationTainted(ctx, policy)
	if err != nil {
		slog.Warn("pa dispatch: conversation taint unreadable, recorded as external", "err", err)
		return TaintExternal
	}
	if tainted {
		return TaintExternal
	}
	return TaintClean
}

func (d *Dispatcher) callTimeout() time.Duration {
	if d.cfg.CallTimeout > 0 {
		return d.cfg.CallTimeout
	}
	return DefaultCallTimeout
}

// toolResultIsError reads the isError flag of a tools/call result. A result
// that is not a JSON object is a protocol error: the call ran, so its
// outcome is unknown.
func toolResultIsError(out []byte) (bool, error) {
	var r struct {
		IsError bool `json:"isError"`
	}
	t := bytes.TrimSpace(out)
	if len(t) == 0 || t[0] != '{' || json.Unmarshal(t, &r) != nil {
		return false, fmt.Errorf("%w: tools/call result is not an object", ErrMCPProtocol)
	}
	return r.IsError, nil
}

// answerExecuteError maps an Execute error to the worker's answer. The
// executor has already audited it.
func (d *Dispatcher) answerExecuteError(w http.ResponseWriter, server string, err error) {
	var reason string
	code := http.StatusForbidden
	status := StatusRefused
	var rr *refreshRefusal
	switch {
	case errors.As(err, &rr):
		reason, code = rr.ref.reason, rr.ref.code
	case errors.Is(err, ErrAuditUnavailable):
		reason, code = ReasonAuditUnavailable, http.StatusServiceUnavailable
	case errors.Is(err, ErrDispatchFenced):
		reason, code, status = ReasonFenced, http.StatusConflict, StatusFenced
	case errors.Is(err, ErrDispatchRefused):
		reason, code = ReasonServerRefused, http.StatusBadGateway
	case errors.Is(err, ErrUnboundConnection):
		reason = ReasonConnectionUnbound
	case errors.Is(err, ErrInvalidCall):
		// A bug on this side (executor, principal, taint), not the worker's
		// connection choice.
		reason, code = ReasonInternal, http.StatusInternalServerError
	case errors.Is(err, catalog.ErrServerUnavailable), errors.Is(err, catalog.ErrListingStale):
		reason, code = PinRefusalReason(err), http.StatusServiceUnavailable
	case errors.Is(err, catalog.ErrNotPinned), errors.Is(err, catalog.ErrToolChanged),
		errors.Is(err, catalog.ErrNoWritePath), errors.Is(err, catalog.ErrUnknownServer):
		reason = PinRefusalReason(err)
	default:
		// The call was dispatched and its outcome is unknown.
		reason, code, status = ReasonOutcomeUnknown, http.StatusBadGateway, StatusOutcomeUnknown
	}
	d.count(server, string(status), reason)
	writeJSON(w, code, refusalResponse{Stop: reason})
}

// answerLowered maps the outcome of a call that ran under a standing
// permission to the worker's answer. The write executor has already
// audited it and queued the principal's notice. The tool's own output is
// never passed on: the answer is server text, so it is not conversation
// state and raises no taint.
func (d *Dispatcher) answerLowered(w http.ResponseWriter, server string, out WriteOutcome) {
	switch out.Status {
	case StatusOK:
		d.count(server, string(StatusOK), "")
		writeJSON(w, http.StatusOK, toolResponse{Status: string(StatusOK), Output: loweredDoneOutput})
		return
	case StatusToolError:
		d.count(server, string(StatusToolError), "")
		writeJSON(w, http.StatusOK, toolResponse{Status: string(StatusToolError), Output: loweredFailedOutput})
		return
	}
	status, reason, code := out.Status, out.Reason, http.StatusForbidden
	switch {
	case status == StatusFenced:
		code = http.StatusConflict
	case status == StatusRefused && reason == ReasonServerRefused:
		code = http.StatusBadGateway
	case status == StatusRefused && (reason == ReasonAuditUnavailable || reason == ReasonStateUnreadable ||
		reason == ReasonServerUnavailable || reason == ReasonListingStale):
		code = http.StatusServiceUnavailable
	case status == StatusRefused:
	default:
		// Sent, and what became of it is not known.
		status, reason, code = StatusOutcomeUnknown, ReasonOutcomeUnknown, http.StatusBadGateway
	}
	if reason == "" {
		reason = ReasonInternal
	}
	d.count(server, string(status), reason)
	writeJSON(w, code, refusalResponse{Stop: reason})
}

// refreshAccess refreshes the connection's tokens after the server
// rejected the token of conn's generation, and returns the token to retry
// with once. The connection it opens must still be exactly the bound one
// (S1-X3), as for AccessToken.
func (d *Dispatcher) refreshAccess(ctx context.Context, principal int64, server string, bound pa.ConnectionRevision, conn connection.Connection) (connection.Secret, connection.Connection, *refusal) {
	token, next, err := d.cfg.Connections.RefreshAccess(ctx, principal, bound.ConnectionID, bound.AuthorityRevision, conn.TokenGeneration)
	if err != nil {
		ref := connectionRefusal(err)
		return connection.Secret{}, connection.Connection{}, &ref
	}
	if next.ID != bound.ConnectionID || next.Principal != principal || string(next.Server) != server {
		return connection.Secret{}, connection.Connection{}, &refusal{ReasonConnectionUnbound, http.StatusForbidden}
	}
	return token, next, nil
}

// refreshRefusal is a dispatch closure's failure when the server rejected
// the token and the refresh that would have let the call retry failed.
// The server ran nothing, so it is recorded as refused, with the
// connection's reason.
type refreshRefusal struct{ ref refusal }

func (e *refreshRefusal) Error() string {
	return "pa connector: token refresh failed: " + e.ref.reason
}

// Unwrap makes the executor record the call as refused: nothing ran.
func (e *refreshRefusal) Unwrap() error { return ErrDispatchRefused }

// resolveConnection picks the run's bound connection for server. A named
// connection must be bound to the run (S1-X3: a connection of another
// principal, or one the run did not bind, is refused) and be on server.
// Without a name the run must have exactly one bound connection on server.
// Only connections on server are considered: the principal's connections
// are read in one listing, and a listing that cannot be read refuses the
// call; it is never taken as "none" (I9).
func (d *Dispatcher) resolveConnection(ctx context.Context, policy pa.Policy, server, id string) (pa.ConnectionRevision, *refusal) {
	principal := policy.Principal().TelegramID()
	bound := policy.Connections()
	if id != "" {
		cr, ok := policy.Connection(id)
		if !ok {
			return pa.ConnectionRevision{}, &refusal{ReasonConnectionUnbound, http.StatusForbidden}
		}
		bound = []pa.ConnectionRevision{cr}
	}
	listed, err := d.cfg.Connections.List(ctx, principal)
	if err != nil {
		ref := connectionRefusal(err)
		return pa.ConnectionRevision{}, &ref
	}
	onServer := map[string]connection.Connection{}
	for _, c := range listed {
		if c.Principal == principal && string(c.Server) == server {
			onServer[c.ID] = c
		}
	}
	var match []pa.ConnectionRevision
	for _, cr := range bound {
		c, ok := onServer[cr.ConnectionID]
		if !ok {
			continue
		}
		// The read set, or the write set of a connection that asked for
		// it (#1320 slice P2-S14c): both carry every read scope.
		if !connection.ScopeAccepted(c) {
			return pa.ConnectionRevision{}, &refusal{ReasonScopeMismatch, http.StatusForbidden}
		}
		match = append(match, cr)
	}
	switch len(match) {
	case 0:
		return pa.ConnectionRevision{}, &refusal{ReasonConnectionUnbound, http.StatusForbidden}
	case 1:
		return match[0], nil
	}
	return pa.ConnectionRevision{}, &refusal{ReasonConnectionAmbiguous, http.StatusBadRequest}
}

// surface returns the pin's view of ep's current listing for this
// connection, read at most catalog.ReadListingTTL ago. Only a successful
// observation is cached: a failure is retried by the next call, and until
// then the server is unavailable. listed is false when the server refused
// this connection's token: that says nothing about the listing, so it is
// counted but is not an observation. refused is the server's refusal of
// the token (wrapping ErrMCPUnauthorized), nil when the listing was read.
func (d *Dispatcher) surface(ctx context.Context, ep MCPEndpoint, token connection.Secret, bound pa.ConnectionRevision) (s *catalog.Surface, refused error) {
	server := ep.Server()
	key := listingKey{server: server, connection: bound.ConnectionID, revision: bound.AuthorityRevision}
	now := d.now()
	d.mu.Lock()
	s = d.listings[key].s
	d.mu.Unlock()
	if s != nil && s.Err() == nil {
		if _, err := s.ModelTools(now); err == nil {
			return s, nil
		}
	}
	pages, err := ep.ListTools(ctx, token)
	if errors.Is(err, ErrMCPUnauthorized) {
		// The connection's token, not the server: no observation, but
		// the window still moves for every server.
		d.countListingFailure(server, listingUnauthorized)
		d.mu.Lock()
		d.uncacheLocked(key, now)
		d.refreshPinsLocked(d.now())
		d.mu.Unlock()
		return nil, err
	}
	if err != nil {
		d.countListingFailure(server, listingUnavailable)
		slog.Warn("pa connector: tools/list failed", "server", server, "err", err)
	}
	s = d.cfg.Pin.Observe(server, pages, err, now)
	drift, denied, ok := PinDrift(s)
	if !ok && err == nil {
		d.countListingFailure(server, listingInvalid)
	}
	if drift {
		d.logDrift(server, s)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if s.Err() == nil {
		if !now.Before(d.listings[key].at) {
			d.listings[key] = cachedSurface{s: s, at: now}
		} else {
			// A newer read finished first and is cached. This call is
			// authorized against that listing, the one the cache and the
			// gauges report, never against its own older read: a tool the
			// newer listing denies must not go through (#1343).
			s = d.listings[key].s
		}
	} else {
		d.uncacheLocked(key, now)
	}
	// Drop expired listings so the map does not grow with old revisions.
	// Expiry is judged at the current time, not at this read's start: a
	// listing that started after a slow read is not "from the future".
	current := d.now()
	for k, v := range d.listings {
		if _, err := v.s.ModelTools(current); err != nil {
			delete(d.listings, k)
		}
	}
	o := d.observations[key]
	switch {
	case ok && !now.Before(o.okAt):
		o.okAt, o.drift, o.denied = now, drift, denied
	case !ok && now.After(o.failAt):
		o.failAt = now
	}
	d.observations[key] = o
	d.pinServers[server] = true
	d.refreshPinsLocked(d.now())
	return s, nil
}

// uncacheLocked drops key's cached listing unless it started after a
// failed read that started at.
func (d *Dispatcher) uncacheLocked(key listingKey, at time.Time) {
	if c, ok := d.listings[key]; ok && !c.at.After(at) {
		delete(d.listings, key)
	}
}

func (d *Dispatcher) countListingFailure(server, reason string) {
	if d.cfg.Metrics != nil {
		d.cfg.Metrics.CountPAListingFailure(server, reason)
	}
}

// denyReasons is every deny reason the drift gauges carry.
var denyReasons = []string{
	string(catalog.DenyNotPinned), string(catalog.DenyMissing), string(catalog.DenyChangedSchema),
	string(catalog.DenyChangedDescription), string(catalog.DenyChangedAnnotations),
}

// PinDrift reports whether s shows drift: a pinned tool that is missing or
// changed. A tool the server lists but the pin does not have is denied
// (not_pinned) but is not drift: tg lists its write tools too. ok is false
// when s has no listing (could not observe), which is never "no drift".
func PinDrift(s *catalog.Surface) (drift bool, denied map[string]int, ok bool) {
	if s == nil || s.Err() != nil {
		return false, nil, false
	}
	denied = map[string]int{}
	for _, dt := range s.Denied() {
		for _, r := range dt.Reasons {
			denied[string(r)]++
			if r != catalog.DenyNotPinned {
				drift = true
			}
		}
	}
	return drift, denied, true
}

// GatewayPrefixed reports whether s looks like a listing read through the
// mctl gateway rather than from the server itself: every pinned tool is
// missing and the server lists the pinned names under the gateway's
// "<server>_" prefix. Such a listing is still denied in full (the pin
// knows no prefixed name); this only names the misconfiguration in logs.
func GatewayPrefixed(s *catalog.Surface, pin *catalog.Pin) bool {
	if s == nil || s.Err() != nil || pin == nil {
		return false
	}
	sp, ok := pin.Servers[s.Server()]
	if !ok || len(sp.Tools) == 0 {
		return false
	}
	denied := map[string][]catalog.DenyReason{}
	for _, dt := range s.Denied() {
		denied[dt.Name] = dt.Reasons
	}
	prefix := s.Server() + "_"
	for name := range sp.Tools {
		if r := denied[name]; len(r) != 1 || r[0] != catalog.DenyMissing {
			return false
		}
		if r := denied[prefix+name]; len(r) != 1 || r[0] != catalog.DenyNotPinned {
			return false
		}
	}
	return true
}

// RefreshPins ages expired observations out of the drift gauges. Without
// it an idle dispatcher would keep publishing its last values: a 0 that
// claims "no drift" with no fresh listing behind it, or a 1 that keeps the
// alert firing on stale data.
func (d *Dispatcher) RefreshPins() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.refreshPinsLocked(d.now())
}

// Run calls RefreshPins every interval (PinRefreshInterval if 0) until ctx
// ends, and writes the refusals_suppressed rows of closed refusal windows.
// Whoever serves RouteTool must also run this.
func (d *Dispatcher) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = PinRefreshInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.RefreshPins()
			d.recordSuppressed(ctx, d.closedRefusalWindows())
		}
	}
}

// refreshPinsLocked drops observations older than PinObservationWindow and
// recomputes the gauges of every published server from what is left: drift
// if any fresh listing of the server drifted, unknown if none could be
// read, including when the last one simply aged out. The caller holds d.mu,
// so two requests cannot write the gauges out of order.
func (d *Dispatcher) refreshPinsLocked(now time.Time) {
	type agg struct {
		seen, drift bool
		denied      map[string]int
	}
	per := map[string]*agg{}
	for server := range d.pinServers {
		per[server] = &agg{denied: map[string]int{}}
	}
	for k, o := range d.observations {
		fresh := !o.okAt.IsZero() && now.Sub(o.okAt) <= PinObservationWindow
		if !fresh && now.Sub(o.failAt) > PinObservationWindow {
			delete(d.observations, k)
			continue
		}
		a := per[k.server]
		if a == nil || !fresh {
			continue
		}
		a.seen = true
		a.drift = a.drift || o.drift
		for r, n := range o.denied {
			a.denied[r] = max(a.denied[r], n)
		}
	}
	if d.cfg.Metrics == nil {
		return
	}
	for server, a := range per {
		if !a.seen {
			d.cfg.Metrics.PAPinUnknown(server)
			continue
		}
		d.cfg.Metrics.PAPinObserved(server, a.drift, a.denied, denyReasons)
	}
}

func (d *Dispatcher) logDrift(server string, s *catalog.Surface) {
	names := make([]string, 0)
	for _, dt := range s.Denied() {
		if len(dt.Reasons) != 1 || dt.Reasons[0] != catalog.DenyNotPinned {
			names = append(names, dt.Name)
		}
	}
	sort.Strings(names)
	slog.Warn("pa connector: pin drift", "server", server, "tools", names,
		"gateway_prefixed", GatewayPrefixed(s, d.cfg.Pin))
}

func (d *Dispatcher) refuse(w http.ResponseWriter, r *http.Request, ref Refusal, code int) {
	server := ref.Server
	if !d.pinned(server) {
		server = invalidServer
	}
	status := string(StatusRefused)
	audit := true
	if ref.Principal > 0 {
		var closed []suppressedRefusals
		audit, closed = d.allowRefusalAudit(ref.Principal, ref.Reason)
		d.recordSuppressed(r.Context(), closed)
	}
	if audit {
		d.cfg.Executor.RecordRefusal(r.Context(), ref, d.pinned)
	} else {
		status = statusRefusedUnaudited
	}
	d.count(server, status, ref.Reason)
	writeJSON(w, code, refusalResponse{Stop: ref.Reason})
}

// allowRefusalAudit reports whether a refusal for reason may be written to
// principal's chain in the current window: the first of each reason
// always, then up to its class's burst (refusalAuditBurst, or
// securityAuditBurst for securityReasons) per refusalAuditWindow. It bounds what a looping or hostile worker can append: every
// request it sends is still refused and counted. It also returns the
// closed windows whose suppressed count is still to be written.
func (d *Dispatcher) allowRefusalAudit(principal int64, reason string) (bool, []suppressedRefusals) {
	now := d.now()
	d.mu.Lock()
	defer d.mu.Unlock()
	var closed []suppressedRefusals
	w := d.refusals[principal]
	if w == nil || now.Sub(w.start) >= refusalAuditWindow {
		if w != nil {
			closed = append(closed, w.summaries(principal)...)
		}
		if w == nil && len(d.refusals) >= maxRefusalPrincipals {
			closed = append(closed, d.closeRefusalWindowsLocked(now)...)
		}
		w = &auditWindow{start: now, seen: map[string]bool{}}
		d.refusals[principal] = w
	}
	c := classGeneral
	if securityReasons[reason] {
		c = classSecurity
	}
	w.n[c]++
	if !w.seen[reason] {
		w.seen[reason] = true
		return true, closed
	}
	if w.n[c] > classBurst[c] {
		w.suppressed[c]++
		return false, closed
	}
	return true, closed
}

// closedRefusalWindows drops the closed refusal windows and returns the
// suppressed counts still to be written.
func (d *Dispatcher) closedRefusalWindows() []suppressedRefusals {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.closeRefusalWindowsLocked(d.now())
}

func (d *Dispatcher) closeRefusalWindowsLocked(now time.Time) []suppressedRefusals {
	var closed []suppressedRefusals
	for p, w := range d.refusals {
		if now.Sub(w.start) < refusalAuditWindow {
			continue
		}
		closed = append(closed, w.summaries(p)...)
		delete(d.refusals, p)
	}
	return closed
}

// recordSuppressed writes one summary row per class of each closed window.
func (d *Dispatcher) recordSuppressed(ctx context.Context, closed []suppressedRefusals) {
	for _, c := range closed {
		d.cfg.Executor.RecordRefusal(ctx, Refusal{
			Principal: c.principal, Reason: c.reason, Suppressed: int64(c.n),
		}, d.pinned)
	}
}

func (d *Dispatcher) count(server, status, reason string) {
	if d.cfg.Metrics != nil {
		d.cfg.Metrics.CountPADispatch(server, status, reason)
	}
}

func with(r Refusal, reason string) Refusal {
	r.Reason = reason
	return r
}

// jobRefusal maps a job-ledger admission error. Anything it does not know,
// a ledger read error included, refuses as unreadable (I9).
func jobRefusal(err error) refusal {
	switch {
	case errors.Is(err, jobs.ErrToolNotInSet):
		return refusal{ReasonToolNotInSet, http.StatusForbidden}
	case errors.Is(err, jobs.ErrToolCap):
		return refusal{ReasonToolCap, http.StatusConflict}
	case errors.Is(err, jobs.ErrBudget):
		return refusal{ReasonBudget, http.StatusConflict}
	case errors.Is(err, jobs.ErrNotFound), errors.Is(err, jobs.ErrStale), errors.Is(err, pa.ErrNoJob):
		return refusal{ReasonJobStale, http.StatusConflict}
	case errors.Is(err, jobs.ErrPrincipalDisabled):
		return refusal{ReasonPrincipalDisabled, http.StatusForbidden}
	case errors.Is(err, jobs.ErrPrincipalNotAllowed):
		return refusal{ReasonPrincipalNotAllowed, http.StatusForbidden}
	case errors.Is(err, jobs.ErrGone):
		return refusal{ReasonJobGone, http.StatusConflict}
	case errors.Is(err, jobs.ErrInvalid):
		return refusal{ReasonBadRequest, http.StatusBadRequest}
	}
	return refusal{ReasonJobUnreadable, http.StatusServiceUnavailable}
}

// connectionRefusal maps a connection gate error. Unknown errors are
// unreadable, never a pass.
func connectionRefusal(err error) refusal {
	switch {
	case errors.Is(err, connection.ErrRefreshInProgress), errors.Is(err, connection.ErrRefreshFailed),
		errors.Is(err, connection.ErrRefreshUnavailable):
		// The connection is unchanged (an expiry that could not be
		// recorded included); this call fails and nothing retries it.
		// Checked first: a failed refresh is never reported as expired.
		return refusal{ReasonRefreshUnavailable, http.StatusServiceUnavailable}
	case errors.Is(err, connection.ErrRevisionMismatch):
		return refusal{ReasonRevisionMismatch, http.StatusConflict}
	case errors.Is(err, connection.ErrExpired), errors.Is(err, connection.ErrInvalidGrant),
		errors.Is(err, connection.ErrNoRefreshToken):
		// The service stopped accepting the connection; the principal is
		// told once to link it again (#1318 slice C2b).
		return refusal{ReasonConnectionExpired, http.StatusForbidden}
	case errors.Is(err, connection.ErrNotActive), errors.Is(err, connection.ErrNotFound),
		errors.Is(err, connection.ErrRefreshTokenReuse):
		return refusal{ReasonConnectionInactive, http.StatusForbidden}
	case errors.Is(err, connection.ErrScopeMismatch):
		return refusal{ReasonScopeMismatch, http.StatusForbidden}
	}
	return refusal{ReasonConnectionUnreadable, http.StatusServiceUnavailable}
}

// atEOF reports whether dec has nothing left but whitespace. dec.More
// would accept a stray closing bracket.
func atEOF(dec *json.Decoder) bool {
	_, err := dec.Token()
	return errors.Is(err, io.EOF)
}

// jsonObject reports whether raw is a JSON object (tools/call arguments).
func jsonObject(raw json.RawMessage) bool {
	t := bytes.TrimSpace(raw)
	return len(t) >= 2 && t[0] == '{' && json.Valid(t)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
