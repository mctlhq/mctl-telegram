package agentapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/mctlhq/mctl-telegram/internal/agent/tools"
	"github.com/mctlhq/mctl-telegram/internal/assistant"
	"github.com/mctlhq/mctl-telegram/internal/assistantregistry"
	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/auth/localjwt"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/metrics"
)

// eventsPollInterval is how often the long-poll loop re-checks the queue
// when the first claim attempt comes up empty.
const eventsPollInterval = 1 * time.Second

// jobEnvelope is the payload POST /jobs/claim returns per claimed job. It carries
// only identity/routing fields — the worker fetches the full event body via
// GET /event/{eventID}, keeping the wake-up response small and avoiding a
// second encryption round-trip on jobs that never get past dedup.
type jobEnvelope struct {
	JobID          int64  `json:"job_id"`
	EventID        string `json:"event_id"`
	ConversationID int64  `json:"conversation_id,omitempty"`
	// Attempt is the claim identity a worker must echo back on
	// POST /jobs/{id}/complete — see internal/db.CompleteAgentJob's fencing
	// comment. Without it a worker whose claim was reclaimed by the stale-
	// job sweeper could clobber a newer claim's outcome.
	Attempt  int    `json:"attempt"`
	Deadline string `json:"deadline"` // RFC3339; advisory, see Server.jobVisibility
	// JobToken is a short-lived credential (aud "agent-job") bound to this
	// job, attempt and conversation. Omitted when no signer is configured.
	JobToken string `json:"job_token,omitempty"`
	// MaxJobCostUSD is the server's per-job spend cap for a managed job: the
	// amount reserved against the account's budget. The worker's own model
	// budget must not exceed it. Omitted for the account runtime.
	MaxJobCostUSD float64 `json:"max_job_cost_usd,omitempty"`
	// TurnID and SourceEventIDs are set when the job is a coalesced turn:
	// every event of the turn in arrival order, head first. EventID stays the
	// head's event so older workers keep working. An edit job that carries
	// the rest of an unsent turn (#962) lists those events as well, ordered
	// by the original messages' arrival, so EventID need not come first.
	TurnID         string   `json:"turn_id,omitempty"`
	SourceEventIDs []string `json:"source_event_ids,omitempty"`
	// Instructions is the system prompt for this job: the account's catalog
	// assistant with its owner notes (assistant.Render). Assistant names it
	// as name@version for the worker's logs. Both are omitted when the
	// server has no catalog configured; the worker then keeps its own
	// AGENT_SYSTEM_PROMPT.
	Instructions string `json:"instructions,omitempty"`
	Assistant    string `json:"assistant,omitempty"`
	// AssistantDigest pins the definition and instructions the job ran
	// with (assistant.Entry.Digest), for the worker's logs.
	AssistantDigest string `json:"assistant_digest,omitempty"`
	// Tools names the job's MCP tools as the definition calls them, each a
	// canonical name or a generic alias (internal/agent/tools). Omitted
	// without a catalog; the worker then uses the canonical names.
	Tools []string `json:"tools,omitempty"`
	// InstallRevision is the account's install revision this claim was
	// made under (#1018); the job's work is refused once it moves.
	InstallRevision int64 `json:"install_revision,omitempty"`
}

// errAssistantNotInCatalog means the account's profile names an assistant
// this server can resolve neither from a stored registry definition nor
// from its embedded catalog.
var errAssistantNotInCatalog = errors.New("assistant not in catalog")

// errAssistantDisabled and errAssistantLifecycleUnknown mean the account's
// pinned registry definition may not take new jobs (#1020): the registry
// disabled it, or its lifecycle has not been confirmed within
// assistantregistry.StaleAfter. The claim refuses before claiming, so the
// jobs stay queued.
var (
	errAssistantDisabled         = errors.New("assistant disabled in the registry")
	errAssistantLifecycleUnknown = errors.New("assistant lifecycle unknown: registry not reached")
)

// errForkNotRunnable means the account runs a private fork (#1043) that may
// not take new jobs: forks are off on this server, or the profile is in
// guarded mode, which no fork version runs in before it is promoted.
var errForkNotRunnable = errors.New("assistant fork may not run")

// accountInstructions renders the system prompt for userID's jobs. It fails
// rather than falling back: running an account's jobs with another
// assistant's instructions would be worse than not running them.
func (s *Server) accountInstructions(r *http.Request, userID int64) (instructions, ref, digest string, toolNames []string, err error) {
	if s.catalog == nil {
		return "", "", "", nil, nil
	}
	a, err := s.Store.GetAgentAssistant(r.Context(), userID)
	if errors.Is(err, db.ErrAgentProfileNotFound) {
		// No profile row is the documented "not configured" state: the
		// listener only queues jobs for a configured account, so there is
		// nothing to claim, and the claim answers as it always has.
		return "", "", "", nil, nil
	}
	if err != nil {
		return "", "", "", nil, err
	}
	ref = a.Name + "@" + a.Version
	if db.IsForkAssistant(a.Name) {
		switch {
		case !s.forksEnabled:
			return "", "", "", nil, fmt.Errorf("%w: %s: forks are disabled", errForkNotRunnable, ref)
		case a.Mode == db.AgentModeGuarded:
			return "", "", "", nil, fmt.Errorf("%w: %s: a fork runs in observe mode until it is promoted", errForkNotRunnable, ref)
		}
	}
	entry, err := s.resolveAssistant(r.Context(), userID, a)
	if err != nil {
		return "", "", "", nil, err
	}
	var in *assistant.Install
	if len(a.Install) > 0 {
		if in, err = assistant.ParseInstall(a.Install); err != nil {
			// The error text can quote a stored value; keep it out.
			return "", "", "", nil, fmt.Errorf("stored install for %s no longer parses", ref)
		}
	}
	return assistant.Render(entry, in), ref, entry.Digest, entry.Definition.Spec.Tools, nil
}

// resolveAssistant finds the definition a's install pinned. The registry
// snapshot stored with the install (#1020) is the source; the embedded
// catalog is only the migration and rollback bridge, used for a profile
// that pins no digest yet or pins exactly the embedded entry's digest. It
// never calls the registry and writes nothing. With the registry enabled,
// a snapshot whose lifecycle is disabled or unknown refuses; the owner's
// notice for an unknown one is the refresher's job.
func (s *Server) resolveAssistant(ctx context.Context, userID int64, a *db.AgentAssistant) (*assistant.Entry, error) {
	entry, def, err := s.lookupAssistant(ctx, userID, a)
	if err != nil || def == nil || !s.registryGate {
		return entry, err
	}
	ref := a.Name + "@" + a.Version
	switch assistantregistry.LifecycleGate(def, s.clock()) {
	case assistantregistry.GateDisabled:
		return nil, fmt.Errorf("%w: %s", errAssistantDisabled, ref)
	case assistantregistry.GateUnknown:
		return nil, fmt.Errorf("%w: %s last checked %s", errAssistantLifecycleUnknown, ref, def.LifecycleCheckedAt.UTC().Format(time.RFC3339))
	}
	return entry, nil
}

// lookupAssistant finds the definition a's install pinned, as
// resolveAssistant does, without the lifecycle gate. def is the stored
// registry definition, nil when the embedded catalog served the entry; for
// a fork it is the fork's base, whose lifecycle is the fork's.
func (s *Server) lookupAssistant(ctx context.Context, userID int64, a *db.AgentAssistant) (*assistant.Entry, *db.AssistantDefinition, error) {
	if db.IsForkAssistant(a.Name) {
		return s.lookupFork(ctx, userID, a)
	}
	ref := a.Name + "@" + a.Version
	embedded, inCatalog := s.catalog.Lookup(a.Name, a.Version)
	if a.Digest == "" {
		if !inCatalog {
			return nil, nil, fmt.Errorf("%w: %s", errAssistantNotInCatalog, ref)
		}
		return embedded, nil, nil
	}
	def, err := s.Store.GetAssistantDefinition(ctx, a.Digest)
	if errors.Is(err, db.ErrAssistantDefinitionNotFound) {
		if inCatalog && embedded.Digest == a.Digest {
			return embedded, nil, nil
		}
		return nil, nil, fmt.Errorf("%w: %s pins %s, which is not stored", errAssistantNotInCatalog, ref, a.Digest)
	}
	if err != nil {
		return nil, nil, err
	}
	if def.Name != a.Name || def.Version != a.Version {
		return nil, nil, fmt.Errorf("stored definition %s is %s@%s, profile names %s", def.Digest, def.Name, def.Version, ref)
	}
	entry, err := s.snapshotEntry(def)
	if err != nil {
		return nil, nil, err
	}
	return entry, def, nil
}

// lookupFork resolves the private fork a's install pinned (#1043): only
// userID's own fork version with that digest, decrypted with userID's key,
// and its base, from the stored snapshot (whose lifecycle gates the fork)
// or, without a registry, the embedded catalog. Forks are not cached: the
// instructions are the owner's data and are decrypted per claim.
func (s *Server) lookupFork(ctx context.Context, userID int64, a *db.AgentAssistant) (*assistant.Entry, *db.AssistantDefinition, error) {
	ref := a.Name + "@" + a.Version
	if a.Digest == "" {
		return nil, nil, fmt.Errorf("%w: fork %s pins no digest", errAssistantNotInCatalog, ref)
	}
	row, err := s.Store.GetAssistantForkByDigest(ctx, userID, a.Digest)
	if errors.Is(err, db.ErrAssistantForkNotFound) {
		return nil, nil, fmt.Errorf("%w: fork %s pins %s, which is not stored", errAssistantNotInCatalog, ref, a.Digest)
	}
	if err != nil {
		return nil, nil, err
	}
	if row.Name != a.Name || row.Version != a.Version {
		return nil, nil, fmt.Errorf("stored fork %s is %s@%s, profile names %s", row.Digest, row.Name, row.Version, ref)
	}
	entry, err := assistant.ParseMaterialized(row.Document)
	if err != nil {
		// The parse error can quote the owner's instructions.
		return nil, nil, fmt.Errorf("stored fork %s no longer parses", row.Digest)
	}
	if entry.Digest != row.Digest {
		return nil, nil, fmt.Errorf("stored fork %s hashes to %s", row.Digest, entry.Digest)
	}
	var base *assistant.Entry
	def, err := s.Store.GetAssistantDefinition(ctx, row.BaseDigest)
	switch {
	case err == nil:
		if base, err = s.snapshotEntry(def); err != nil {
			return nil, nil, err
		}
	case errors.Is(err, db.ErrAssistantDefinitionNotFound) && !s.registryGate:
		embedded, ok := s.catalog.Lookup(row.BaseName, row.BaseVersion)
		if !ok || embedded.Digest != row.BaseDigest {
			return nil, nil, fmt.Errorf("%w: base %s@%s of fork %s is not available", errAssistantNotInCatalog, row.BaseName, row.BaseVersion, ref)
		}
		base, def = embedded, nil
	case errors.Is(err, db.ErrAssistantDefinitionNotFound):
		// With the registry on, the base's lifecycle comes from its stored
		// snapshot; without one it is unknown, and unknown does not run.
		return nil, nil, fmt.Errorf("%w: base %s of fork %s is not stored", errAssistantNotInCatalog, row.BaseDigest, ref)
	default:
		return nil, nil, err
	}
	if err := assistant.ValidateFork(base, entry); err != nil {
		return nil, nil, fmt.Errorf("stored fork %s does not narrow its base", row.Digest)
	}
	return entry, def, nil
}

// snapshotEntry parses a stored definition, caching it by digest: the
// document under a digest never changes.
func (s *Server) snapshotEntry(def *db.AssistantDefinition) (*assistant.Entry, error) {
	s.snapshotMu.Lock()
	defer s.snapshotMu.Unlock()
	if e, ok := s.snapshots[def.Digest]; ok {
		return e, nil
	}
	e, err := assistant.ParseMaterialized(def.Document)
	if err != nil {
		// The parse error can quote document content.
		return nil, fmt.Errorf("stored definition %s no longer parses", def.Digest)
	}
	if e.Digest != def.Digest {
		return nil, fmt.Errorf("stored definition %s hashes to %s", def.Digest, e.Digest)
	}
	if s.snapshots == nil {
		s.snapshots = map[string]*assistant.Entry{}
	}
	s.snapshots[def.Digest] = e
	return e, nil
}

// jobTokenAudience is the aud of the per-job credential.
const jobTokenAudience = "agent-job"

// mintJobToken signs the job credential for a freshly claimed job. The TTL
// ends at the claim deadline. jobTools, the job's canonical tool set, is
// signed into it (job_tools) so the worker cannot widen it. The parent's jti and origin are inherited so
// revoking the worker token revokes its job tokens. Returns "" when no signer
// is configured or signing fails (the worker then falls back to its own
// token, as before).
func (s *Server) mintJobToken(parent *auth.Identity, j db.AgentJob, jobTools []string) string {
	// A parent without a Telegram id (shared-hmac) cannot be re-resolved to a
	// user by the job-token verifier; keep the account token for it.
	if s.jobTokenSigner == nil || parent.TelegramID == 0 {
		return ""
	}
	return s.signJobToken(parent, parent.Subject, parent.TelegramID, parent.TelegramUsername, j, jobTools)
}

// mintJobTokenFor is mintJobToken for either kind of parent. A pool parent
// belongs to no account, so Subject and TelegramID come from the job's user;
// the pool's jti and origin are still inherited, which is what lets revoking
// the pool revoke every job token derived from it. Returns "" when no token
// can be minted: a pool-claimed job is never handed out without one.
func (s *Server) mintJobTokenFor(ctx context.Context, parent *auth.Identity, j db.AgentJob, jobTools []string) string {
	if !parent.IsPool() {
		return s.mintJobToken(parent, j, jobTools)
	}
	if s.jobTokenSigner == nil {
		return ""
	}
	tg, found, err := s.Store.TelegramIDByUserID(ctx, j.UserID)
	if err != nil {
		logHandlerErr("mint_job_token", err)
		return ""
	}
	if !found {
		return ""
	}
	return s.signJobToken(parent, "tg:"+strconv.FormatInt(tg, 10), tg, "", j, jobTools)
}

func (s *Server) signJobToken(parent *auth.Identity, subject string, tgID int64, tgUsername string, j db.AgentJob, jobTools []string) string {
	ttl := time.Until(j.ClaimedAt.Add(s.jobVisibility))
	if ttl <= 0 {
		return ""
	}
	tok, err := s.jobTokenSigner.Mint(localjwt.Claims{
		Subject:          subject,
		TelegramID:       tgID,
		TelegramUsername: tgUsername,
		Audience:         []string{jobTokenAudience},
		Jti:              parent.Jti,
		OriginalIssuedAt: parent.OriginalIssuedAt,
		JobID:            j.ID,
		JobAttempt:       j.Attempts,
		ConversationID:   j.ConversationID,
		JobTools:         jobTools,
	}, ttl)
	if err != nil {
		logHandlerErr("mint_job_token", err)
		return ""
	}
	return tok
}

// handleLegacyEvents preserves the original GET endpoint during a rolling
// upgrade. It is intentionally deprecated because claiming mutates durable
// queue state; new workers use POST /jobs/claim.
func (s *Server) handleLegacyEvents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Deprecation", "@1785024000")
	w.Header().Set("Sunset", "Thu, 31 Dec 2026 23:59:59 GMT")
	w.Header().Set("Link", `</api/agent/v1/jobs/claim>; rel="successor-version"`)
	s.handleClaimJobs(w, r)
}

// handleClaimJobs is POST /jobs/claim — a long-poll claim of the next due job(s).
// Honors an optional integer ?limit= (default 1, capped at 10). Always
// responds 200; an empty "jobs" array means the poll window elapsed with
// nothing to claim, not an error.
func (s *Server) handleClaimJobs(w http.ResponseWriter, r *http.Request) {
	id, ok := identity(w, r)
	if !ok {
		return
	}
	if !s.requireAccountToken(w, r, id, "get_events") {
		return
	}
	limit := 1
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			writeJSONError(w, http.StatusBadRequest, "limit must be a positive integer")
			return
		}
		if n > 10 {
			n = 10
		}
		limit = n
	}

	if id.IsPool() {
		s.handlePoolClaim(w, r, id, limit)
		return
	}

	// Rendered before anything is claimed, so a failure leaves every job
	// queued instead of claimed by a request that cannot run it.
	instructions, assistantRef, assistantDigest, toolNames, err := s.accountInstructions(r, id.UserID)
	switch {
	case errors.Is(err, errAssistantDisabled):
		logHandlerErr("get_events", err)
		writeJSONError(w, http.StatusServiceUnavailable, "assistant disabled in the registry")
		return
	case errors.Is(err, errAssistantLifecycleUnknown):
		logHandlerErr("get_events", err)
		writeJSONError(w, http.StatusServiceUnavailable, "assistant registry unreachable, lifecycle unknown")
		return
	case errors.Is(err, errForkNotRunnable):
		logHandlerErr("get_events", err)
		writeJSONError(w, http.StatusServiceUnavailable, "assistant fork may not run: forks are off, or the mode is guarded")
		return
	case err != nil:
		logHandlerErr("get_events", err)
		writeJSONError(w, http.StatusInternalServerError, "assistant instructions unavailable")
		return
	}
	// The tool set the job tokens carry: the definition's tools by canonical
	// name, or every tool without a catalog.
	bindings, err := tools.ForJob(toolNames)
	if err != nil {
		logHandlerErr("get_events", err)
		writeJSONError(w, http.StatusInternalServerError, "assistant instructions unavailable")
		return
	}
	jobTools := tools.CanonicalNames(bindings)

	ctx := r.Context()
	deadline := time.Now().Add(s.longPollTimeout)
	tick := time.NewTicker(eventsPollInterval)
	defer tick.Stop()
	for {
		jobs, err := s.Queue.Claim(ctx, id.UserID, db.RuntimeOwn, limit)
		if err != nil {
			// A client disconnect mid-Claim surfaces here as context.Canceled
			// (the ctx.Done() case below only catches cancellation *between*
			// poll iterations, not one already in flight inside Claim). That is
			// an ordinary hang-up, not a server error: logging it and
			// returning 500 would misreport every normal long-poll disconnect
			// as a failure.
			if ctx.Err() != nil {
				writeJSON(w, http.StatusOK, map[string]any{"jobs": []jobEnvelope{}})
				return
			}
			logHandlerErr("get_events", err)
			writeJSONError(w, http.StatusInternalServerError, "claim failed")
			return
		}
		if len(jobs) > 0 {
			out := make([]jobEnvelope, 0, len(jobs))
			for _, j := range jobs {
				out = append(out, jobEnvelope{
					JobID:           j.ID,
					EventID:         j.EventID,
					ConversationID:  j.ConversationID,
					Attempt:         j.Attempts,
					Deadline:        j.ClaimedAt.Add(s.jobVisibility).UTC().Format(time.RFC3339),
					JobToken:        s.mintJobToken(id, j, jobTools),
					TurnID:          j.TurnID,
					SourceEventIDs:  j.SourceEventIDs,
					Instructions:    instructions,
					Assistant:       assistantRef,
					AssistantDigest: assistantDigest,
					Tools:           toolNames,
					InstallRevision: j.InstallRevision,
				})
			}
			s.audit(ctx, id.UserID, "get_events", "ok", "")
			writeJSON(w, http.StatusOK, map[string]any{"jobs": out})
			return
		}
		select {
		case <-ctx.Done():
			writeJSON(w, http.StatusOK, map[string]any{"jobs": []jobEnvelope{}})
			return
		case <-tick.C:
			if time.Now().After(deadline) {
				writeJSON(w, http.StatusOK, map[string]any{"jobs": []jobEnvelope{}})
				return
			}
		}
	}
}

// handlePoolClaim is POST /jobs/claim for the managed-runtime pool identity:
// one job per managed account per response, round robin over the accounts
// with due work, each handed a job token minted from the job's own user.
// Every account's instructions are rendered before its job is claimed, and a
// job whose token cannot be minted is released without charging an attempt.
func (s *Server) handlePoolClaim(w http.ResponseWriter, r *http.Request, id *auth.Identity, limit int) {
	if s.jobTokenSigner == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "job tokens not configured")
		return
	}
	if s.managed == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "managed runtime not enabled")
		return
	}
	ctx := r.Context()
	origin := time.Unix(id.OriginalIssuedAt, 0)
	deadline := time.Now().Add(s.longPollTimeout)
	tick := time.NewTicker(eventsPollInterval)
	defer tick.Stop()
	// skipped counts, by reason, the accounts this request passed over; it is
	// logged once if the request ends without serving anyone, so a pool that
	// is starved by accounts it cannot serve is visible.
	skipped := map[string]int{}
	finish := func(out []jobEnvelope) {
		// nothing_claimable alone is normal contention (another pool replica
		// took the job between the candidate read and the claim), not a
		// starved pool.
		starved := false
		for reason := range skipped {
			starved = starved || reason != poolSkipNothing
		}
		if len(out) == 0 && starved {
			slog.Warn("agentapi pool claim: candidate accounts were skipped and none was served",
				"pool", id.Pool, "skipped", skipped)
		}
		writeJSON(w, http.StatusOK, map[string]any{"jobs": out})
	}
	page := max(s.poolCandidatePage, limit, 1)
	for {
		out := make([]jobEnvelope, 0, limit)
		// Walk the whole candidate order, page by page, until limit jobs are
		// claimed: accounts the pool must skip (blanket revocation, an
		// assistant that cannot render, a claim that comes back empty) keep
		// their place at the front of the order, and a fixed window would let
		// a few of them starve every other managed account.
		var after *db.ManagedClaimCursor
		// served makes "one job per account per response" hold for any
		// in-flight cap: with a cap above 1 an account served on one page
		// can sort after the cursor again (its next claimable job is due
		// later) and would otherwise get a second job ahead of others.
		served := map[int64]bool{}
		for scanned := 0; len(out) < limit && scanned < maxPoolCandidateScan; scanned += page {
			cands, err := s.Store.ListManagedClaimCandidates(ctx, s.clock(), s.managed.MaxInflightPerAccount, after, page)
			if err != nil {
				if ctx.Err() != nil {
					writeJSON(w, http.StatusOK, map[string]any{"jobs": []jobEnvelope{}})
					return
				}
				logHandlerErr("get_events", err)
				writeJSONError(w, http.StatusInternalServerError, "claim failed")
				return
			}
			for _, c := range cands {
				if len(out) >= limit {
					break
				}
				if served[c.UserID] {
					continue
				}
				env, reason := s.poolClaimOne(r, id, c, origin)
				if reason != "" {
					skipped[reason]++
					continue
				}
				served[c.UserID] = true
				out = append(out, env)
			}
			if len(cands) < page {
				break
			}
			after = &cands[len(cands)-1].Cursor
		}
		if len(out) > 0 {
			finish(out)
			return
		}
		select {
		case <-ctx.Done():
			finish([]jobEnvelope{})
			return
		case <-tick.C:
			if time.Now().After(deadline) {
				finish([]jobEnvelope{})
				return
			}
		}
	}
}

// defaultPoolCandidatePage is how many candidate accounts one page of the
// pool claim reads; maxPoolCandidateScan bounds one pass over the candidate
// order (well above MANAGED_RUNTIME_MAX_ACCOUNTS today).
const (
	defaultPoolCandidatePage = 32
	maxPoolCandidateScan     = 4096
)

// Skip reasons poolClaimOne reports for an account it hands nothing out for.
const (
	poolSkipRevoked     = "blanket_revoked"
	poolSkipRevokeCheck = "revocation_check_failed"
	poolSkipRender      = "instructions_unavailable"
	poolSkipTools       = "tool_set_unavailable"
	poolSkipClaimError  = "claim_failed"
	poolSkipNothing     = "nothing_claimable"
	poolSkipMint        = "job_token_unavailable"
)

// poolClaimOne claims at most one job of candidate c for the pool. A
// non-empty reason means nothing is handed out for this account; its jobs
// stay pending.
func (s *Server) poolClaimOne(r *http.Request, id *auth.Identity, c db.ManagedClaimCandidate, origin time.Time) (jobEnvelope, string) {
	ctx := r.Context()
	// A blanket revocation of the account at or after the pool's origin would
	// make every job token minted from the pool dead on arrival.
	if s.managed.Revocations != nil {
		revoked, err := s.managed.Revocations.IsBlanketRevoked(ctx, c.TelegramID, origin)
		if err != nil {
			slog.Debug("agentapi pool claim: revocation check failed; account skipped", "user_id", c.UserID, "err", err)
			return jobEnvelope{}, poolSkipRevokeCheck
		}
		if revoked {
			return jobEnvelope{}, poolSkipRevoked
		}
	}
	instructions, assistantRef, assistantDigest, toolNames, err := s.accountInstructions(r, c.UserID)
	if err != nil {
		slog.Debug("agentapi pool claim: instructions unavailable; account skipped", "user_id", c.UserID, "err", err)
		return jobEnvelope{}, poolSkipRender
	}
	bindings, err := tools.ForJob(toolNames)
	if err != nil {
		slog.Debug("agentapi pool claim: tool set unavailable; account skipped", "user_id", c.UserID, "err", err)
		return jobEnvelope{}, poolSkipTools
	}
	jobTools := tools.CanonicalNames(bindings)
	// The candidate list is a lock-free hint; ClaimManaged re-checks the
	// in-flight cap atomically with the claim.
	jobs, err := s.Queue.ClaimManaged(ctx, c.UserID, 1, s.managed.MaxInflightPerAccount)
	if err != nil {
		if ctx.Err() == nil {
			slog.Warn("agentapi pool claim: claim failed", "user_id", c.UserID, "err", err)
		}
		return jobEnvelope{}, poolSkipClaimError
	}
	if len(jobs) == 0 {
		return jobEnvelope{}, poolSkipNothing
	}
	j := jobs[0]
	tok := s.mintJobTokenFor(ctx, id, j, jobTools)
	if tok == "" {
		// Not RetryAgentJob: a signer outage must not spend the job's retry
		// budget. The release keeps the context alive past a hang-up.
		if err := s.Queue.ReleaseUnissued(context.WithoutCancel(ctx), j.ID, j.Attempts); err != nil {
			slog.Warn("agentapi pool claim: release of unissued claim failed", "job_id", j.ID, "err", err)
		}
		return jobEnvelope{}, poolSkipMint
	}
	s.audit(ctx, c.UserID, "get_events", "ok", "pool:"+id.Pool)
	return jobEnvelope{
		JobID:           j.ID,
		EventID:         j.EventID,
		ConversationID:  j.ConversationID,
		Attempt:         j.Attempts,
		Deadline:        j.ClaimedAt.Add(s.jobVisibility).UTC().Format(time.RFC3339),
		JobToken:        tok,
		MaxJobCostUSD:   s.managed.MaxJobCostUSD,
		TurnID:          j.TurnID,
		SourceEventIDs:  j.SourceEventIDs,
		Instructions:    instructions,
		Assistant:       assistantRef,
		AssistantDigest: assistantDigest,
		Tools:           toolNames,
		InstallRevision: j.InstallRevision,
	}, ""
}

// eventResponse is the full payload for GET /event/{eventID}.
type eventResponse struct {
	EventID    string `json:"event_id"`
	Kind       string `json:"kind"`
	ChatTGID   int64  `json:"chat_tg_id"`
	SenderTGID int64  `json:"sender_tg_id"`
	MessageID  int64  `json:"message_id"`
	Body       string `json:"body"`
	Meta       string `json:"meta"`
	CreatedAt  string `json:"created_at"`
}

func (s *Server) handleGetEvent(w http.ResponseWriter, r *http.Request) {
	id, ok := identity(w, r)
	if !ok {
		return
	}
	eventID := chi.URLParam(r, "eventID")
	if eventID == "" {
		writeJSONError(w, http.StatusBadRequest, "event id required")
		return
	}
	if jobBound(id) {
		// A job credential may only read the events of its own job's turn.
		job, jerr := s.Store.GetAgentJob(r.Context(), id.UserID, id.JobID)
		if jerr != nil || !slices.Contains(job.SourceEventIDs, eventID) {
			s.denyBinding(w, r, id, "get_event", fmt.Sprintf("event is not the event of job=%d", id.JobID))
			return
		}
	}
	ev, err := s.Store.GetIncomingEvent(r.Context(), id.UserID, eventID)
	if errors.Is(err, db.ErrIncomingEventNotFound) {
		writeJSONError(w, http.StatusNotFound, "event not found")
		return
	}
	if err != nil {
		logHandlerErr("get_event", err)
		writeJSONError(w, http.StatusInternalServerError, "lookup failed")
		return
	}
	s.audit(r.Context(), id.UserID, "get_event", "ok", "")
	writeJSON(w, http.StatusOK, eventResponse{
		EventID:    ev.EventID,
		Kind:       ev.Kind,
		ChatTGID:   ev.ChatTGID,
		SenderTGID: ev.SenderTGID,
		MessageID:  ev.MessageID,
		Body:       ev.Body,
		Meta:       ev.Meta,
		CreatedAt:  ev.CreatedAt.UTC().Format(time.RFC3339),
	})
}

type completeJobRequest struct {
	Attempt        int    `json:"attempt"`
	Status         string `json:"status"`
	Note           string `json:"note"`
	ResultActionID *int64 `json:"result_action_id,omitempty"`
	ResultLeadID   *int64 `json:"result_lead_id,omitempty"`
}

type jobStatusResponse struct {
	JobID          int64  `json:"job_id"`
	Status         string `json:"status"`
	Attempt        int    `json:"attempt"`
	ResultActionID int64  `json:"result_action_id,omitempty"`
	ResultLeadID   int64  `json:"result_lead_id,omitempty"`
}

// handleGetJob is GET /jobs/{id}. It exposes only the durable status and
// attempt of a user-scoped job so a headless worker can enforce the
// postcondition "claude exit 0 AND complete_agent_job actually succeeded."
// No event, conversation, error, or message content is returned.
func (s *Server) handleGetJob(w http.ResponseWriter, r *http.Request) {
	id, ok := identity(w, r)
	if !ok {
		return
	}
	jobID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || jobID <= 0 {
		writeJSONError(w, http.StatusBadRequest, "invalid job id")
		return
	}
	if !s.enforceBinding(w, r, id, "get_agent_job", 0, jobID, 0) {
		return
	}
	job, err := s.Store.GetAgentJob(r.Context(), id.UserID, jobID)
	if errors.Is(err, db.ErrAgentJobNotFound) {
		writeJSONError(w, http.StatusNotFound, "job not found")
		return
	}
	if err != nil {
		logHandlerErr("get_agent_job", err)
		writeJSONError(w, http.StatusInternalServerError, "lookup failed")
		return
	}
	writeJSON(w, http.StatusOK, jobStatusResponse{
		JobID: job.ID, Status: job.Status, Attempt: job.Attempts,
		ResultActionID: job.ResultActionID, ResultLeadID: job.ResultLeadID,
	})
}

// handleJobComplete is POST /jobs/{id}/complete. A job may only be completed
// as "completed" while atomically linking an exact persisted action or lead.
// status=failed/ignored carry no result because those are legitimate
// terminal outcomes with no durable output.
func (s *Server) handleJobComplete(w http.ResponseWriter, r *http.Request) {
	id, ok := identity(w, r)
	if !ok {
		return
	}
	jobIDStr := chi.URLParam(r, "id")
	jobID, err := strconv.ParseInt(jobIDStr, 10, 64)
	if err != nil || jobID <= 0 {
		writeJSONError(w, http.StatusBadRequest, "invalid job id")
		return
	}
	var req completeJobRequest
	if err := decodeStrict(w, r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if !s.enforceBinding(w, r, id, "complete_agent_job", 0, jobID, req.Attempt) {
		return
	}
	switch req.Status {
	case db.JobCompleted, db.JobFailed, db.JobIgnored:
	default:
		writeJSONError(w, http.StatusBadRequest, "status must be completed, failed, or ignored")
		return
	}
	ctx := r.Context()
	if _, err := s.Store.GetAgentJob(ctx, id.UserID, jobID); err != nil {
		if errors.Is(err, db.ErrAgentJobNotFound) {
			writeJSONError(w, http.StatusNotFound, "job not found")
			return
		}
		logHandlerErr("complete_agent_job", err)
		writeJSONError(w, http.StatusInternalServerError, "lookup failed")
		return
	}
	var completeErr error
	if req.ResultActionID == nil && req.ResultLeadID == nil && s.AllowLegacyJobCompletion {
		// Rolling compatibility for workers released before exact result
		// linkage. Keep this branch until every deployed worker sends the new
		// fields; new workers always take CompleteWithResult below.
		w.Header().Set("Deprecation", "@1785024000")
		w.Header().Set("Sunset", "Thu, 31 Dec 2026 23:59:59 GMT")
		completeErr = s.Queue.Complete(ctx, jobID, req.Attempt, req.Status, req.Note)
	} else {
		var actionID, leadID int64
		if req.ResultActionID != nil {
			actionID = *req.ResultActionID
		}
		if req.ResultLeadID != nil {
			leadID = *req.ResultLeadID
		}
		completeErr = s.Queue.CompleteWithResult(
			ctx, id.UserID, jobID, req.Attempt, req.Status, req.Note,
			actionID, leadID,
		)
	}
	if completeErr != nil {
		err := completeErr
		if errors.Is(err, db.ErrAgentJobResultRequired) {
			writeJSONError(w, http.StatusConflict,
				"cannot mark job completed without an exact persisted result id")
			return
		}
		if errors.Is(err, db.ErrAgentJobResultInvalid) {
			writeJSONError(w, http.StatusConflict,
				"result does not belong to this job and account")
			return
		}
		if errors.Is(err, db.ErrAgentJobNotFound) {
			// Lost the compare-and-set race (stale claim, already completed by
			// another attempt after a visibility-timeout requeue) — the caller's
			// ack is simply too late, not a server error.
			writeJSONError(w, http.StatusConflict, "job is no longer claimed under that attempt")
			return
		}
		logHandlerErr("complete_agent_job", err)
		writeJSONError(w, http.StatusInternalServerError, "complete failed")
		return
	}
	s.audit(ctx, id.UserID, "complete_agent_job", "ok", "")
	writeJSON(w, http.StatusOK, map[string]any{"completed": true})
}

// retryJobRequest is the body of POST /jobs/{id}/retry. Outcome is a fixed
// vocabulary, not free text, so a worker (or a prompt-injected run that
// somehow reached it) cannot write arbitrary content into last_error.
type retryJobRequest struct {
	Attempt int    `json:"attempt"`
	Outcome string `json:"outcome"`
}

// retryOutcomes are the failure classes a worker may report.
var retryOutcomes = map[string]bool{
	"invocation_failed":               true,
	"model_exited_without_completion": true,
}

// handleRetryJob is POST /jobs/{id}/retry: the worker says the invocation of
// its claimed attempt failed and the job should run again soon, instead of
// after the visibility timeout. Worker-only and not a tool. The compare-and-
// set on status and attempt makes it harmless when late: a job already
// completed, dead-lettered or re-claimed answers 409.
func (s *Server) handleRetryJob(w http.ResponseWriter, r *http.Request) {
	id, ok := identity(w, r)
	if !ok {
		return
	}
	jobID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || jobID <= 0 {
		writeJSONError(w, http.StatusBadRequest, "invalid job id")
		return
	}
	var req retryJobRequest
	if err := decodeStrict(w, r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if !s.enforceBinding(w, r, id, "retry_agent_job", 0, jobID, req.Attempt) {
		return
	}
	attempt := req.Attempt
	if jobBound(id) {
		attempt = id.JobAttempt
	}
	if attempt <= 0 {
		writeJSONError(w, http.StatusBadRequest, "attempt must be positive")
		return
	}
	if !retryOutcomes[req.Outcome] {
		writeJSONError(w, http.StatusBadRequest, "unknown outcome")
		return
	}
	ctx := r.Context()
	// Ownership: the job must belong to the caller's account.
	if _, err := s.Store.GetAgentJob(ctx, id.UserID, jobID); err != nil {
		if errors.Is(err, db.ErrAgentJobNotFound) {
			writeJSONError(w, http.StatusNotFound, "job not found")
			return
		}
		logHandlerErr("retry_agent_job", err)
		writeJSONError(w, http.StatusInternalServerError, "lookup failed")
		return
	}
	status, err := s.Queue.RequeueFailed(ctx, jobID, attempt, req.Outcome)
	if err != nil {
		if errors.Is(err, db.ErrAgentJobNotFound) {
			writeJSONError(w, http.StatusConflict, "job is no longer claimed under that attempt")
			return
		}
		logHandlerErr("retry_agent_job", err)
		writeJSONError(w, http.StatusInternalServerError, "retry failed")
		return
	}
	s.audit(ctx, id.UserID, "retry_agent_job", "ok", req.Outcome+" -> "+status)
	writeJSON(w, http.StatusOK, map[string]any{"status": status})
}

// reportJobCostRequest is the body of POST /jobs/{id}/cost. It carries only
// what the worker observed. The user, job, attempt (from the job token) and
// runtime (from the job row) are never read from it: decodeStrict rejects a
// body that names user_id, runtime or job_id.
type reportJobCostRequest struct {
	// Attempt is the legacy claim identity; optional with a job token.
	Attempt      int     `json:"attempt"`
	CostUSD      float64 `json:"cost_usd"`
	Model        string  `json:"model"`
	Runner       string  `json:"runner"`
	InputTokens  int64   `json:"input_tokens"`
	OutputTokens int64   `json:"output_tokens"`
}

// usageLabelRE bounds the runner and model strings a worker may report.
var usageLabelRE = regexp.MustCompile(`^[A-Za-z0-9._:/-]{0,128}$`)

// handleReportJobCost is POST /jobs/{id}/cost — a worker-only, out-of-band
// report of the Claude spend observed for one claimed attempt. Modelled on
// handleJobComplete's shape (identity, decodeStrict, an existing-job check,
// the same 409-on-stale-claim mapping), but deliberately NOT registered as
// an MCP tool anywhere (absent from allowedTools and NewMCPServer's tool
// builders — see internal/agentworker/claudeinvoker.go) and NOT reachable by
// the model: this is a fact the worker observes after `claude` exits, not a
// claim the model can assert about its own spend.
func (s *Server) handleReportJobCost(w http.ResponseWriter, r *http.Request) {
	id, ok := identity(w, r)
	if !ok {
		return
	}
	jobID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || jobID <= 0 {
		writeJSONError(w, http.StatusBadRequest, "invalid job id")
		return
	}
	var req reportJobCostRequest
	if err := decodeStrict(w, r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if !s.enforceBinding(w, r, id, "report_agent_job_cost", 0, jobID, req.Attempt) {
		return
	}
	// With a job token the attempt is the token's. An account token must name
	// it: the cost write fences on attempts, and attempt 0 would match a
	// never-claimed pending job (ClaimAgentJobs always hands out >= 1).
	attempt := req.Attempt
	if jobBound(id) {
		attempt = id.JobAttempt
	}
	if attempt <= 0 {
		writeJSONError(w, http.StatusBadRequest, "attempt must be positive")
		return
	}
	if req.CostUSD < 0 {
		writeJSONError(w, http.StatusBadRequest, "cost_usd must not be negative")
		return
	}
	if req.InputTokens < 0 || req.OutputTokens < 0 {
		writeJSONError(w, http.StatusBadRequest, "token counts must not be negative")
		return
	}
	if !usageLabelRE.MatchString(req.Runner) || !usageLabelRE.MatchString(req.Model) {
		writeJSONError(w, http.StatusBadRequest, "invalid runner or model")
		return
	}
	ctx := r.Context()
	job, err := s.Store.GetAgentJob(ctx, id.UserID, jobID)
	if err != nil {
		if errors.Is(err, db.ErrAgentJobNotFound) {
			writeJSONError(w, http.StatusNotFound, "job not found")
			return
		}
		logHandlerErr("report_agent_job_cost", err)
		writeJSONError(w, http.StatusInternalServerError, "lookup failed")
		return
	}
	outcome, err := s.Store.RecordAgentJobUsage(ctx, id.UserID, jobID, attempt, db.Usage{
		CostUSD: req.CostUSD, Model: req.Model, Runner: req.Runner,
		InputTokens: req.InputTokens, OutputTokens: req.OutputTokens,
		JobScoped: jobBound(id),
	})
	if err != nil {
		if errors.Is(err, db.ErrUsageCredential) {
			s.audit(ctx, id.UserID, "report_agent_job_cost", "denied", "managed job needs its job token")
			writeJSONError(w, http.StatusForbidden, "managed job cost must be reported with the job token")
			return
		}
		if errors.Is(err, db.ErrUsageConflict) {
			s.audit(ctx, id.UserID, "report_agent_job_cost", "refused", "usage_conflict")
			writeJSON(w, http.StatusConflict, map[string]any{"error": "usage_conflict"})
			return
		}
		if errors.Is(err, db.ErrAgentJobNotFound) {
			// Same "too late" shape as handleJobComplete's own CAS loss: the
			// claim was requeued and re-claimed under a newer attempt since
			// the worker last saw it.
			writeJSONError(w, http.StatusConflict, "job is no longer claimed under that attempt")
			return
		}
		logHandlerErr("report_agent_job_cost", err)
		writeJSONError(w, http.StatusInternalServerError, "record cost failed")
		return
	}
	if outcome == db.UsageUnchanged {
		writeJSON(w, http.StatusOK, map[string]any{"recorded": true, "unchanged": true})
		return
	}
	s.countUsage(req, job.Runtime == db.RuntimeManaged)
	s.audit(ctx, id.UserID, "report_agent_job_cost", "ok", "")
	writeJSON(w, http.StatusOK, map[string]any{"recorded": true})
}

// countUsage adds a first settle to the usage metrics. Runner is clamped to a
// fixed set and model to a bounded set (Registry.UsageModel) that only
// managed-runtime jobs can add to, so no worker can grow the label space.
func (s *Server) countUsage(req reportJobCostRequest, managed bool) {
	if s.m == nil {
		return
	}
	model := s.m.UsageModel(req.Model, managed)
	s.m.AgentUsageCostUSDTotal.WithLabelValues(metrics.UsageRunner(req.Runner), model).Add(req.CostUSD)
	s.m.AgentUsageTokensTotal.WithLabelValues("input", model).Add(float64(req.InputTokens))
	s.m.AgentUsageTokensTotal.WithLabelValues("output", model).Add(float64(req.OutputTokens))
}
