# Finance owner-origin and source-consent contract (design proposal, #1265)

Status: PROPOSED. DESIGN ONLY. Refs #1265 (not Closes). Nothing here is implemented,
activated, or approved. Merging this document changes no behavior and authorizes no
implementation. Every new schema, token, permission or owner UX below is
**PENDING OPERATOR DECISION**.

`FINANCE_SECURITY_GATE=BLOCKED`. Parent #1244 and mctlhq/.github#325 remain
`RESEARCH_ONLY_DEFER`. This document does not approve finance runtime, pilot,
production, real Telegram accounts, finance records, egress or deployment.

Source revision read: `origin/main` = `0a8d29fc572ad945d38245af2bc49344dd9704fc`
(fetched 2026-11-10). Evidence report read: `docs/reports/finance-assistant-l2-results.md`,
which records its own tested HEAD `b9ba5ebfb36a6ff4907786fbb341342f42f1fac7` (workflow run
#42620545631). Code facts below were read at the `origin/main` revision, not re-run.
No tests, mutations or network were used for this document.

## 1. Problem

A job created from a third-party (Bob) private message can call `send_owner_summary`
and the server queues an owner notification. The only checks are job binding, install
revision, kill switch and mode. Nothing asks whether the owner invoked, or consented
to, finance handling of that source. Routing the output to the owner only (Saved
Messages) is an output-audience property. It is not consent to process the source.

Four properties are distinct and must not be conflated:

| Property | Question | Exists today |
| --- | --- | --- |
| Owner identity / output audience | Who receives the output? | Yes: `owner_notifications.user_id`, delivered to `InputPeerSelf` |
| Invocation authority | Did the owner start this work? | Partly: `saved_command` events are owner-authored; peer `private_message` events are not. Not consulted by the summary path |
| Source consent | Did the owner agree this source may feed a finance summary? | No |
| Finance classification | Is this work finance work at all? | No (L2 row `T2.finance_origin_authorization` is NOT-IMPLEMENTED) |

## 2. Existing facts (read from source)

All paths are at `origin/main` 0a8d29fc.

- `internal/agentapi/actions.go` `handleNotifySummary` calls `handleOwnerFacing`
  (`db.ActionTypeOwnerSummary`, `db.NotificationSummary`, tool `send_owner_summary`).
  Order: strict decode; `enforceBinding` and `requireBoundJob` (`internal/agentapi/binding.go`);
  non-empty text; profile load; conversation load by `(user, conversation_id)`; if a
  job is named, `GetAgentJob` and a job-to-conversation check, and
  `jobRevision = job.InstallRevision`; assistant-manipulation special case;
  `policy.Evaluate`; `InsertAgentAction`; reload persisted action (durable state is
  authoritative on replay); `InsertOwnerNotification` (idempotent per `action_id`).
- `internal/agent/policy/policy.go` `Evaluate`: owner-facing action types return
  `Allow` ("owner-facing action") after the global gates (kill switch, mode off,
  install-revision fence). `policy.Input` has no origin, consent or classification
  field. Conversation state and sender blocklist are explicitly bypassed.
- Origin evidence that exists: `db.IncomingEvent` kinds in `internal/db/agent_events.go`:
  `private_message` (non-bot peer), `message_edit`, `owner_outgoing`, `saved_command`
  (owner message in Saved Messages parsed as `/mctl`, classified by peer identity in
  `internal/agent/listener/extract.go`, not by `msg.Out`), `message_delete`. Events
  carry `ChatTGID` and `SenderTGID`. `agent_jobs.event_id` links a job to its head
  event; `AgentJob.SourceEventIDs` lists the coalesced turn. `AgentJob` also carries
  `ConversationID`, `Attempts`, `InstallRevision`, `Runtime`, `Status`.
- Delivery: `internal/agent/control/notifier.go` `Notifier.DeliverPending` drains
  `owner_notifications` (claim, lease, `SendToSelfWithRandomID`, mark sent/failed).
  Recent fence commits on this branch lineage (`f145fa68`, `9453263d`) are in
  `origin/main`; this design does not depend on their internals.
- Callers that reach owner-facing output (grep of non-test code):
  1. Worker MCP tool `send_owner_summary` (`internal/agentworker/mcpserver.go`,
     `client.go` -> `POST /notify/summary`) with a job-bound credential: the
     peer-triggered case this issue is about, and also ordinary non-finance use.
  2. Same endpoint with the account-wide `agent` token, jobless (for example a
     general daily summary). Judged at the server-verified current revision (#1266).
  3. `request_owner_approval` (same handler, `NotificationApproval`).
  4. `propose_reply` pending-approval notifications (control notifier doc comment).
  5. `internal/humaninput/poller.go` direct `InsertOwnerNotification` of
     human-input follow-ups: no action row, no job. Out of scope here.
  6. The server-owned `assistant_manipulation` alert: fixed text that never quotes
     the sender; must remain exempt from any finance gate (it carries no finance data).
  `internal/agent/schedule/schedule.go` contains no summary call (grep); not confirmed
  beyond that.
- Canonical L2 behavior (`internal/agentapi/l2finance_api_test.go`, `TestL2Finance_T2`,
  tag `l2finance`): a job-bound `POST /notify/summary` with finance-looking synthetic
  text yields HTTP 200, one `executed` action, one `owner_notifications` row owned by
  Alice (kind `summary`), zero Carol rows, zero peer sends. That records
  `T2.ordinary_owner_routing` = PASS. The same test then calls
  `expectGap("T2.bob_job_owner_summary", ok, ...)`, which records FAIL/GAP
  ("finance-looking text from Bob-conversation job allowed to queue owner summary
  without a finance owner-invocation grant"). `T2.finance_origin_authorization` is
  recorded NOT-IMPLEMENTED ("no finance-source label, source consent or finance policy
  gate exists"). Matrix in `finance-assistant-l2-results.md`: 64 rows, PASS 43,
  FAIL/GAP 9, NOT-IMPLEMENTED 6, CANNOT-OBSERVE 6. The gate manifest
  (`internal/l2finance/gate/testdata/manifest.txt`) lists `agentapi:T2.bob_job_owner_summary`
  and `agentapi:T2.ordinary_owner_routing`.
- Existing discovery (`docs/reports/finance-assistant-owner-private-discovery.md`)
  states there is no consent grant and that `send_owner_summary` invocation "is
  peer-triggered"; it sketches an install revision plus a consent-grant revision and
  a per-account consent/source grant with revoke. It does not specify binding fields,
  issuer, checks or tests. This document is the detailed contract for that sketch's
  origin/consent part, not a duplicate of an existing design. No other equivalent
  design was found in `docs/`.

Missing context: the text of issues #1265, #1271, #1272, #1244 and .github#325 was not
available offline; this document relies on the task statement for them. #1271/#1272
code is not assumed.

Documentation inconsistency (observed, not edited): `docs/reports/finance-assistant-l2-slice-c.md`
(pinned `5fb1de89`) lists `T2.bob_job_owner_summary` as PASS "Ordinary owner routing
only". That conflicts with the results report and the current test, which grade it
FAIL/GAP and forbid reclassification. The results report and test are treated as
canonical; the slice-c row predates them and must not be used as evidence of a pass.

## 3. What counts as evidence of origin and consent

Not proof: model intent, keywords or finance-looking text, sender identity, workspace
identity, an agent-supplied `intent` string, or the request body. All of these are
attacker-influenced by a third party or by the model.

Usable, server-derived evidence:

- **Origin of the job**: the persisted event kind(s) and `SenderTGID` of
  `agent_jobs.event_id` and `SourceEventIDs`, read server-side from the DB by job id.
  Never taken from the request. Owner-origin = every event in the turn is
  `saved_command` (owner-authored, peer-identity classified). Third-party-origin =
  any `private_message` or `message_edit`. Mixed turns count as third-party-origin.
- **Install state**: `profile.InstallRevision`, `job.InstallRevision`, `mode`.
- **Owner consent record**: does not exist today. It would be created only by an
  owner-authenticated path (section 5).
- **Finance classification**: no evidence exists. Content inspection is rejected. The
  only non-content basis is an owner declaration (decision D1).

## 4. Contract options

### Option 1 (recommended): declared-scope deny-by-default, owner-origin only

Finance handling is a property the owner declares on the install (a revisioned
purpose flag, PENDING schema). For an install so declared, an owner-facing summary
whose job has any third-party-origin event is refused. Summaries from owner-origin
jobs (`saved_command`) are allowed. There is no grant, token or issuer: the absence
of a grant is the control.

- Binding fields: owner `user_id`, `job_id`, `attempt`, `job.InstallRevision` versus
  current revision, the persisted origin set of the job, purpose declaration revision.
- Issuer: none. Owner-origin is established only from the persisted event kind.
- Pros: smallest new surface; no token or UX; fail-closed; no consent state to leak
  or revoke. Cons: peer-triggered finance summaries are impossible until a later
  option is approved.

### Option 2 (main alternative): owner-issued per-source consent grant

A durable grant row, issued only by the owner, authorizes owner summaries for
third-party-origin jobs from one source.

- Issuer: the owner via an owner-authenticated Saved Messages `/mctl` command
  (`saved_command`, existing peer-identity classification) handled by the control
  path (`internal/agent/control`). Never an agent/job token, never a model tool, never
  the web UI without a separate decision.
- Binding fields: `owner_user_id`, `account_tg_id`, `install_revision` and
  `grant_revision`, `conversation_id` plus source peer `tg_id`, `purpose`
  (a fixed enumerated value, for example `finance_owner_summary`), `issued_at`,
  `expires_at` (mandatory, bounded), `revoked_at`, a random `grant_id`/nonce. Optional
  `job_id` for one-shot use; without it the grant is per-source, time-boxed.
- Replay: one-shot grants are consumed by an atomic update; per-source grants are
  bound to install and grant revision so a bump invalidates them.
- Pros: allows peer-triggered finance summaries with explicit consent. Cons: new
  table, new owner command/UX, revocation and expiry semantics, larger attack
  surface.

### Option 3: per-job owner approval through the human-input mechanism

Each finance-origin summary waits for an owner answer (existing
`internal/humaninput`). Smaller than Option 2 in schema, but the job blocks on a
human and the approval code flow is not a consent record for the source. Listed for
completeness; not recommended.

## 5. Behavior rules (apply to all options)

- Non-finance routing is unchanged. An install without the declaration, and every
  non-finance caller in section 2 (jobless account-token summaries, approval
  requests, manipulation alerts, humaninput follow-ups), keep today's behavior byte
  for byte. The new check is a no-op unless the declaration is present.
- No finance declassification: the check keys on server-persisted install
  declaration and event kinds, never on text, `intent`, or a client flag. A request
  cannot lower its own classification. A conversation or job whose origin cannot be
  determined counts as third-party-origin.
- Missing, ambiguous, unreadable or legacy state fails closed: origin events missing
  or unreadable, job without event, `ConversationID == 0` on a named job, declaration
  read error, grant lookup error, install revision 0 or legacy revision (already
  denied by policy `install_revision_missing`/`legacy_install_revision_missing`):
  deny. A denial is durable (an `agent_actions` row with `denied`, typed reason,
  and a checked audit write) before any notification or other effect. If the durable
  denial cannot be written, answer 500 and take no action (matches `denyBindingCode`).
- Jobless account-token calls cannot carry job origin. Under a finance-declared
  install a jobless summary is treated as unproven origin and denied unless Option 2
  later grants it explicitly (PENDING).
- Replay: the persisted denied action is authoritative on redelivery, as in the
  current handler; lifting a flag never turns a stored denial into a send.

### TOCTOU checkpoints

1. Queue time (`handleOwnerFacing`, before `InsertAgentAction`): origin, declaration,
   grant (Option 2), revision, kill, mode.
2. Send time (`Notifier.DeliverPending`, before `SendToSelfWithRandomID`): re-evaluate
   declaration revision, grant validity/expiry/revocation, and install revision
   against the row. Requires the queued row to carry its origin and grant binding
   (PENDING schema); a row with no binding under a finance-declared install is not
   sent and is deferred or failed, not sent.
3. Recovery/replay (lease expiry, redelivered job, sweep after restart): same check as
   send time; never trust the queue-time decision alone.
4. Revocation or expiry between queue and send blocks the send.

### Negative cases (each must be refused with no notification, no peer send)

Third-party-origin job under declared install with no grant; mixed turn (owner plus
Bob events); edited message (`message_edit`) origin; job whose event row is missing;
forged `intent` or `text` claiming owner origin; request-body fields claiming a grant;
Alice's grant used for Carol's conversation, another job, another account, or another
purpose; expired, revoked, replayed one-shot, wrong install/grant revision; declaration
removed and re-added; owner-summary with `ConversationID` of a different conversation
than the job; foreign-tenant job id; DB error on any lookup; audit write failure; queued
row surviving a revocation; notifier restart mid-claim.

Positive/regression cases: non-finance install unchanged; declared install with
owner-origin `saved_command` job allowed; assistant-manipulation alert still allowed;
jobless summary on a non-declared install unchanged.

## 6. Dependencies

- #1271 is being implemented concurrently; #1272 is unmerged. Neither is assumed. This
  proposal touches different logical gates (origin/consent at queue and send) but
  likely shares `internal/agentapi/actions.go`, `internal/agent/control/notifier.go`
  and `internal/db/agent_actions.go`. Implementation must rebase on whatever of
  #1271/#1272 has merged and may need to be sequenced after them. This PR edits none
  of those paths.

## 7. Proposed implementation files (NOT authorized; for owner approval)

Conditional on the decision table. Option 1 only unless noted.

- `internal/db/agent_schema.go`, `internal/db/agent_jobs.go` / `agent_events.go`: a
  read helper for a job's persisted origin set; declaration field on the install
  profile (D1). Option 2 adds a grants table and `grant` store methods.
- `internal/agent/policy/policy.go` (and `policy_test.go`): add origin and declaration
  inputs and a typed `DenyCode`; owner-facing Allow short-circuit consults them.
- `internal/agentapi/actions.go`: derive origin server-side in `handleOwnerFacing`,
  persist the denial durably before any effect.
- `internal/agent/control/notifier.go`: send-time re-check and a row binding.
- Tests (offline, synthetic personas Alice/Bob/Carol/Dana only, `l2finance` tag for
  matrix rows): `internal/agentapi/l2finance_api_test.go` (new finance-origin rows that
  do not rename or alter the 64 existing rows), `internal/agent/policy/*_test.go`,
  `internal/agent/control/*_test.go`, `internal/db/*_test.go`,
  `internal/l2finance/gate/testdata/manifest.txt` only by an approved row addition.

### Offline test and mutation plan (to be run only after approval)

Unit tests for each negative and positive case in section 5; a replay test (redeliver
after state change); a send-time test (queue allowed, then revoke or bump revision,
assert no send). Mutation controls to define and run later, one at a time on a
committed tree: remove the queue-time origin check; remove the send-time check; trust
request `intent`; treat missing events as owner-origin; skip durable denial write;
ignore expiry/revocation (Option 2). Each mutant must fail at least one test. Run only
bare targeted `go test` commands, offline, no live data.

## 8. Migration, compatibility and rollback

- Additive only: nullable/defaulted columns or a new table; default means "not
  declared", which preserves current behavior. Existing queued rows with no binding
  are unaffected on non-declared installs.
- Legacy and in-flight jobs and rows under a declared install fail closed (denied or
  not sent) rather than being grandfathered.
- Rollback: disable by clearing the declaration (behavior reverts to today) or by
  reverting the code; additive schema is left in place. A rolled-back state is the
  current known FAIL/GAP, not a pass.

## 9. Evidence rules

- The 64 canonical row IDs and rubric are preserved. `agentapi:T2.bob_job_owner_summary`
  stays FAIL/GAP and `T2.finance_origin_authorization` stays NOT-IMPLEMENTED until
  real implementation proof from a fresh tagged run at the implementing HEAD.
  `ordinary_owner_routing` stays PASS and must not be relabeled.
- Any new rows, or any change in the meaning of an existing row, needs separate owner
  approval and a new fixture ID; none are approved here. Nothing in this document
  claims a finance-origin row passes.
- Even after implementation, `FINANCE_SECURITY_GATE` stays BLOCKED until the owner
  and the parent gate say otherwise.

## 10. Decision table (all PENDING OPERATOR DECISION)

| # | Decision | Recommendation | Alternative | Compatibility / security tradeoff |
| --- | --- | --- | --- | --- |
| D1 | How finance classification is established | Owner-declared install purpose flag (revisioned); never content, keyword, model or sender | Per-conversation owner label; or classification from a new finance command/product class (not accepted by default) | Install flag is coarse (over-blocks peer-origin work under that install) but cannot be influenced by third parties; per-conversation label is finer but adds owner UX and state |
| D2 | Contract option | Option 1: deny peer-origin summaries under a declared install, owner-origin allowed, no grant | Option 2: owner-issued per-source consent grant | Option 1 is smallest and fail-closed but disables peer-triggered finance summaries; Option 2 restores them at the cost of a table, owner command, revocation and replay logic |
| D3 | Grant issuer (Option 2 only) | Owner `saved_command` via control path | Owner web UI with strong auth | Saved Messages reuses existing peer-identity classification; web UI is a new authenticated surface |
| D4 | Grant lifetime and scope (Option 2 only) | Mandatory short expiry, per-source, bound to install and grant revision | One-shot per job | Per-source is less friction, larger blast radius if misused; one-shot is tighter but needs an owner action per job |
| D5 | Send-time enforcement | Re-check at notifier send, queued row carries a binding | Queue-time check only | Send-time closes the queue-to-send TOCTOU but needs a schema column and touches the notifier shared with #1271/#1272 |
| D6 | Jobless account-token summaries under a declared install | Deny (origin unproven) | Allow if the owner grants explicitly | Deny may break a general daily summary for finance-declared installs; allow reopens an origin-free path |
| D7 | Row/evidence changes | No change to the 64 rows; any new row separately approved | Add rows in the same implementation PR | Keeps evidence comparable across revisions versus faster coverage |
| D8 | Sequencing with #1271/#1272 | Implement after they merge and rebase | Land in parallel and resolve conflicts | Sequencing avoids rewriting shared notifier/actions paths; parallel is faster but risks semantic conflict |

Stop point: this is a proposal. Owner exact-content approval is required before any
implementation. No push, PR, merge, activation or release follows from this document.
