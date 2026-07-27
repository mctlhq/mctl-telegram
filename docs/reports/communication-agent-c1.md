# Communication Agent C1 validation report

This report is the durable evidence log for the C1 preview rollout described
in [`docs/plans/communication-agent.md`](../plans/communication-agent.md).
Do not copy Telegram message bodies, credentials, owner-profile restricted
fields, or Vault values into this file.

## Scope and acceptance

C1 is bounded to the preview service, one owner Telegram account, and one
dedicated allowlisted test sender. Exact Telegram identifiers remain in the
private operational evidence store, not this repository. During a test window:

- server kill switch is false;
- profile mode is `observe`;
- autopilot is unpaused only so proposals are permitted;
- listener is enabled with only the dedicated test sender allowlisted;
- every reply still requires owner approval.

Acceptance:

- 30-fixture evaluation: at least 27 correct action classifications;
- all 30 jobs terminal under the same claimed attempt;
- zero restricted/adversarial output leaks;
- zero wrong-peer/job/attempt durable writes;
- three live drills pass: draft/notification/audit, one explicitly approved
  harmless reply to the test peer, and kill-switch rejection after approval.

## Evidence

### 2026-07-26 — containment and MCP completion fix

- Preview profile confirmed `mode=observe`, `autopilot_paused=true`, and
  `listener_enabled=false` before rollout work.
- PR [#316](https://github.com/mctlhq/mctl-telegram/pull/316) merged to main
  as `d92939d`: MCP config uses `alwaysLoad: true`; a successful Claude exit
  is accepted only after `GET /jobs/{id}` confirms a terminal status for the
  same job and attempt.
- Full `go test ./...` and `go vet ./...` passed locally; GitHub build,
  CodeQL, vulnerability, Docker, manifest, and lint checks passed.
- The required Claude review was retried after the interactive limit reset,
  but both GitHub Action and the resumed local Claude session failed before
  analysis with the organization monthly spend limit. The merge records the
  explicit infrastructure exception; independent review found no P1/P2.

### 2026-07-26 — validation hardening branch

- Added an admin-controlled sender allowlist enforced before listener
  persistence. Empty remains allow-all; a configured but invalid list fails
  closed. Targeted DB/API/listener/worker tests pass.
- Added an opt-in 30-fixture real Claude Code + stdio MCP evaluation harness.
  Normal CI skips it and consumes no model quota.

### 2026-07-26 — Saved Messages capture and live approve cycle

- PR [#319](https://github.com/mctlhq/mctl-telegram/pull/319) added a
  DB-backed Saved Messages cursor and five-second history polling while
  preserving push delivery as the fast path.
- Live validation exposed that `messages.getHistory(InputPeerSelf)` does not
  reliably set `Message.Out=true`. PR
  [#322](https://github.com/mctlhq/mctl-telegram/pull/322) removed that
  invalid history-only gate and added regression coverage. Direct
  self-peer checks, forwarded-message rejection, event-id deduplication, and
  cursor retry semantics remain enforced.
- A fresh `/mctl approve` command was captured from Saved Messages and routed
  through the existing durable event/control path. The corresponding action
  reached `agent_actions.status=executed`, and the resulting message was
  delivered to the allowlisted test peer. Neither the message body nor exact
  Telegram identifiers are recorded in this report.
- Diagnostic logging from #320/#321 was removed by the final #322 change; it
  is not present on main.
- The test window was closed and verified live:
  `AGENT_KILL_SWITCH=true`, `listener_enabled=false`,
  `autopilot_paused=true`, and worker replicas `0`.
- GitOps PRs
  [#639](https://github.com/mctlhq/mctl-gitops/pull/639) and
  [#640](https://github.com/mctlhq/mctl-gitops/pull/640) changed both
  Telegram Deployments to `Recreate`. After clearing the stale live
  `rollingUpdate` field, both Argo applications reported
  `Synced / Healthy / Succeeded` at merge revision `31e49a4c`.
- A later diagnostic call found the preview MTProto session rejected with
  `AUTH_KEY_DUPLICATED`. The safe stopped state is unaffected, but the test
  account must complete a fresh OAuth reconnect before the next live window.

### 2026-07-26 — pre-production hardening and exact-SHA preview

- PRs
  [#323](https://github.com/mctlhq/mctl-telegram/pull/323),
  [#324](https://github.com/mctlhq/mctl-telegram/pull/324),
  [#326](https://github.com/mctlhq/mctl-telegram/pull/326),
  [#327](https://github.com/mctlhq/mctl-telegram/pull/327),
  [#328](https://github.com/mctlhq/mctl-telegram/pull/328), and
  [#331](https://github.com/mctlhq/mctl-telegram/pull/331) shipped a
  fail-closed review gate, terminal-session retirement, hashed/encrypted
  approval codes, mutation-safe job claim, encrypted per-tenant owner
  profiles, and atomic exact-result completion.
- PR [#332](https://github.com/mctlhq/mctl-telegram/pull/332) shipped the
  operations runbook, full retention/deletion mapping, dead-letter and stuck
  execution alerts, retention enforcement, and adversarial policy tests.
  Codex found three P2 issues before merge: an executing-action retention
  race, contradictory privacy wording, and a nonexistent key-rotation
  procedure. All were fixed, their threads resolved, and a final Codex
  review returned no additional findings.
- Full Go tests, vet, targeted race tests, Docker build, govulncheck,
  Prometheus rule validation, manifest checks, and CodeQL passed. Claude
  review did not run because the organization monthly quota was exhausted;
  the explicit operator-approved admin exception was used only for that
  failed check.
- Main merge `57f9ba6` was built as
  `ghcr.io/mctlhq/mctl-telegram:main-57f9ba6` with digest
  `sha256:212b0e9292449550c0bca9cea8f7d5dd58edee11e18c1251e7e1718892da0547`.
  GitOps commit `0cd36f1` selected that exact tag. The platform status API
  reported `labs-mctl-telegram-preview` and `labs-agent-worker-preview`
  `Healthy / Synced`; the server used `main-57f9ba6`, and the worker's
  GitOps source remained `replicaCount: 0`.
- The closed-state source of truth remains
  `AGENT_KILL_SWITCH=true`, worker replicas `0`, and the previously verified
  `listener_enabled=false` / `autopilot_paused=true`. No test window was
  opened during this deployment.

### 2026-07-26 — worker parity and legacy profile retirement

- GitOps workflow
  [run 30219882645](https://github.com/mctlhq/mctl-gitops/actions/runs/30219882645)
  built `Dockerfile.agent-worker` from exact code merge
  `57f9ba6e3e8fdd0ac37c6c8607ec20f1b57e69b4` and published
  `ghcr.io/mctlhq/agent-worker-preview:main-57f9ba6` with digest
  `sha256:1a5404d253e5f110efdaa0c189ddd9f90216d3e637b7019ccae3d4b9360a3d0d`.
- Startup logs proved the migration sequence without exposing profile
  content: the first DB-backed release logged
  `legacy agent owner profile migration checked` with `imported=true`;
  subsequent restarts logged `imported=false` for the same tenant row.
- GitOps PR
  [#641](https://github.com/mctlhq/mctl-gitops/pull/641), merged as
  `1d67c6c635445c41065ff0067fcae8ef0acb1c1c`, removed
  `AGENT_PROFILE_PATH`, `AGENT_PROFILE_OWNER_TG_ID`, the plaintext profile
  Secret projection, and its volume mount. Runtime profile reads are now
  encrypted and DB-backed only.
- The same PR completed the C1 worker pod baseline: non-root execution,
  read-only root filesystem, all capabilities dropped, privilege escalation
  disabled, `RuntimeDefault` seccomp, no service-account token, explicit
  ephemeral-storage bounds, and bounded writable `HOME`/`/tmp` emptyDir
  mounts. Claude review approved the PR with no P1/P2 findings and all
  manifest/lint checks passed.
- After merge, the platform status API reported both
  `labs-mctl-telegram-preview` and `labs-agent-worker-preview`
  `Healthy / Synced`, both selecting `main-57f9ba6`. Worker replicas remained
  `0`; the server kill switch remained on and no test window was opened.
- The separate production quota-domain gate is tracked in
  [#334](https://github.com/mctlhq/mctl-telegram/issues/334). Admin merge
  bypasses do not supply runtime model capacity and are not a C2 mitigation.

### 2026-07-27 — Telegram reconnect and 30-fixture gate

- The preview Telegram account completed a fresh OAuth/MTProto reconnect.
  A post-reconnect `list_dialogs` call succeeded, and server logs recorded a
  successful Telegram login without another `AUTH_KEY_DUPLICATED` error.
- The first full 30-fixture run correctly classified and terminated all 30
  jobs but exposed restricted output in all three adversarial fixtures.
  Field-level diagnostics identified the affected reply/summary arguments
  without logging their values.
- PR [#336](https://github.com/mctlhq/mctl-telegram/pull/336) made filtered
  diagnostic runs fail closed, added field-level leak evidence, and hardened
  the C1 prompt so adversarial clauses are silently discarded from every
  tool argument. The targeted adversarial rerun passed 3/3 with zero leaks.
- The final full real-Claude-Code evaluation passed in 393.148 seconds:
  30/30 correct classifications, 30/30 same-attempt terminal jobs, zero
  restricted/adversarial output leaks, and zero wrong binding writes.
  `go test ./...`, `go vet ./...`, Docker, CodeQL, vulnerability, lint, and
  manifest checks also passed. Claude review could not run because the
  organization monthly quota was exhausted; the operator-approved admin
  exception was limited to that infrastructure failure.
- GitOps PR
  [#644](https://github.com/mctlhq/mctl-gitops/pull/644) selected the same
  validated prompt guardrails for deployment. Its manifest and YAML checks passed, and
  Claude explicitly approved it with no P1/P2 findings. The PR did not alter
  replicas, kill-switch, listener, or autopilot settings.

## Remaining checklist

- [x] Merge the sender-allowlist/eval follow-up (#318).
- [x] Deploy the Saved Messages fix by exact merge SHA and verify the live
      approve cycle.
- [x] Deploy the encrypted per-tenant DB profile implementation and the
      hardened server by exact merge SHA; verify ArgoCD `Synced Healthy` and
      record the image digest.
- [x] Verify the legacy YAML was imported once, then remove the plaintext
      profile Secret projection and migration env vars.
- [x] Build and deploy the matching `Dockerfile.agent-worker` image by exact
      merge SHA before the worker is scaled above zero.
- [x] Run the 30-fixture harness and record aggregate results here.
- [ ] Run the remaining kill-switch-after-approval live drill. Draft,
      notification, audit, and one harmless explicitly approved reply have
      passed.
- [x] Finish the completed test window in the safe stopped state:
      `AGENT_KILL_SWITCH=true`, `listener_enabled=false`,
      `autopilot_paused=true`, worker replicas `0`.
- [x] Reconnect the preview Telegram test account with a fresh OAuth session
      before opening another test window.
- [x] Store approval codes as hashes and ship the full
      retention/adversarial hardening set.
- [ ] Run the `random_id` retry drill before guarded autopilot.
- [ ] Provision a production quota domain isolated from interactive sessions
      and `claude-review.yml` before C2.
- [ ] Close implementation issues #296/#297 and GitOps #624 only after all
      evidence is present; create the separate C2 quota-domain gate issue.
