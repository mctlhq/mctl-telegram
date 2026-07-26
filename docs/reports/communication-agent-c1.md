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

## Remaining checklist

- [x] Merge the sender-allowlist/eval follow-up (#318).
- [ ] Move the whole owner profile from Git ConfigMap to Vault-backed Secret.
- [x] Deploy the Saved Messages fix by exact merge SHA and verify the live
      approve cycle.
- [ ] Run the 30-fixture harness and record aggregate results here.
- [ ] Run the remaining kill-switch-after-approval live drill. Draft,
      notification, audit, and one harmless explicitly approved reply have
      passed.
- [x] Finish the completed test window in the safe stopped state:
      `AGENT_KILL_SWITCH=true`, `listener_enabled=false`,
      `autopilot_paused=true`, worker replicas `0`.
- [ ] Reconnect the preview Telegram test account with a fresh OAuth session
      before opening another test window.
- [ ] Store approval codes as hashes, run the `random_id` retry drill, and
      ship the full retention/adversarial hardening set before guarded
      autopilot.
- [ ] Provision a production quota domain isolated from interactive sessions
      and `claude-review.yml` before C2.
- [ ] Close implementation issues #296/#297 and GitOps #624 only after all
      evidence is present; create the separate C2 quota-domain gate issue.
