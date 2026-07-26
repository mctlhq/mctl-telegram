# Communication Agent C1 validation report

This report is the durable evidence log for the C1 preview rollout described
in [`docs/plans/communication-agent.md`](../plans/communication-agent.md).
Do not copy Telegram message bodies, credentials, owner-profile restricted
fields, or Vault values into this file.

## Scope and acceptance

C1 is bounded to the preview service, owner Telegram account `210408407`,
and dedicated test sender `8745115872`. During a test window:

- server kill switch is false;
- profile mode is `observe`;
- autopilot is unpaused only so proposals are permitted;
- listener is enabled with `sender_allowlist=8745115872`;
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

## Remaining checklist

- [ ] Merge the sender-allowlist/eval follow-up PR after CI and review.
- [ ] Move the whole owner profile from Git ConfigMap to Vault-backed Secret.
- [ ] Deploy the merged server and `Dockerfile.agent-worker` image by exact
      merge SHA; verify ArgoCD `Synced Healthy` and the running image digest.
- [ ] Run the 30-fixture harness and record aggregate results here.
- [ ] Run and record all three live Telegram drills.
- [ ] Finish in the safe stopped state:
      `AGENT_KILL_SWITCH=true`, `listener_enabled=false`,
      `autopilot_paused=true`, worker replicas `0`.
- [ ] Close implementation issues #296/#297 and GitOps #624 only after all
      evidence is present; create the separate C2 quota-domain gate issue.
