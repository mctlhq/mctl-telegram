# Preflight checklist: Part B managed soak (gate #889)

Status: PLANNED, NOT APPROVED FOR EXECUTION (2026-11-04). Run this list on the
day before the window. Every item needs a recorded answer. A blank or "could
not check" is a NO-GO for starting, not a pass. Plan: `gate-889-managed-soak.md`.

Items marked OWNER need a separate owner permission. Nothing on this list is
done by the agent without it.

## A. Authorisations (all OWNER)

- [ ] A1. Owner decision D-A recorded on #889 (how Part A is closed).
- [ ] A2. Tester allowlist approved (D1): count, who asks, how consent is kept.
- [ ] A3. Written consent from every tester, covering: AI processing by a
      third-party provider, no replies sent, withdrawal at any time. Kept by the
      owner outside the repository.
- [ ] A4. Permission to set `audience.onlySenders` to the allowlist (D2).
- [ ] A5. Permission to set `listening: true` for the window (D2).
- [ ] A6. Permission for the isolation account to listen on `runtime: own` (D2).
- [ ] A7. Stop actions pre-authorised for the window (D2).
- [ ] A8. Window caps approved (D3), and a gitops PR approved if the day cap is raised.
- [ ] A9. Thresholds approved (D5).
- [ ] A10. The Part B acceptance table posted on #889 and accepted by the owner.

## B. Build and configuration (read-only checks)

- [ ] B1. Merge commits of #885 and #886 are ancestors of the preview server
      image and of the pool worker image. Both tags recorded.
- [ ] B2. Preview server and pool worker are on the same release lineage; image
      tags recorded and compared to `main`.
- [ ] B3. Worker: `AGENT_RUNNER=openai`, model `zai-org/GLM-5.1`, base URL
      `custom-nebius`, `AGENT_WORKER_CONCURRENCY=1`, 1 replica, memory limit 256Mi.
- [ ] B4. `MANAGED_RUNTIME_ENABLED` true on preview, `MANAGED_RUNTIME_MAX_ACCOUNTS`
      1, caps as agreed in A8; per-job cap 0.25.
- [ ] B5. Production has no `MANAGED_*` flags set and its release PR #1117 is untouched.
- [ ] B6. Managed account install: `runtime: managed`, mode `observe`, send
      disabled, install revision recorded, `listening: false` before A5.
- [ ] B7. Isolation account is `runtime: own`, `listening: false` before A6.
- [ ] B8. Pool token present and not revoked; its `jti` recorded (not the token).
- [ ] B9. Held replies from earlier runs are `expired` or otherwise accounted for.
- [ ] B10. No rollout, image bump or gitops change to the server or worker is
      scheduled for the window (freeze). The owner is told the window dates.

## C. Evidence tooling (read-only)

- [ ] C1. Sampler dry run produced a baseline sample: restarts, `kubectl top`,
      job counts by status, `processing` older than 5 min, unsettled usage rows,
      owner-only notification counts.
- [ ] C2. Database access works read-only and the queries for criteria 3 to 11b
      run on the baseline.
- [ ] C3. Log retention for the server and worker covers 72 h plus a margin, and
      previous-container logs are saved on any restart.
- [ ] C4. Metrics queryable in vmsingle: the names listed in section 3.4 of the plan.
- [ ] C5. Window start time and the baseline job id are written down; every
      query filters on `created_at` from that time.

## D. Safety

- [ ] D1. The rollback order in the runbook is open and understood; the targeted
      stop (listening off, then paused) is distinguished from the full rollback.
- [ ] D2. The owner has a channel for withdrawal by a tester.
- [ ] D3. No Cloudflare apply, Vault write, production change or flag change is
      part of the start. If one is needed, stop and ask.
- [ ] D4. Sending stays disabled; no pending reply is approved at any point.

## E. Go for start

All of A, B, C and D are ticked, with the answers recorded in a comment on #889.
The agent then asks for the start command from the owner; it does not start by
itself.
