# Preflight checklist: Part B managed soak (gate #889)

Status: APPROVED (2026-11-04). Run this list before the window. Every item needs
a recorded answer. A blank or "could not check" is a NO-GO for starting, not a
pass. Plan: `gate-889-managed-soak.md`.

Section A records owner permissions. Tester consent is confirmed by the owner, and
no identifier or consent text is written to GitHub.

## A. Authorisations (all OWNER)

- [ ] A1. Owner decision D-A recorded on #889: Part A stays INCONCLUSIVE.
- [ ] A2. Three testers who are not contacts and have no chat with the account.
- [ ] A3. The owner confirms written consent from every tester, covering AI
      processing by a third-party provider, no replies sent, and withdrawal at any
      time by direct message to the owner. Kept outside the repository.
- [ ] A4. Allowlist permitted (D2) and set to the consenting testers only.
- [ ] A5. Listening and lifting `autopilot_paused` on the managed account permitted (D2).
- [ ] A6. Isolation account listening on `runtime: own` permitted (D2).
- [ ] A7. Stop actions pre-authorised for the window (D2).
- [ ] A8. Window limit of $3 and day cap of 1.00 recorded (D3).
- [ ] A9. Thresholds recorded (D5).
- [ ] A10. The Part B acceptance table posted on #889 with the owner's decision.

## B. Build and configuration (read-only checks)

- [ ] B1. Merge commits of #885 and #886 are ancestors of the preview server
      image and of the pool worker image. Both tags recorded.
- [ ] B2. Preview server and pool worker are on the same release lineage; image
      tags recorded and compared to `main`.
- [ ] B3. Worker: `AGENT_RUNNER=openai`, model `zai-org/GLM-5.1`, base URL
      `custom-nebius`, `AGENT_WORKER_CONCURRENCY=1`, 1 replica, memory limit 256Mi.
- [ ] B4. `MANAGED_RUNTIME_ENABLED` true on preview, `MANAGED_RUNTIME_MAX_ACCOUNTS`
      1, day cap 1.00, per-job cap 0.25. `MANAGED_BUDGET_USD_PER_ACCOUNT_MONTH` is
      the month's ledger total at the start plus 2.70, `MANAGED_CLAIM_NOT_AFTER`
      is the window end, `AGENT_OPENAI_MAX_OUTPUT_TOKENS` is 4096, and all of them
      are read from the running pods. The window lies inside one UTC month.
- [ ] B5. Production has no `MANAGED_*` flags set and its release PR #1117 is untouched.
- [ ] B6. Managed account install: `runtime: managed`, mode `observe`, sending
      read back as off, install revision recorded, `listening: false` before A5.
- [ ] B7. Isolation account is `runtime: own`, sending read back as off,
      `listening: false` before A6.
- [ ] B8. Pool token present and not revoked; its `jti` recorded (not the token).
- [ ] B9. Held replies from earlier runs are `expired` or otherwise accounted for.
- [ ] B10. Freeze: the `push` trigger is gone from `preview-deploy.yml` on `main`,
      no rollout, image bump or gitops change to the server or worker is scheduled
      for the window, and `sampler.sh pin` has recorded the digests and templates.
- [ ] B11. The four budget alerts route to the operator Telegram channel, firing
      and resolving were both observed, and any temporary cap is restored.

## C. Evidence tooling (read-only)

- [ ] C1. Sampler dry run produced a baseline sample: restarts, `kubectl top`,
      job counts by status, `processing` older than 5 min, unsettled usage rows,
      owner-only notification counts.
- [ ] C2. Database access works read-only and `scripts/gate-889/criteria.sql` runs
      on the live database. `scripts/gate-889/mutations.py` shows every detector
      green on a converged input and red on a deliberate mutation.
- [ ] C3. Log retention for the server and worker covers 72 h plus a margin, and
      previous-container logs are saved on any restart.
- [ ] C4. Metrics queryable in vmsingle: the names listed in section 3.4 of the plan.
- [ ] C5. Window start and end times and the baseline job id are written down;
      every query filters on `created_at` from the start time.
- [ ] C7. The value of `EVENTS_OPERATOR_ROUTING` on preview is recorded (default false:
      then no routed rows exist and criterion 3's route-reason check is not observable).
- [ ] C6. Minimum traffic precondition: 30 completed turns and 3 coalesced turns
      from organic tester traffic are achievable with the agreed schedule.

## D. Safety

- [ ] D1. The rollback order in the runbook is open and understood; the targeted
      stop (listening off, then paused) is distinguished from the full rollback.
- [ ] D2. The owner has a channel for withdrawal by a tester.
- [ ] D3. No Cloudflare apply, Vault write, production change or flag change is
      part of the start. If one is needed, stop and ask.
- [ ] D4. Sending stays disabled; no pending reply is approved at any point.

## E. Go for start

All of A, B, C and D are ticked, and the comment on #889 quotes each recorded
value (tester count, window start and end, baseline job id, caps, thresholds). A
tick with no quoted value does not count and a blank is NO-GO.
On a green list the agent starts the window at the next 00:00 UTC without a
further "go" (owner decision, 2026-11-04) and records the actual UTC boundaries,
baseline, versions and budget on #889.
