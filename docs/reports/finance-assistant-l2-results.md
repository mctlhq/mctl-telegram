FINANCE_SECURITY_GATE=BLOCKED

# Finance Assistant L2 — canonical full-suite evidence (slice D, #1251)

## Current result: NOT YET VERIFIED ON THE AMENDED HEAD

- `harness_status=INVALID` — the complete runner has **not** yet executed successfully against
  the amended 64-row source-mapped manifest.
- `issue_outcome=CANNOT_OBSERVE_BLOCKED` — no new complete, pinned, trustworthy full-suite
  result exists for this revision. The test harness may yield a more specific blocked outcome
  after an actual successful invocation.
- `FINANCE_SECURITY_GATE=BLOCKED`, regardless of conventional CI status.
- `RESEARCH_ONLY_DEFER` under mctlhq/.github#325 is unchanged. No pilot, production release,
  finance policy change, live Telegram or real customer/financial data is authorized.

**Do not infer PASS from the per-case expected rubric below.** This report is a conservative
fail-closed placeholder pending an actual executed run; it is not generated test evidence.
Do not merge PR #1257 solely on the strength of this document.

## Source-reviewed canonical crosswalk (#1244)

The amended `internal/l2finance/gate/testdata/manifest.txt` contains **64 mandatory
package-qualified rows** mapped to the acceptance contract in issue #1244 and its canonical
`issue-1244-spike-test-finance-assistant-l2-owner-pr` requirements/design.
Every required source-mapped row must be emitted in the next run. The gate rejects missing,
unexpected or duplicate rows, invalid outcome tokens or revisions, fixture mismatches,
failed mutation/guard controls, and preflight/test errors.

| #1244 | Coverage and expected rubric — not fresh execution evidence |
| --- | --- |
| T1 | `listener:T1.listener_status` + `control:T1.notifier_self_only` + `telegram:T1.source_pin` / `T1.wire_input_peer_self` test owner-only delivery. Newly mandatory `listener:T1.finance_command` must prove unknown finance verb and emit **NOT-IMPLEMENTED**, not PASS. |
| T2 | `listener:T2.bob_dm` covers Bob's status, approve, and finance-looking DM. `agentapi:T2.ordinary_owner_routing` separately checks ordinary owner-only delivery. **`agentapi:T2.bob_job_owner_summary` must emit FAIL/GAP** for finance origin authorization bypass (via `expectGap`), never PASS. `T2.finance_origin_authorization` remains NOT-IMPLEMENTED. |
| T3 | `control:T3.per_user`; `agentapi:T3.account_foreign_*`, `T3.job_foreign_conversation`; missing finance source/consent remains NOT-IMPLEMENTED. |
| T4 | `listener:T4.group_chat`, `T4.channel`, `T4.forwarded`, `T4.saved_peer`, plus spoofed sender validation. |
| T5 | `listener:T5.1.push_then_history`, `T5.3.cursor_monotonic`, `control:T5.2.random_id`. |
| T6 | `listener:T6.out_false_push` and `T6.reconnect_replay`; actual `getDifference` integration remains CANNOT-OBSERVE. |
| T7 | `policy:T7.1`, `T7.2`; `agentapi:T7.3.with_job_id` / `omit_job_id`. Revision-zero and omitted-job vulnerabilities must stay FAIL/GAP while reproduced. |
| T8 | Policy kill/mode-off and control kill, queued-delivery mode/off, reply-kill and revocation checks. Missing delivery fences stay FAIL/GAP or CANNOT-OBSERVE as appropriate. |
| T9 | Observe-mode reply behavior, guarded allowlist, absent finance tier (NOT-IMPLEMENTED), executor peer-send boundary (CANNOT-OBSERVE). |
| T10 | Deny codes, durable action/audit, redaction via production slog handler with **nonzero** synthetic slog bytes, uninstrumented traces (CANNOT-OBSERVE). Durable plaintext intent / missing deny fields remain FAIL/GAP. |
| M1–M4 | Independent harness-only mutation controls in listener, control, and agentapi; all must detect their injected leaks (not silently PASS). |
| OFFLINE | All five packages must pass `OFFLINE.default_paths`; **whole-process isolation is not established** and retains CANNOT-OBSERVE. |

The crosswalk is encoded in both the manifest comments and
`TestGateCanonicalCrosswalk`, which validates 64 mandatory entries plus
critical T1–T10 / M1–M4 anchors. The remaining acceptance distinction is
**run-level evidence**, not an unchecked source mapping.

## Required validation before acceptance

Execute a **fresh**, SHA-pinned, clean-tree
`scripts/l2finance/run.sh` after a separate `go mod download` preflight. It must run:

1. Two independent `go test -json -tags l2finance -race -count=1 -run L2Finance` runs over the
   five application packages, comparing sorted `(package,id,outcome,fixture_id,rev)` tuples.
2. `go vet -tags l2finance` over the five packages and aggregator.
3. `go test -tags l2finance -count=1 -run '^TestGate' ./internal/l2finance/gate/`.
4. The untagged `go test -race -count=1 ./...` comparison.
5. The `TestL2FinanceGate` aggregator for both tagged streams and the regression
   `bash scripts/l2finance/test-failclosed.sh` against stale PASS/tuple artifacts.
6. Publication of the exact, full **64-row** outcome matrix and exit codes, or
   an `INVALID / BLOCKED` sentinel with nonzero exit on any incomplete step.

During test execution, dependencies must be cached and
`GOPROXY=off GOSUMDB=off GOFLAGS=-mod=readonly`; integration credentials
are stripped. These guards are **not** a whole-process egress firewall.
The `.github/workflows/l2finance-gate.yml` manual evidence job is
`workflow_dispatch` only and is *not* part of required `build.yml` CI; this
continuous tagged-regression coverage gap remains open.

## Historical evidence, not current outcome

The pre-AMEND 62-row report is preserved in the Git history at
[`mctl-telegram@6731937`](https://github.com/mctlhq/mctl-telegram/blob/673193767baa740143bb07893fe9ef149fc849be/docs/reports/finance-assistant-l2-results.md),
derived from tested source `370efd01a8841f909217d06befdfb75932530b3d`.
It reported 43 PASS, 8 FAIL/GAP, 5 NOT-IMPLEMENTED, 6 CANNOT-OBSERVE;
**those historical numbers and the old T2 PASS classification are not valid
for the amended 64-case rubric**. No new counts are asserted here.

Previously observed blocking areas include revision-zero/omitted-job fencing,
queued mode-off/kill/revocation gaps, durable DenyCode, plaintext intent,
and absent finance-specific consent/tier. These are *not* fixed by this
test-only PR; follow-up product/security changes require separate approval.

No merge, runtime implementation, deployment or Finance Assistant pilot
is authorized by this report.
