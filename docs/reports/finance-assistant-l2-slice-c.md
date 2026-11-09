# Finance Assistant L2 slice C: agent API isolation, revision binding and redaction evidence

FINANCE_SECURITY_GATE=BLOCKED

Slice C only; not L2 completion; no aggregation across slices.

Harness status (every case executed, tagged binary exits 0) is separate from
security status: a harness PASS says the case ran, not that the finance
assistant is secure. Rows classified FAIL/GAP are reproduced gaps that this
test-only slice does not repair.

- Pinned source revision: `5fb1de8952e12e975df5366ade45f8aa95aa0220`
- Go version: go1.26.10 linux/amd64
- Approval reference: this proposal's own reviewed digest and owner approval
  (`issue-1255-test-finance-l2-c-recovery-canonical-dev`). The #1244 and slice-B grants do not apply.
- Files: `internal/agentapi/l2finance_harness_test.go`, `internal/agentapi/l2finance_api_test.go`,
  `internal/telegram/l2finance_sendself_test.go` (all behind `//go:build l2finance`).

## Commands

```
L2FINANCE_SOURCE_REV=$(git rev-parse HEAD) go test -tags l2finance -race -count=1 -run L2Finance -v ./internal/agentapi/ ./internal/telegram/ | grep L2RESULT
go vet -tags l2finance ./internal/agentapi/ ./internal/telegram/
go test -race -count=1 ./internal/agentapi/ ./internal/telegram/   # untagged, unchanged
```

## Results

| id | outcome | observed evidence |
| --- | --- | --- |
| T2.bob_job_owner_summary | PASS | Ordinary owner routing only: 200, one executed action, one `owner_notifications` row owned by Alice, no Carol rows, peer sink 0. |
| T2.finance_origin_authorization | NOT-IMPLEMENTED | No finance-source label, consent or finance policy gate exists. Nothing inferred from finance-looking text. |
| T3.account_foreign_conversation | PASS | notify 404, propose 404, no action or notification rows for either user. |
| T3.account_foreign_context | PASS | 404. |
| T3.job_foreign_conversation | PASS | notify/propose/context all 403, denied `audit_logs` rows under Alice, no action or notification rows. |
| T3.account_foreign_job | PASS | 400, no rows under either user. |
| T3.finance_source_consent | NOT-IMPLEMENTED | 400 from `decodeStrict` on unknown field `finance_source`; no consent store, none mocked. |
| T7.3.with_job_id | PASS | Control: denied with `ReasonInstallChanged`, no notification. |
| T7.3.omit_job_id | FAIL/GAP | Job-bound summary without `job_id` after the revision bump: executed, notification queued, persisted `job_id=0`, `install_revision=2` (current), so the fence is skipped. |
| T9.observe_no_peer_send | PASS | `require_approval` / `pending_approval`; API peer sink 0 (API has no sender; not an executor claim). |
| T9.guarded_allowlisted | PASS | `allow` / `approved`, peer sink 0. `approved` is an API policy state, not evidence of delivery. |
| T9.executor_peer_send | CANNOT-OBSERVE | Delivery happens in the executor, outside this slice. No full no-peer-send claim. |
| T9.finance_tier | NOT-IMPLEMENTED | 400 for unknown field `tier`; no finance tier exists. |
| T10.action_rows | PASS | Every action row has non-empty status and decision; denied rows carry reasons. |
| T10.denycode_persisted | FAIL/GAP | Code `install_changed` is visible in `mctl_agent_policy_denials_total` only; absent from `audit_logs` and `agent_actions`; no deny-code column. |
| T10.redaction_text | PASS | Marker absent from redacting slog capture and from `audit_logs`, `agent_actions` and `owner_notifications` plaintext columns. The handlers emitted 0 slog bytes in this scenario, so the slog half is weak evidence. |
| T10.intent_channel | FAIL/GAP | Marker placed in the agent-supplied `intent` is stored in plaintext in `agent_actions.intent`. |
| T10.traces | CANNOT-OBSERVE | `spans=0`; no agentapi non-test file imports OpenTelemetry. An empty provider is not a redaction PASS. |
| M4 | PASS (detected) | Unredacted JSON handler leak reported by the same helper used by T10. |
| M4.redacted_twin | PASS | Production redacting handler returns nil from the same helper. |
| OFFLINE.default_paths | PASS | TEST-NET-1 dial and external lookup refused with `errL2ExternalDial`; loopback server reachable. |
| OFFLINE.whole_process | CANNOT-OBSERVE | Guards cover `net.DefaultResolver` and `http.DefaultTransport` only. |
| T1.wire_input_peer_self | PASS | Terminating middleware captured `*tg.InputPeerSelf`; resolver dial counter 0; `Run` never called. |
| T1.source_pin | PASS | Source evidence only, not wire: `SendToSelf` and `SendToSelfWithRandomID` pass `&tg.InputPeerSelf{}`. |

Counts (24 rows): PASS 15 (including M4 PASS (detected)), FAIL/GAP 3, NOT-IMPLEMENTED 3, CANNOT-OBSERVE 3.

T7.1 (PASS) and T7.2 (FAIL/GAP, `InstallRevision=0` skips the fence) are cited unchanged from
`finance-assistant-l2-results.md` and were not re-run.

## Limitations and layer boundary

- Identities are injected with `auth.With`; job-token minting and the auth middleware are not exercised.
- The offline guard covers default resolver and transport only.
- Separate ordinary owner routing (T2) from finance-source authorization; API approval (T9) from executor
  delivery; metric-only deny code from durable audit; zero spans from trace-redaction evidence.

## Open questions

- Whether the executor sends for `approved` finance-looking replies (slice D / executor harness).
- Whether `job_id` should be derived from a job-bound identity when omitted (T7.3.omit_job_id).
- Whether the deny code and intent text should be persisted/redacted (T10.denycode_persisted, T10.intent_channel).
