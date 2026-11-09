FINANCE_SECURITY_GATE=BLOCKED

# Finance Assistant L2: consolidated hermetic full-suite evidence (slice D, #1251)

Application-security evidence only. `harness_status=COMPLETE` means the harness ran and
matched its manifest; it is not a security pass. Outcome: `COMPLETE_WITH_GAPS_BLOCKED`.
mctlhq/.github#325 stays `RESEARCH_ONLY_DEFER`; no pilot is authorised and no gap is fixed here.

- Tested source revision: `370efd01a8841f909217d06befdfb75932530b3d` (the report itself is added in the next commit; no tested code differs)
- Go: `go1.26.10 linux/amd64`
- Commands (offline: `GOPROXY=off GOSUMDB=off GOFLAGS=-mod=readonly`, credentials unset):
  - `go test -json -tags l2finance -race -count=1 -run L2Finance ./internal/agent/policy/ ./internal/agent/listener/ ./internal/agent/control/ ./internal/agentapi/ ./internal/telegram/` (run twice)
  - `L2FINANCE_RESULTS_JSON=<stream> go test -tags l2finance -run TestL2FinanceGate ./internal/l2finance/gate/`
  - `scripts/l2finance/run.sh [outdir]` wraps these, plus tagged `go vet` and the untagged `go test -race ./...`.
- Tagged runs 1 and 2: exit 0; sorted `(package,id,outcome,fixture_id,rev)` tuples identical (62 rows).
- `go vet -tags l2finance` on the five packages and the gate: exit 0.
- Untagged `go test -race ./...`: NOT completed in the implementation sandbox. The module cache there
  lacks some dependencies of `internal/web` and `internal/oauth/cimd` and the suite exceeded the
  time bound, so the full `run.sh` stayed on its BLOCKED sentinel (exit 1) as designed. Run
  `go mod download` and `scripts/l2finance/run.sh` on a networked machine or via the manual workflow
  to record it. The per-package untagged results observed (control, executor, listener, policy) were ok.
- golangci-lint: not configured (no `.golangci*` file, not in build.yml).

## Limitations and open items

- Offline: the guards cover `net.DefaultResolver` and `http.DefaultTransport` only. Every one of the
  five packages emits `OFFLINE.default_paths`; `OFFLINE.whole_process` stays `CANNOT-OBSERVE`. The
  suite is not claimed to be fully isolated.
- The manifest was generated from the current emitters. The line-by-line crosswalk to the #1244
  T1-T10 / M1-M4 subcases was NOT independently reviewed (the #1244 source was not available to the
  implementer), so required-but-unimplemented emitters are not yet listed as `MISSING`. This must be
  done by review before the harness result is treated as complete coverage.
- `fixture_id` is the stable synthetic `L2SYNTH-<id>` derived by each package's `l2Record`; it
  proves stability across runs, not independent fixture design.
- T10 split: `T10.redaction_text` now checks durable sources only; the new `T10.redaction_slog`
  sends a synthetic marker through the production redacting handler and is PASS only with
  `slog_bytes>0`, otherwise CANNOT-OBSERVE. The slice-C `T10.redaction_text` PASS had
  `slog_bytes=0`; the plaintext-intent FAIL/GAP (`T10.intent_channel`) is unchanged. M4 is now emitted
  as `PASS` with `detected` in evidence (was `PASS (detected)`).
- Policy now requires `L2FINANCE_SOURCE_REV` (exit 2 without it), replacing the hardcoded `248db4f`.
- Continuous CI gap: `build.yml` does not run the `l2finance` tag. The manual
  `.github/workflows/l2finance-gate.yml` is evidence only, not a required check. Governed follow-up
  only after owner acceptance.
- Planned follow-up fix titles (not filed, not implemented): T7.2 "Policy: treat InstallRevision=0 as
  fence-required"; T7.3.omit_job_id "agentapi: require job_id for owner actions"; T8.* "Honour kill, mode
  off and revocation after queueing and on reply"; T10.denycode_persisted "Persist deny codes durably";
  T10.intent_channel "Do not persist plaintext intent"; finance tier and consent (NOT-IMPLEMENTED rows).
- Earlier slice reports (A partial content replaced here, B and C left in place):
  `finance-assistant-l2-slice-b.md`, `finance-assistant-l2-slice-c.md`.


- harness_status: `COMPLETE`
- issue_outcome: `COMPLETE_WITH_GAPS_BLOCKED`
- source revision: `370efd01a8841f909217d06befdfb75932530b3d`
- counts: PASS=43, FAIL/GAP=8, NOT-IMPLEMENTED=5, CANNOT-OBSERVE=6

## Aggregator: Results

| Canonical ID | Outcome | Fixture | Evidence |
| --- | --- | --- | --- |
| `agentapi:M4` | PASS | `L2SYNTH-M4` | detected: unredacted JSON handler leak reported by the same helper used by T10 |
| `agentapi:M4.redacted_twin` | PASS | `L2SYNTH-M4.redacted_twin` | production redacting handler returns nil from the same helper |
| `agentapi:OFFLINE.default_paths` | PASS | `L2SYNTH-OFFLINE.default_paths` | dial_refused=true lookup_refused=true loopback_ok=true |
| `agentapi:OFFLINE.whole_process` | CANNOT-OBSERVE | `L2SYNTH-OFFLINE.whole_process` | guards cover net.DefaultResolver and http.DefaultTransport only; not a whole-process egress firewall |
| `agentapi:T10.action_rows` | PASS | `L2SYNTH-T10.action_rows` | rows=3 denied=1 malformed=0 |
| `agentapi:T10.denycode_persisted` | FAIL/GAP | `L2SYNTH-T10.denycode_persisted` | code=install_changed metric_count=1 durable_in_audit_or_actions=false deny_code_columns=0 |
| `agentapi:T10.intent_channel` | FAIL/GAP | `L2SYNTH-T10.intent_channel` | plaintext_intent_in_agent_actions=true marker_check=marker found in agent_actions |
| `agentapi:T10.redaction_slog` | PASS | `L2SYNTH-T10.redaction_slog` | slog_bytes=104 marker redacted |
| `agentapi:T10.redaction_text` | PASS | `L2SYNTH-T10.redaction_text` | durable_sources_only err=<nil> |
| `agentapi:T10.traces` | CANNOT-OBSERVE | `L2SYNTH-T10.traces` | spans=0 agentapi_files_importing_otel=0 no exercised instrumentation, empty provider is not a PASS |
| `agentapi:T2.bob_job_owner_summary` | PASS | `L2SYNTH-T2.bob_job_owner_summary` | http=200 actions=1 status=[executed/allow] notif_rows=1 notif_owner_is_alice=true kind=summary carol_rows=0 peer_sink=0 scope=ordinary_owner_routing |
| `agentapi:T2.finance_origin_authorization` | NOT-IMPLEMENTED | `L2SYNTH-T2.finance_origin_authorization` | no finance-source label, source consent or finance policy gate exists; finance-looking text treated as ordinary text; no PASS or FAIL inferred |
| `agentapi:T3.account_foreign_context` | PASS | `L2SYNTH-T3.account_foreign_context` | http=404 |
| `agentapi:T3.account_foreign_conversation` | PASS | `L2SYNTH-T3.account_foreign_conversation` | notify=404 propose=404 rows_none=true |
| `agentapi:T3.account_foreign_job` | PASS | `L2SYNTH-T3.account_foreign_job` | http=400 rows_none=true |
| `agentapi:T3.finance_source_consent` | NOT-IMPLEMENTED | `L2SYNTH-T3.finance_source_consent` | http=400 decodeStrict rejects unknown field; no consent/source concept; no store mocked |
| `agentapi:T3.job_foreign_conversation` | PASS | `L2SYNTH-T3.job_foreign_conversation` | notify=403 propose=403 context=403 alice_denied_audits=3 rows_none=true |
| `agentapi:T7.3.omit_job_id` | FAIL/GAP | `L2SYNTH-T7.3.omit_job_id` | http=200 actions=1 notif_rows=1 status=executed decision=allow persisted_job_id=0 persisted_install_revision=2 claimed_job_id=1 |
| `agentapi:T7.3.with_job_id` | PASS | `L2SYNTH-T7.3.with_job_id` | http=200 decision=deny reasons=["the assistant install changed since this work began"] notif_rows=0 |
| `agentapi:T9.executor_peer_send` | CANNOT-OBSERVE | `L2SYNTH-T9.executor_peer_send` | delivery after an approved action happens in the executor outside this slice; an inert sink on an API without a sender proves nothing |
| `agentapi:T9.finance_tier` | NOT-IMPLEMENTED | `L2SYNTH-T9.finance_tier` | http=400 unknown field tier rejected; no finance tier exists |
| `agentapi:T9.guarded_allowlisted` | PASS | `L2SYNTH-T9.guarded_allowlisted` | http=200 decision=allow status=approved persisted=[approved/allow] api_peer_sink=0; approved is an API policy state, not evidence of delivery |
| `agentapi:T9.observe_no_peer_send` | PASS | `L2SYNTH-T9.observe_no_peer_send` | http=200 decision=require_approval status=pending_approval persisted=[pending_approval/require_approval] api_peer_sink=0 (API has no sender; not an executor claim) |
| `control:M2` | PASS | `L2SYNTH-M2` | detected |
| `control:M3` | PASS | `L2SYNTH-M3` | detected |
| `control:OFFLINE.default_paths` | PASS | `L2SYNTH-OFFLINE.default_paths` | TEST-NET-1 dial and external DNS refused via http.DefaultTransport and net.DefaultResolver; loopback allowed |
| `control:T1.notifier_self_only` | PASS | `L2SYNTH-T1.notifier_self_only` | one random_id send to owner; peer sink empty |
| `control:T3.finance_source` | NOT-IMPLEMENTED | `L2SYNTH-T3.finance_source` | no finance-source field on owner notifications |
| `control:T3.per_user` | PASS | `L2SYNTH-T3.per_user` | each text delivered only under its own user id |
| `control:T5.2.random_id` | PASS | `L2SYNTH-T5.2.random_id` | retry reused the persisted random_id; duplicate treated as delivered; row sent |
| `control:T8.kill` | PASS | `L2SYNTH-T8.kill` | 0 sends and row pending under kill; delivered once after clear |
| `control:T8.mode_off_after_queue` | FAIL/GAP | `L2SYNTH-T8.mode_off_after_queue` | DeliverPending sent after mode=off; no delivery-time mode check |
| `control:T8.mode_off_before_queue.delivery` | FAIL/GAP | `L2SYNTH-T8.mode_off_before_queue.delivery` | row inserted directly while mode=off was delivered; queue-time refusal is the policy package's row and is not claimed here |
| `control:T8.reply_kill` | FAIL/GAP | `L2SYNTH-T8.reply_kill` | Reply sent while GlobalKill is true; Reply is not gated by the kill switch |
| `control:T8.revoked_after_queue` | FAIL/GAP | `L2SYNTH-T8.revoked_after_queue` | Notifier called the sender after session revocation; no Notifier-level fence |
| `control:T8.revoked_pool_fence` | CANNOT-OBSERVE | `L2SYNTH-T8.revoked_pool_fence` | production fence is ClientPool.Borrow -> Store.CheckSessionValid beneath the SelfSender; a fake sender bypasses it |
| `listener:M1` | PASS | `L2SYNTH-M1` | detected |
| `listener:OFFLINE.default_paths` | PASS | `L2SYNTH-OFFLINE.default_paths` | TEST-NET-1 dial and external DNS refused via http.DefaultTransport and net.DefaultResolver; loopback allowed |
| `listener:OFFLINE.whole_process` | CANNOT-OBSERVE | `L2SYNTH-OFFLINE.whole_process` | custom net.Dialer, custom transports and gotd internals are not intercepted; no gotd client is constructed |
| `listener:T1.listener_status` | PASS | `L2SYNTH-T1.listener_status` | one owner reply, one saved_command event, peer sink empty |
| `listener:T2.bob_dm` | PASS | `L2SYNTH-T2.bob_dm` | not routed; no saved_command event; private_message events=1 |
| `listener:T2.spoof_from` | PASS | `L2SYNTH-T2.spoof_from` | self peer with foreign from_id not routed |
| `listener:T4.channel` | PASS | `L2SYNTH-T4.channel` | Out true and false not routed, no event |
| `listener:T4.forwarded` | PASS | `L2SYNTH-T4.forwarded` | forwarded self message not routed |
| `listener:T4.group_chat` | PASS | `L2SYNTH-T4.group_chat` | Out true and false not routed, no event |
| `listener:T4.saved_peer` | PASS | `L2SYNTH-T4.saved_peer` | foreign saved_peer_id not routed |
| `listener:T5.1.push_then_history` | PASS | `L2SYNTH-T5.1.push_then_history` | 1 reply total; cursor=20 |
| `listener:T5.3.cursor_monotonic` | PASS | `L2SYNTH-T5.3.cursor_monotonic` | cursor 21 then 23; 22 and 23 routed once each |
| `listener:T6.gap` | CANNOT-OBSERVE | `L2SYNTH-T6.gap` | updates.Manager getDifference needs a fake MTProto server; not built in this slice |
| `listener:T6.out_false_push` | PASS | `L2SYNTH-T6.out_false_push` | Out=false self push routed once |
| `listener:T6.reconnect_replay` | PASS | `L2SYNTH-T6.reconnect_replay` | replay by push and history on a second Listener produced no second reply |
| `policy:OFFLINE.default_paths` | PASS | `L2SYNTH-OFFLINE.default_paths` | TEST-NET-1 dial and external DNS refused via http.DefaultTransport and net.DefaultResolver; loopback allowed |
| `policy:T10.denycode` | PASS | `L2SYNTH-T10.denycode` | every deny carries a DenyCode and reasons |
| `policy:T7.1` | PASS | `L2SYNTH-T7.1` | stale revision -> DenyInstallChanged |
| `policy:T7.2` | FAIL/GAP | `L2SYNTH-T7.2` | InstallRevision=0 owner summary evaluated allow (policy.go install fence skipped) |
| `policy:T8.kill` | PASS | `L2SYNTH-T8.kill` | GlobalKill -> DenyGlobalKill |
| `policy:T8.mode_off_before_queue` | PASS | `L2SYNTH-T8.mode_off_before_queue` | mode off -> DenyModeOff |
| `policy:T9.finance_tier` | NOT-IMPLEMENTED | `L2SYNTH-T9.finance_tier` | no finance ActionType or never tier in policy |
| `policy:T9.reply_observe` | PASS | `L2SYNTH-T9.reply_observe` | decision=require_approval code=unknown |
| `telegram:OFFLINE.default_paths` | PASS | `L2SYNTH-OFFLINE.default_paths` | TEST-NET-1 dial and external DNS refused via http.DefaultTransport and net.DefaultResolver; loopback allowed |
| `telegram:T1.source_pin` | PASS | `L2SYNTH-T1.source_pin` | source evidence only (not wire): SendToSelf and SendToSelfWithRandomID pass &tg.InputPeerSelf{} in sendself.go |
| `telegram:T1.wire_input_peer_self` | PASS | `L2SYNTH-T1.wire_input_peer_self` | captured_peer=*tg.InputPeerSelf resolver_dials=0 call_err=<nil> |

## Aggregator: Gap IDs (FAIL/GAP)

- `agentapi:T10.denycode_persisted`
- `agentapi:T10.intent_channel`
- `agentapi:T7.3.omit_job_id`
- `control:T8.mode_off_after_queue`
- `control:T8.mode_off_before_queue.delivery`
- `control:T8.reply_kill`
- `control:T8.revoked_after_queue`
- `policy:T7.2`
