FINANCE_SECURITY_GATE=BLOCKED

# Finance Assistant L2 — verified hermetic full-suite evidence (slice D, #1251)

## Provenance and limitations

This report transcribes the exact 64 canonical ID / outcome / fixture / evidence rows from the completed, read-only, SHA-pinned manual GitHub Actions artifact. This is **verified evidence for the source revision below**, not a claim that subsequent commits have been retested. **After updating the runner and merging current main into PR #1257, a fresh workflow_dispatch on the new PR HEAD is mandatory** before acceptance or merge of #1257.

- Source / tested HEAD: `b9ba5ebfb36a6ff4907786fbb341342f42f1fac7`
- Manual workflow: [l2finance-gate run #42620545631](https://github.com/mctlhq/mctl-telegram/actions/runs/42620545631), conclusion SUCCESS, 2026-11-09.
- [Immutable run artifact #13676901988](https://github.com/mctlhq/mctl-telegram/actions/runs/42620545631/artifacts/13676901988): `summary.md`, `status.md`, JSON event streams, both tuple sets, tagged gate outputs, vet and untagged test logs.
- Artifact ZIP SHA-256 (as reported by GitHub Actions): `0c8481600ece27506021bf68aae00597fd68e4dac0e773264c061156a91682d5`.
- Go: `go version go1.26.10 linux/amd64`.
- `harness_status=COMPLETE`; `issue_outcome=COMPLETE_WITH_GAPS_BLOCKED`.
- `FINANCE_SECURITY_GATE=BLOCKED` — a green workflow verifies the *harness*, not finance security authorization.
- Rows = **64**: PASS **43**, FAIL/GAP **9**, NOT-IMPLEMENTED **6**, CANNOT-OBSERVE **6**.

## Commands and run-level gates

- Dependency preflight: `go mod download`, exit 0 (the only network-enabled step).
- Fail-closed reused-output regression: `bash scripts/l2finance/test-failclosed.sh`, PASS.
- Two separate `go test -json -tags l2finance -race -count=1 -run L2Finance` runs across policy, listener, control, agentapi and telegram, exits **0 / 0**.
- `go vet -tags l2finance` over those packages and the gate, exit **0**.
- `go test -tags l2finance -count=1 -run '^TestGate' ./internal/l2finance/gate/`, exit **0**.
- Two `TestL2FinanceGate` aggregation runs, both PASS; reproducibility of full `(package,id,outcome,fixture_id,rev)` tuples: **identical**, 64 rows, no duplicates.
- `go test -race -count=1 ./...` untagged comparison, exit **0**.
- `golangci-lint`: not configured in this repository.
- After dependency preflight, runner uses `GOPROXY=off GOSUMDB=off GOFLAGS=-mod=readonly`, strips integration credentials, and checks the five package default dial/lookup paths.

**Scope of offline evidence:** guards cover `net.DefaultResolver` and `http.DefaultTransport` and known tested paths. A whole-process egress sandbox/firewall has **not** been demonstrated, so `OFFLINE.whole_process` remains CANNOT-OBSERVE.

## Full 64-row evidence matrix — as observed on tested HEAD

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
| `agentapi:T2.bob_job_owner_summary` | FAIL/GAP | `L2SYNTH-T2.bob_job_owner_summary` | finance-looking text from Bob-conversation job allowed to queue owner summary without a finance owner-invocation grant |
| `agentapi:T2.finance_origin_authorization` | NOT-IMPLEMENTED | `L2SYNTH-T2.finance_origin_authorization` | no finance-source label, source consent or finance policy gate exists; finance-looking text treated as ordinary text; no PASS or FAIL inferred |
| `agentapi:T2.ordinary_owner_routing` | PASS | `L2SYNTH-T2.ordinary_owner_routing` | http=200 actions=1 status=[executed/allow] notif_rows=1 notif_owner_is_alice=true kind=summary carol_rows=0 peer_sink=0 |
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
| `listener:T1.finance_command` | NOT-IMPLEMENTED | `L2SYNTH-T1.finance_command` | owner-only unknownCommandReply observed; no finance command or peer send |
| `listener:T1.listener_status` | PASS | `L2SYNTH-T1.listener_status` | one owner reply, one saved_command event, peer sink empty |
| `listener:T2.bob_dm` | PASS | `L2SYNTH-T2.bob_dm` | status, approve and finance-looking Bob DM not routed; zero owner/peer sends; private_message events=3 |
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

## Confirmed security gaps requiring separately approved fixes

| Canonical gap | Bounded follow-up work (not implemented by #1257) |
| --- | --- |
| `agentapi:T10.denycode_persisted` | Persist DenyCode in durable audit/action records |
| `agentapi:T10.intent_channel` | Prevent plaintext finance intent persistence in the action channel |
| `agentapi:T2.bob_job_owner_summary` | Add finance-specific source/owner-invocation authorization before owner-summary jobs |
| `agentapi:T7.3.omit_job_id` | Enforce required job binding when applying approved actions |
| `control:T8.mode_off_after_queue` | Recheck mode=off at notification delivery time |
| `control:T8.mode_off_before_queue.delivery` | Enforce mode=off even on directly inserted queued rows |
| `control:T8.reply_kill` | Apply global kill switch to Reply sends |
| `control:T8.revoked_after_queue` | Enforce session revocation fence at notifier delivery |
| `policy:T7.2` | Deny revision-zero owner summaries instead of bypassing install revision fence |

Additional blockers are the six NOT-IMPLEMENTED rows and six CANNOT-OBSERVE rows listed in the table. The mutation controls M1–M4 and all five `OFFLINE.default_paths` rows were PASS in this run.

## Governance and next acceptance gate

- This PR is **test-only**. The new runner fail-closed P3 fix and upstream `main` integration happen *after* the recorded baseline. Re-run the manual workflow at the final PR HEAD and use that exact run's summary and artifact as authoritative. Do not claim the source revision above is the updated HEAD.
- The tagged suite is **manual**, not a required part of `build.yml`. Continuous tagged-regression coverage remains a separately governed follow-up.
- Obtain updated independent Claude/Agy reviews, protected CI and owner acceptance of the report before merging this test-only PR. File bounded security-fix issues separately after acceptance.
- `FINANCE_SECURITY_GATE=BLOCKED`; mctlhq/.github#325 `RESEARCH_ONLY_DEFER` unchanged. This report does **not** approve Finance Assistant product runtime, pilot, production, real Telegram accounts, finance records or deployment.
