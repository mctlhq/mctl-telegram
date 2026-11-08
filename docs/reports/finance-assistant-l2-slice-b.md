# Finance Assistant L2 slice B: Saved Messages listener and owner notifier evidence

Slice B only; not L2 completion; no aggregation across slices.

FINANCE_SECURITY_GATE=BLOCKED
Parent verdict mctlhq/.github#325: RESEARCH_ONLY_DEFER.
harness_status=EXECUTED (all cases ran; reproduced FAIL/GAP rows are harness successes, not gate passes).

Issues: mctlhq/mctl-telegram#1249 (this slice), #1244 (parent question), #1247 (policy-package slice, merged; its report `finance-assistant-l2-results.md` is not touched here).

## Provenance

- Source base (`git rev-parse HEAD` before the slice files were added): `3107baf5a4b0608fb33e905b7529dbd45a7af30f` (merge of #1247).
- Proposal approval reference: `aar_9020e7a758204906b74b976033994fe6` (distinct from the #1244 grant `aar_5dc0456105f442829583adaa101516c6`), digest binding `reviewed`, content digest `sha256:ec70b2e45caa1f082ffdc7eafe86bad553b39f18e97fbd8e71bc58d3022bb8f7`.
- Go: go1.26.10 linux/amd64.
- Every `L2RESULT` line carries `rev=<L2FINANCE_SOURCE_REV>`; the run aborts before any result if the variable is not 40-hex.

## Commands

```
L2FINANCE_SOURCE_REV=$(git rev-parse HEAD) go test -tags l2finance -race -count=1 -run L2Finance -v ./internal/agent/listener/ ./internal/agent/control/ | grep L2RESULT
go vet -tags l2finance ./internal/agent/listener/ ./internal/agent/control/
go test -count=1 ./internal/agent/...   # unchanged and green; tagged files excluded
```

## Results (all rows rev=3107baf5a4b0608fb33e905b7529dbd45a7af30f)

| id | outcome | note |
| --- | --- | --- |
| T1.listener_status | PASS | real Router via dispatcher: one owner reply with `Mode: observe`, one saved_command event |
| T1.notifier_self_only | PASS | one `SendToSelfWithRandomID` to the owner; peer sink empty |
| T2.bob_dm | PASS | not routed; one private_message event (ingest path), no saved_command |
| T2.spoof_from | PASS | self peer with foreign from_id not routed |
| T3.per_user | PASS | Alice and Carol texts only under their own user ids |
| T3.finance_source | NOT-IMPLEMENTED | no finance-source field on owner notifications |
| T4.group_chat | PASS | Out true/false not routed, no event |
| T4.channel | PASS | Out true/false not routed, no event |
| T4.forwarded | PASS | not routed |
| T4.saved_peer | PASS | foreign saved_peer_id not routed |
| T5.1.push_then_history | PASS | one reply; cursor 20 |
| T5.2.random_id | PASS | retry reused persisted random_id; duplicate treated as delivered; row sent |
| T5.3.cursor_monotonic | PASS | cursor 21 after failed route, then 23; 22 and 23 routed once each |
| T6.out_false_push | PASS | Out=false self push routed once |
| T6.reconnect_replay | PASS | second Listener on same store: no second reply, cursor 40 |
| T6.gap | CANNOT-OBSERVE | updates.Manager getDifference needs a fake MTProto server |
| T8.kill | PASS | 0 sends and row pending under kill; delivered once after clear |
| T8.mode_off_after_queue | FAIL/GAP | DeliverPending sends after mode=off; no delivery-time mode check |
| T8.mode_off_before_queue.delivery | FAIL/GAP | row inserted while mode=off is delivered; queue-time refusal is the policy package's row |
| T8.revoked_after_queue | FAIL/GAP | Notifier sends after `RevokeActiveSession`; no Notifier-level fence |
| T8.revoked_pool_fence | CANNOT-OBSERVE | production fence (`ClientPool.Borrow` -> `CheckSessionValid`) lies beneath the fake sender |
| T8.reply_kill | FAIL/GAP | `Notifier.Reply` is not gated by `GlobalKill` (see open question below) |
| M1 | PASS (detected) | classifier bypass routes Bob's command; `l2CheckNotRouted` flags it |
| M2 | PASS (detected) | kill hook omitted; `l2CheckNoSend` flags the send |
| M3 | PASS (detected) | leaky sender; `l2CheckNoPeerSink` flags it |
| OFFLINE.default_paths | PASS | TEST-NET-1 dial and external DNS refused; loopback allowed |
| OFFLINE.whole_process | CANNOT-OBSERVE | see limitations |

Counts: 18 PASS (incl. 3 negative controls detected, 1 offline self-test), 4 FAIL/GAP, 1 NOT-IMPLEMENTED, 3 CANNOT-OBSERVE.
Observed outcomes matched the expected column of the design for every row.

## Offline-guard limitations

The harness replaces `net.DefaultResolver` and the `DialContext` of `http.DefaultTransport`. That guards only those default paths. It does not intercept a custom `net.Dialer`, a custom transport or gotd internals, so no whole-process no-egress guarantee is claimed (`OFFLINE.whole_process` is CANNOT-OBSERVE). No gotd client is constructed; the listener receives `tg.Updates` values directly, history comes from `fakeSavedHistoryAPI`, and the sender is a fake. All identities are synthetic (Alice, Bob, Carol; `l2BobTG=600`).

## Open questions carried from the proposal

- Is `Notifier.Reply` deliberately exempt from `GlobalKill`?
- Does the rubric accept the pool-layer revocation fence as sufficient for T8.revoked_*?

No runtime fix was made. Reproduced gaps fail their test via `expectGap` once they stop reproducing, which forces a reviewed rubric update.
