# Finance assistant L2 results (partial, #1244)

harness_status: PASS (policy package only)
FINANCE_SECURITY_GATE=BLOCKED

The gate stays BLOCKED: T7.2 is FAIL/GAP, T9 finance tier is NOT-IMPLEMENTED,
and the listener, control, agentapi and telegram cases are not yet written.
Parent #325 stays RESEARCH_ONLY_DEFER; #1240 verdict unchanged; no pilot is allowed.

Command:
`go test -tags l2finance -count=1 -run L2Finance -v ./internal/agent/policy/`

| id | outcome |
| --- | --- |
| T7.1 | PASS |
| T7.2 | FAIL/GAP (InstallRevision=0 skips the fence) |
| T8.kill, T8.mode_off_before_queue | PASS |
| T9.reply_observe | PASS |
| T9.finance_tier | NOT-IMPLEMENTED |
| T10.denycode | PASS |

Not done: tasks 4, 5, 7, 8, 8a, 9, 10a, mutations M1-M4.
