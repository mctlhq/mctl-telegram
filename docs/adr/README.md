# Architecture decision records

Each record states one decision that shapes mctl-telegram, the context that
forced it, and what it costs. They were written in October 2026, after the
fact, for decisions the code already implements; each one links the code
that carries it and the release that introduced it where the changelog
records one. The code is authoritative: if a record and the code disagree,
the record is wrong and should be fixed.

| # | Decision | Status |
|---|---|---|
| [0001](0001-per-user-session-keys.md) | Telegram sessions are sealed with per-user keys, and the hosted mode is stated as not zero-knowledge | Accepted |
| [0002](0002-send-gate.md) | Every write passes one gate with three independent conditions; new accounts start read-only | Accepted |
| [0003](0003-hash-chained-audit-log.md) | The audit log is a per-user hash chain, and logs are redacted by a handler rather than by convention | Accepted |
| [0004](0004-own-authorization-server.md) | The service is its own OAuth 2.1 authorization server, brokering Telegram's OpenID Connect sign-in | Accepted |
| [0005](0005-session-pool-and-sticky-routing.md) | MTProto sessions live in a per-pod pool; the service runs as one replica, with sticky routing ready for more | Accepted |
| [0006](0006-local-bridge-relay.md) | Local Bridge keeps the session on the user's machine and turns the server into a relay | Accepted (beta) |
| [0007](0007-tool-surface-as-contract.md) | The tool surface is a reviewed contract: a committed snapshot and a release gate | Accepted |
| [0008](0008-managed-runtime.md) | Managed runtime: one pooled platform worker per environment, OpenAI-compatible models through the AI gateway, consent and hard budget caps | Proposed |

## Format

`Context` is what was true when the decision was made. `Decision` is what
the code does. `Consequences` lists the costs as well as the gains.
`Alternatives` names what was rejected and why. A record is superseded, not
edited, when the decision changes.
