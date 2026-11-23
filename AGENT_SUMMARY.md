# AGENT_SUMMARY

Issue: [mctlhq/mctl-telegram#1401](https://github.com/mctlhq/mctl-telegram/issues/1401)
Branch: `fix/bounty-1401`
Commit: `3b14df0` — `docs(platforms): record the AgentsPodium Hermes Phase 0 spike as HOLD`

## Root cause

#1401 is a `GO_RESEARCH` spike, not a code defect, so "what was wrong" is a
documentation and analysis gap in three parts.

1. **The repository's record of this platform was stale and misdirected.** The
   Hermes Agent row in `docs/platforms/compatibility.md`, the client-status
   row in `internal/web/docs.html` and the bullet in
   `internal/web/platforms.html` all said sign-in comes from a per-user
   subdomain of `agentspodium.com` that "cannot be admitted as one host". The
   vendor reported on 2026-11-22 that hosted Hermes now uses a vendor-owned
   stable domain with per-pod CIMD documents and matching callbacks, which is
   exactly why #1384 was closed *not planned*. The public pages were still
   pointing users at that closed issue.
2. **No evidence artefact existed.** The issue's acceptance criterion is one
   evidence-linked matrix with an unambiguous PASS/HOLD and the outstanding
   security issues. Nothing in the repository held that.
3. **The central Gate A security question had not been answered against the
   code.** Gate A asks whether `/oauth/mcp/clients/<pod>/<server>.json` binds
   to the callback `/oauth/mcp/cb/<pod>/<server>`. The answer is in this
   repository, and it is no.

## Fix

Four files, no Go code, no configuration, no allowlist entry.

**New: `docs/reports/agentspodium-hermes-compat-spike.md`** — the Phase 0
report. Verdict **HOLD**. It separates what could be measured here (what
MCTL's own OAuth/CIMD code does, every claim carrying a `file:line`) from
what could not (anything requiring a live fetch of `agentspodium.com` or a
hosted pod), and marks the latter `not measured here` rather than leaving a
blank that reads as coverage. It carries the Gate A table, the ten-check
Gate B matrix with every row `not run`, Gate C as untested, the candidate
admission described but explicitly not proposed, the `UNKNOWN` distribution
baseline, and five findings:

- **F1 (P1), the reason for HOLD.** For a URL `client_id`, `validateClient`
  (`internal/oauth/server.go:3788`–`3798`) takes the redirect URI from the
  fetched document and, by its own comment, "never from a registration or the
  implicit-host allowlist". The document parser accepts any `https` redirect
  with a host (`internal/oauth/cimd/cimd.go:736`) and pins only `jwks_uri` to
  the `client_id` host (`:698`). So a path-scoped
  `OAUTH_CIMD_ALLOWED_HOSTS` entry binds the *document* path and cannot bind
  the callback: a document admitted for pod A may name a callback under
  another pod's path or on a third-party host.
  `internal/oauth/cimd_client_test.go:156`–`157` pins that a redirect *absent
  from* the document is refused; nothing pins or enforces the cross-host or
  cross-pod case when it is *present in* the document. The report gives the
  two ways out (a vendor guarantee about who authors `redirect_uris`, or an
  MCTL-side rule using the `AllowEntry` the resolver already carries) and
  marks the second out of scope for `GO_RESEARCH`.
- **F2 (P2).** Document TTL comes from `Cache-Control` clamped to
  `[30s, 24h]`, default 1h, so a reassigned pod or a withdrawn redirect URI
  keeps working for up to a day.
- **F3 (P2, largely mitigated).** PKCE S256 is mandatory and codes are bound
  to `client_id` and the exact `redirect_uri`, so cross-pod *redemption* is
  blocked; the residual is F1, which misdelivers the code before those
  bindings apply.
- **F4 (P2).** An admitted client with no `MCP_CLIENT_PROFILES` binding gets
  the default scope surface, so a pilot pod must be bound to a read-only
  profile in the same change.
- **F5 (no action).** Prefix boundary, path traversal and encoding, entry
  shape, `jti` replay and unregistered-pod refusal are already handled; cited
  so a reviewer can see what was checked and found sound.

**`docs/platforms/compatibility.md`** — the Hermes row now states the
vendor-reported CIMD path, that it was not fetched or verified, that the
vendor's end-to-end result is with Notion MCP rather than tg.mctl.ai, that
admission is on HOLD because a path-scoped entry binds the document and not
the callback, and it links the report and #1401. Status stays `not tested`
and the date stays `not observed`, which is what the status legend requires.

**`internal/web/docs.html`, `internal/web/platforms.html`** — the superseded
per-user-subdomain reason is dropped, the vendor claim is labelled unverified,
and the tracking link moves from closed #1384 to #1401. Both keep
`not tested`. Gate B authorises moving these pages only to an *evidenced*
status, and nothing is evidenced, so the status words are unchanged.

### What was deliberately not done

Per the issue's `GO_RESEARCH` scope: no `OAUTH_ALLOWED_IMPLICIT_HOSTS` or
`OAUTH_CIMD_ALLOWED_HOSTS` change and no candidate GitOps PR, no deployment,
no pod created, no external account signed in, no real Telegram account or
session touched, no partner link invented, and no private mail reproduced.
No Go code or configuration file was modified.

## Verification

- **`go test` could not be run: there is no Go toolchain in this
  environment** (`go` is absent from `PATH` and a filesystem search for
  `go.exe` found nothing). No Go source was changed, so `go vet` and `gofmt`
  are unaffected, but the suite is genuinely unrun here. To confirm:
  `go test ./docs/ ./internal/web/ ./internal/oauth/...`.
- The guards that touch the changed files were re-implemented in Python and
  run against the edited files:
  - `docs/compatibility_test.go` logic: the matrix parses, all 14 rows have
    exactly 6 cells, the required host set matches exactly, every status is
    one of the three legal words, and every `works` row still has an evidence
    link and an ISO date. Result: 14 rows, pass.
  - `TestUntestedClients_LabelledEverywhere` logic: every block of
    `docs.html` and `platforms.html` naming Cursor, VS Code, Windsurf,
    Notion, Rayrun, Hermes or Gemini also contains `not tested` or
    `not yet tested`. Result: 0 unlabelled.
- `grep` confirms no test pins the strings removed from the two HTML pages
  (`per-user subdomain`, `cannot be admitted as one host`), and no test pins
  `1384`.
- Every `file:line` citation in the report was read back, and three were
  corrected to the exact line before committing.
- Relative links resolve: `../reports/agentspodium-hermes-compat-spike.md`,
  `docs/local-bridge.md`, `docs/tool-descriptors.core-readonly.json` and the
  admission runbook all exist.

## Concerns for a reviewer

1. **F1 is the finding to check first.** It is the one claim here that is
   about MCTL's code rather than the vendor's, and it is what turns an
   otherwise routine admission into a HOLD. If I have misread
   `validateClient`, the HOLD verdict weakens and the row should be
   revisited. The assertion is narrow: nothing constrains a CIMD document's
   `redirect_uris` to the host or path prefix that admitted it.
2. **No live verification happened, by necessity.** Two Gate A checks need
   outbound HTTPS, which this environment does not have. The report says so
   per row instead of inferring from the vendor's description. A reviewer with
   network access should fetch the example document and archive its headers,
   chain and `Cache-Control` before any admission decision.
3. **The working tree was already CRLF end to end** while `HEAD` is LF and
   `core.autocrlf=false`, so `git status` showed all ~1370 files modified
   before I touched anything. `git add -A` as written in the task process
   would have committed that churn, so I staged only my four files and
   normalised those to LF; the commit diff is 3 changed lines plus the new
   report. The pre-existing line-ending churn is untouched and still shows in
   `git status`.
4. **`AGENT_SUMMARY.md` is intentionally uncommitted** for the same reason.
5. **The public-page edits are a judgement call.** Gate B gates status changes
   on evidence, and I changed no status word. I did change the stated *reason*
   and the tracking link, because leaving a superseded explanation pointed at
   an issue closed *not planned* is itself inaccurate. If a reviewer prefers
   the public pages frozen until Gate B runs, the two one-line HTML changes
   are the part to drop.
6. **Nothing here is a partner claim.** The commercial terms are recorded as
   the vendor's published terms as of 2026-11-22, unverified, with the
   own-agent versus referred-agent payout collision flagged as unresolved.
