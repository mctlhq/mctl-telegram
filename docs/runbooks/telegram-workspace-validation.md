# Telegram Workspace operator validation

The canonical evidence issue is [#650](https://github.com/mctlhq/mctl-telegram/issues/650). See the [validation plan](../plans/telegram-workspace.md) for source and deployment pins.

## 1. Independent review and isolated preflight

1. Record an independent reviewer, reviewed commit and proposal digest, findings, dispositions and the applicable human approval. Review the named tool profile, auxiliary routes, OAuth trust, Telegram data boundary, CSP/OriginGuard and the SEP-1865 contract before provisioning. Record `BLOCKED_SECURITY` whenever isolation evidence is missing.
2. After review and approval, verify the isolated server has its own endpoint, issuer/audience and signing and encryption keys, OAuth clients and grants, database and session store. Check routing, secret references and actual image digest. Use test-only Telegram credentials and a synthetic identity/data set or a dedicated throwaway account with only controlled test conversations. Verify that a Telegram test-DC identity can be mapped into the isolated OAuth flow before relying on that approach. Keep the operator onboarding path separate from the host-facing route. Exclude shared production keys, bearer credentials, production stores, work-context integrations and worker, admin and bridge routes.
3. Attest `AUTH_REQUIRED=true`, `ALLOW_SEND=false`, `MCP_APPS_ENABLED=true`, the named registration profile and OAuth scopes `telegram:dialogs:read` and `telegram:messages:read` as required by the approved inventory. Compare effective discovery with the exact allowlist.
4. In a synthetic or instrumented preflight, verify server denial of direct authenticated named calls outside that list, using valid argument shapes. Include send and prepare, mark-read and draft, template mutation, account/admin and token/worker tools. Require dispatch denial and no handler side effect. Verify missing-scope, cross-principal, wrong-audience, expired/revoked and anonymous denial, including anonymous resource reads. Confirm allowed reads retain caller identity. Exercise refusals with fixtures before registering any live host. Keep actual writes out of the validation.
5. Pin one Workspace bundle per release. Record the URI, MIME, SHA-256 of the decoded `resources/read` text bytes, build and route. Compare the actual bytes loaded by each host where observable with the reference. If the host prevents inspection, mark the hash as unobserved and record the limitation.

## 2. Host observations

Connect the isolated endpoint using a distinct least-privilege OAuth grant for each eligible host. Register direct MCP and an independently authorized isolated Portal mapping separately. Never repoint the shared Portal mapping for the test. Record eligibility, date, host and build, route, scopes, resource and digest, capabilities, MCP/UI handshake, and sanitized screenshot or recording references.

| Host | Priority | Direct native | Portal native | Fallback |
| --- | --- | --- | --- | --- |
| ChatGPT Web | P1 | UNMEASURED | UNMEASURED | UNMEASURED |
| ChatGPT Work | P1 | UNMEASURED | UNMEASURED | UNMEASURED |
| Claude | P1 | UNMEASURED | UNMEASURED | UNMEASURED |
| Google Antigravity | P1 | UNMEASURED | UNMEASURED | UNMEASURED |
| Cursor | P2 | UNMEASURED | UNMEASURED | UNMEASURED |
| Codex GUI direct MCP | P2 | UNMEASURED | UNMEASURED | UNMEASURED |
| Codex GUI plugin registration | Comparison | UNMEASURED | UNMEASURED | UNMEASURED |
| VS Code Copilot | P3 | UNMEASURED | UNMEASURED | UNMEASURED |
| Goose | P3 | UNMEASURED | UNMEASURED | UNMEASURED |
| Gemini consumer | Fallback | UNMEASURED | UNMEASURED | UNMEASURED |
| Grok native | Fallback | UNMEASURED | UNMEASURED | UNMEASURED |
| Gemini Enterprise | Deferred | DEFERRED | DEFERRED | DEFERRED |

For each row, record the outcome of these checks individually.

- Capture real `initialize` capability negotiation and paginated `tools/list` metadata, `resources/list` and authenticated `resources/read`. Verify the nested UI binding and MIME. Record absence or route-specific transformation.
- Open with empty input. Observe the actual sandbox, `ui/initialize`, the response ID and protocol, `ui/notifications/initialized`, and delivery of the original `ui/notifications/tool-result`. Verify the populated snapshot is visible.
- Verify refresh, inbox/unread and folder or type filters, conversation and message context, grouped search and date filters, and own-account status. Check loading, no items, errors and partial data.
- Trigger an allowed App-originated read and correlate it to the isolated principal and upstream audit outcome using sanitized request identifiers. Keep model-originated and UI-originated calls separately identified. Verify host theme, keyboard navigation, narrow and wide layout, and host-supported expansion.
- Run headless independently and record a semantic text result. A model statement or tool success alone is insufficient for a native verdict. Use `REAL_HOST_VERIFIED`, `BLOCKED_BY_HOST`, `BLOCKED_BY_PORTAL`, `BLOCKED_SECURITY`, `UNSUPPORTED` or `UNMEASURED` with dated evidence. Record fixture results as fixtures.

## 3. Troubleshooting

| Observed failure | Next check |
| --- | --- |
| Tool unavailable or text only | Check the granted scopes, exact registration route, enabled profile, extension capability and the host-visible opener descriptor. Confirm the descriptor references the exact listed URI and MIME. |
| Missing or stale view | Compare raw tool metadata, served digest and host-loaded digest. For an isolated connector the operator owns, record refresh/reconnect results. With permission to delete that test connector, remove it completely, recreate it, authorize again, and repeat the descriptor and resource checks. Record whether that restores rendering. |
| View times out before ready | Record requested and negotiated protocol, app version, request/response IDs, whether the response came from the immediate parent and whether ready was emitted. Compare with the pinned SDK/reference fixture under the same authorized route. Retain source and CSP checks. |
| Ready with blank or stale data | Confirm the host delivered a standard tool result and the app recognizes its structured schema without a tool-name field. Check ordering around ready, app-originated tools/call support and stale refresh responses. |
| Portal differs | Compare direct and isolated Portal metadata, UI bytes, lifecycle, read and actor/audit evidence. Record the precise missing capability. |

## 4. Evidence and cleanup

Use synthetic content only in screenshots and recording. Record native open, filter, search and refresh, then retain only sanitized traces and audit references. Exclude raw Telegram payloads, raw host context, personal identifiers, tokens and secrets. Revoke the test OAuth grants and Telegram sessions, remove isolated connector registrations and test secrets or resources via their approved lifecycle, and verify access denial after revocation. Link cleanup evidence and the reviewer disposition in #650. Keep the issue open until the required real-host evidence and recommendation are recorded.
