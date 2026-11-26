# Telegram Workspace operator validation

The canonical evidence issue is [#650](https://github.com/mctlhq/mctl-telegram/issues/650). See the [validation plan](../plans/telegram-workspace.md) for source and deployment pins.

## 1. Independent review and shared connector preflight

1. Record the reviewed commit and bundle digest, reviewer, findings, dispositions and human approval. Review the full App allowlist, existing OAuth and write gates, host visibility, CSP, OriginGuard and rendering of untrusted content. Confirm only the Workspace resource is served and only `telegram_dashboard` binds to it.
2. Exercise a controlled host fixture with synthetic data. Confirm the four allowed reads work and that absent-scope, anonymous and cross-principal access fail. Confirm existing tools and schemas remain available to normal calls under the same scopes, and that consent, rate limiting and confirmations keep their current behavior.
3. Deploy the approved pilot-capable image with `MCP_APPS_PILOT=true` and `MCP_APPS_ENABLED=false`. It selects the existing authenticated canary OAuth account on `/mcp`, and the pilot server refuses every tool outside its named read-only profile regardless of OAuth scope. Ordinary accounts and machine monitoring keep the normal MCP handlers. Confirm a canary OAuth tool list shows the Workspace while a non-canary OAuth tool list does not. Use the existing ChatGPT connector with the controlled account.
4. Prove host bridge enforcement before general activation. Use `get_my_identity` as the model-only negative control. It makes no Telegram write and the canary may call it through the model. Verify an explicit host refusal when the Workspace iframe requests it, with no matching upstream MCP call. Use Workspace Refresh as the permitted iframe control. Record sanitized statuses and audit correlation, without identity payloads. Never dispatch a real write to test bridge refusal. Record the host build and enforcement evidence, and record `BLOCKED_SECURITY` if the intended host fails that boundary or evidence is unavailable.
5. Verify the approved image digest and existing production OAuth, OriginGuard, normal tool filtering and send settings. Remove `MCP_APPS_PILOT` and enable `MCP_APPS_ENABLED=true` together with `MCP_APPS_WORKSPACE_ONLY=true` through approved GitOps. Roll back by disabling Apps if discovery, OAuth continuity, native rendering or bridge enforcement regresses.
6. Pin a Workspace bundle per release. Record URI, MIME, SHA-256 of the decoded `resources/read` text, image and route. Mark any host-loaded digest that cannot be observed as unobserved.

## 2. Host observations

Open the Workspace through the existing `https://tg.mctl.ai/mcp` connector registration. Use a controlled test account for evidence. Verify authenticated `tools/list`, native ChatGPT rendering, read interactions and normal tool and OAuth continuity without a second connector. Test approved Portal mappings independently. Record the date, host and build, route, scopes, resource and digest, capabilities, MCP/UI handshake and sanitized screen evidence.

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
- Trigger an allowed App-originated read and correlate it to the same caller and upstream audit outcome using sanitized request identifiers. Keep model-originated and UI-originated calls separately identified. Verify host theme, keyboard navigation, narrow and wide layout, and host-supported expansion.
- Run headless independently and record a semantic text result. A model statement or tool success alone is insufficient for a native verdict. Use `REAL_HOST_VERIFIED`, `BLOCKED_BY_HOST`, `BLOCKED_BY_PORTAL`, `BLOCKED_SECURITY`, `UNSUPPORTED` or `UNMEASURED` with dated evidence. Record fixture results as fixtures.

### Portability gates

Use the [#376 gate definitions](https://github.com/mctlhq/mctl-gitops/blob/f64f79d1c/platform-gitops/agents-state/.github/proposals/issue-376-spike-mcp-apps-write-once-run-across-ai/design.md#6-gates-scope-outcome-table-and-decisions). Attach a dated verdict and immutable sanitized evidence path and SHA-256 for each applicable cell.

| Gate | Required evidence |
| --- | --- |
| G1 Bundle | One canonical HTML SHA-256 per release. Compare the server-served digest and each observed digest across core hosts and measured routes. A Portal-only transformation with a matching upstream digest makes that route unsupported for this release. |
| G2 Render and refresh | Observe an empty-input launch, refresh, filter and detail opening on direct MCP for ChatGPT, Claude and Antigravity. Record ChatGPT Web and Work independently. |
| G3 Read semantics | On direct MCP for each core host, compare structured output from App-originated and model-originated reads with equivalent arguments and identity. Normalize timestamps using controlled synthetic data. |
| G4 Headless | For each configured headless client, verify existing text results are byte-equal with Apps on and off using fixed input and data. Verify semantic text for the new opener separately, since it is introduced by the Workspace proposal. |
| G5 Degradation | Require a pinned browser fixture that tests absent capabilities and both teardown and no-teardown cases, plus one verified core host on the same release. |
| G6 Security | Record host bridge denial and backend OAuth enforcement, then capture comparable caller, policy and audit evidence for a UI read and a model read on each core host that passed G2. |

A full adoption recommendation requires G2 and G3 on all three direct core hosts and G1, G4, G5 and G6. Apply #376's owner decision table for standard-only adoption, reviewed thin adapter metadata with the same bundle, or deferral. Keep unmeasured cells and Portal limitations visible in the result.

## 3. Troubleshooting

| Observed failure | Next check |
| --- | --- |
| Tool unavailable or text only | Check the granted scopes, exact registration route, enabled profile, extension capability and the host-visible opener descriptor. Confirm the descriptor references the exact listed URI and MIME. |
| Missing or stale view | Compare raw tool metadata, served digest and host-loaded digest. Refresh descriptors on the existing registration and record the result. If only recreation restores the view in a controlled test, record an existing-registration compatibility failure. |
| View times out before ready | Record requested and negotiated protocol, app version, request/response IDs, whether the response came from the immediate parent and whether ready was emitted. Compare with the pinned SDK/reference fixture under the same authorized route. Retain source and CSP checks. |
| Ready with blank or stale data | Confirm the host delivered a standard tool result and the app recognizes its structured schema without a tool-name field. Check ordering around ready, app-originated tools/call support and stale refresh responses. |
| Portal differs | Compare direct and Portal metadata, UI bytes, lifecycle, read and actor/audit evidence. Record the precise missing capability. |

## 4. Evidence and cleanup

Use synthetic content only in screenshots and recording. Record native open, filter, search and refresh, then retain only sanitized traces and audit references. Exclude raw Telegram payloads, raw host context, personal identifiers, tokens and secrets. Revoke the test OAuth grants and Telegram sessions, remove temporary test registrations and test resources via their approved lifecycle, and verify access denial after revocation. Link cleanup evidence and the reviewer disposition in #650. Keep the issue open until the required real-host evidence and recommendation are recorded.
