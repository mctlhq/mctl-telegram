# Telegram Workspace validation and rollout

[Operator issue #650](https://github.com/mctlhq/mctl-telegram/issues/650) owns the live evidence and disposition. The product target is the existing `https://tg.mctl.ai/mcp` connector and its OAuth issuer and grants. Activation is pending independent review and host enforcement evidence. The baseline below records the original prototype assessment.

## Audit baseline

| Evidence | Observation |
| --- | --- |
| Telegram main `92027b53970c9223e0b92467902cd8b754002bf6` | #569 Triage, #1479 template Dashboard and #1480 handshake fix |
| GitOps main `f64f79d1c` and live MCTL service status | ArgoCD reported both services Synced and Healthy. Production `0.149.0`, preview `main-92027b5`. Both GitOps manifests set `ALLOW_SEND=true` and omit `MCP_APPS_ENABLED`, which defaults to false. Service status establishes versions and sync, and the flag evidence comes from the manifests and application default. |
| Pending changes | [Telegram #1481](https://github.com/mctlhq/mctl-telegram/pull/1481) for 0.150.0 and [GitOps #3028](https://github.com/mctlhq/mctl-gitops/pull/3028) for preview activation were open and required review. [GitOps #3029](https://github.com/mctlhq/mctl-gitops/pull/3029) for production activation was draft. |

Production's tagged source has the flag-gated Triage resource and predates the Dashboard and handshake correction. The pinned main embeds two resources. Both use `text/html;profile=mcp-app`, `io.modelcontextprotocol/ui`, nested tool `_meta.ui.resourceUri` and lists of zero permitted external CSP domains. `resources/read` requires an authenticated identity and returns static bytes. Their SHA-256 hashes below identify source bytes, which must be compared with bytes actually served and rendered during validation.

| Source | Existing URI | SHA-256 |
| --- | --- | --- |
| 0.149.0 Triage | `ui://mctl-telegram/triage` | `390a03383cafc2a0272f5fac87e462306a365a07953f267f0760b999c7a50e88` |
| Pinned main Triage 0.2.0 | `ui://mctl-telegram/triage` | `eed387687b60d14a133922fe3bbe3dfbc97f154ef128eaec86fd82842be533ca` |
| Pinned main Dashboard 0.2.0 | `ui://mctl-telegram/dashboard` | `d601482184cf2a56cad2ca70aa5f376eead882c9ec30e7b35a9298111d38ed5d` |

### Existing behavior and gaps

- **Triage.** Provides unread, dialog and search views, context, media preparation and a prepare/send flow. It uses text nodes for Telegram content. On init it expects an iframe `tools/list` response before fetching unread. Its tool-result consumer branches on `params.name`, which the standard `CallToolResult` notification does not supply, and its initial unread fetch can overwrite a result from the opening tool.
- **Template Dashboard.** Provides validated `tg-dashboard/v1` tiles, read source allowlisting, folder and forum views, bounded polling, MCTL visual components, and host theme/locale handling. It opens from a dashboard-linked tool, then requests iframe `tools/list` and loads templates. It has no handler for the standard initial tool result. The editor and actions for mark-read and Telegram drafts belong to the existing prototype surface. Template data-source allowlisting constrains templates only.
- **Transport.** #1480 fixes required `ui/initialize` fields and emits `ui/notifications/initialized`. The existing fixture expressly implements iframe `tools/list`, which is outside the stable App bridge contract. A host that does not implement this request can leave initialization pending at that step. Both apps check the immediate parent as the message source. Triage does not apply the initial host theme. Size notification direction and expanded-mode negotiation need contract work. A fixture pass establishes local behavior and the live-host result is still unmeasured.
- **Authorization.** Host calls enter the existing HTTP OriginGuard/auth path. Server scope filtering applies at discovery and invocation. Handlers derive identity from request context and retain hidden-chat, account, consent, rate-limit, audit and confirmation controls where applicable. Tool visibility and read-only annotations are host hints. The existing `read-only` registration mode selects by annotation, and config validation accepts only `all` or `read-only`. Template save/delete currently require the dialogs read scope, illustrating why scopes alone cannot enforce endpoint read-only behavior. `ALLOW_SEND=false` is defense in depth.
- **Coverage.** The prototype report's seven linked tools reflect the original slice. Current main has a second resource and more linked tools. The template engine, server tools, designs and fixtures already cover substantial UI/data work. The remaining product slice is a deterministic open, standards-based lifecycle and a focused read-only workspace assembled from those capabilities.

Sources include [#569 and its original proposal](https://github.com/mctlhq/mctl-telegram/issues/569), [#1479](https://github.com/mctlhq/mctl-telegram/pull/1479), [#1480](https://github.com/mctlhq/mctl-telegram/pull/1480), [Triage report](../reports/mcp-apps-spike.md), [Dashboard report](../reports/telegram-dashboard.md), [stable SEP-1865](https://github.com/modelcontextprotocol/ext-apps/blob/main/specification/2026-01-26/apps.mdx), and the pinned `internal/mcp/server.go`, `internal/config/config.go` and `internal/mcpui/` sources.

### Local verification

The Go test and vet runs passed for `internal/mcpui`, `internal/mcp`, `internal/mcpprobe` and `internal/config`. Local Chromium rendered both apps with the repository's synthetic host and the Triage Refresh button issued another `get_unread_messages` call. In a separate control that returned JSON-RPC `-32601` to the iframe's `tools/list`, both apps completed the ready handshake and then stopped with a tool-list error. The control changed the fixture host only, using the same HTML bytes for both runs. No live host or Telegram account participated. Targeted lint reported 17 findings on the unchanged Go baseline, including an unused `withUIResource` helper.

## MCTL Stats Dashboard comparison

Reviewed mctl-api main `5a434bf`, including `internal/mcp/stats.go`, `internal/mcp/statsview/view.html`, `internal/mcp/stats_browser_test.go` and handshake fix `77dd77e9792a2bcaed759f11dc6d8c29fd059472`. Its read-only `mctl_stats_dashboard` opener returns caller-scoped structured data with a readable text summary. The HTML consumes standard tool-result notifications, completes the ready handshake and uses the host proxy for refresh. It versions its URI (current `ui://mctl-stats/view-3.html`). It also emits an OpenAI-specific descriptor field. The evidence does not establish that the field is necessary for Telegram or that it fixes stale metadata.

[mctl-api #1189](https://github.com/mctlhq/mctl-api/issues/1189) records a surfaced version mismatch and restoration of initial rendering after deleting and recreating the Stats connector. The internal cause is unresolved. The handoff also records Codex direct registration rendering where plugin registration previously produced text. These observations motivate separate registration/route rows and verification of metadata and loaded HTML. Stats results belong to Stats and do not establish Telegram compatibility.

The #569 proposal preferred attaching existing reads because the proposed `open_telegram_triage` had no business behavior beyond opening a view. A bounded snapshot gives `telegram_dashboard` its own coherent read-only contract in headless clients and lets hosts hydrate the first view deterministically. `open_telegram_workspace` is an alternate descriptive name. Prefer `telegram_dashboard` for consistency with `mctl_stats_dashboard` and describe it as the Telegram Workspace in discovery. Preserve the existing tools and resource contracts for existing clients. Version the new Workspace resource path on byte-changing releases and maintain bounded, byte-identical legacy resource aliases only where needed for cached metadata.

## Shared connector authorization

- Publish only the Workspace resource in production. Preserve the regular tool inventory, OAuth scopes, caller identity, consent, rate limits and confirmations. Legacy prototype resources and their additional tools stay off in Workspace-only mode.
- The explicit App allowlist is `telegram_dashboard`, `list_dialogs`, `get_messages` and `search_messages`. All other tools are model-only, including mutating tools that use a read scope. ChatGPT's widget compatibility flag mirrors the standard visibility.
- The authenticated host proxies calls to `/mcp`. MCP supplies no trusted signal identifying an iframe call versus a model call under that grant. The host must enforce the App allowlist, and the backend independently enforces OAuth scope, account ownership and existing write gates. A host that ignores App visibility cannot satisfy the shared deployment security requirement. Frontend code, annotations and client-supplied metadata are insufficient as authorization.
- Review the checked-in bundle, resource CSP, safe text rendering and the narrow bridge methods together with the host visibility policy. Use a synthetic no-op tool declaration to test host denial under a grant that can call it as the model, without exercising a real write.

## Implementation sequence

1. [#1482](https://github.com/mctlhq/mctl-telegram/issues/1482) and [Workspace OpenSpec](../../openspec/changes/telegram-workspace-dashboard/requirements.md) delivered the opener and workspace. [#1483](https://github.com/mctlhq/mctl-telegram/issues/1483) records the optional fixture isolation profile.
2. Review the shared-connector change and run the preflight in the [operator runbook](../runbooks/telegram-workspace-validation.md). Record the independent security and contract verdict and host bridge enforcement on #650.
3. Deploy a release containing Workspace-only mode with Apps disabled first. Activate through the approved [GitOps #3029](https://github.com/mctlhq/mctl-gitops/pull/3029) change using both `MCP_APPS_ENABLED=true` and `MCP_APPS_WORKSPACE_ONLY=true`. Roll back by disabling Apps. Keep the existing production OAuth, normal tool filters and send settings.
4. Use the existing ChatGPT registration against `https://tg.mctl.ai/mcp`. Confirm authenticated discovery, native rendering and allowed reads. Verify existing tools and OAuth continue to work. Retain the broader host and Portal matrix in #650. #1443 consumes the Antigravity result and #784 tracks the broader capability layer.

Keep #650 open until the required real-host evidence and decision are recorded. Release, deployment health and CI establish separate facts from native rendering or iframe authorization.
