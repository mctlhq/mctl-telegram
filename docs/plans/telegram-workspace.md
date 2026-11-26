# Telegram Workspace validation and rollout

[Operator issue #650](https://github.com/mctlhq/mctl-telegram/issues/650) owns the live evidence and disposition. As of 2026-11-26, provisioning and live validation are **BLOCKED_SECURITY**. The existing registration filter cannot prove the required named read-only surface, and the independent security and contract review for the isolated endpoint is pending.

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

## Implementation sequence

1. [#1483](https://github.com/mctlhq/mctl-telegram/issues/1483) and [isolation OpenSpec](../../openspec/changes/telegram-app-read-only-isolation/requirements.md). Add a fail-closed, endpoint-level registration allowlist. Independently review the security and contract design before provisioning. An isolated synthetic stage may validate the existing protocol only once the isolation and fixture gates pass.
2. [#1482](https://github.com/mctlhq/mctl-telegram/issues/1482) and [Workspace OpenSpec](../../openspec/changes/telegram-workspace-dashboard/requirements.md). Evolve the existing embedded UI and Go reads into one server-owned Workspace bundle per release. Use standard lifecycle and caller identity, render the opening tool result, and refresh via the same read contract. Reuse the existing data, renderer and styles where suitable.
3. Run [the operator runbook](../runbooks/telegram-workspace-validation.md) under #650 after independent review and an approved isolated deployment. Put evidence and any Portal limitation on that issue. #1443 consumes the Antigravity result for packaging. #784 tracks the broader capability layer. [Architecture #393](https://github.com/mctlhq/.github/issues/393) and [portability #376](https://github.com/mctlhq/.github/issues/376) define the shared standard and adoption gates.

## Readiness recommendation

Hold existing preview and production activation and connector submission for this validation. Keep #650 operator-owned. Complete the named allowlist, independently review endpoint and protocol isolation, and attest the isolated deployment before connecting hosts. Collect native ChatGPT, Claude and Antigravity evidence, semantic fallback, denial and cleanup evidence before making a production recommendation. A Portal limitation is recorded separately. Any production change requires its own human-approved GitOps path and rollback decision.
