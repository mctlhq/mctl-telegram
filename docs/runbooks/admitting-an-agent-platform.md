# Runbook: agent platform admission

This runbook is the operator procedure for letting a new MCP host or agent
platform reach `https://tg.mctl.ai/mcp`. The current state per host is in the
[compatibility matrix](../platforms/compatibility.md). All settings live in
mctl-gitops `platform-gitops/services/labs/mctl-telegram/values.yaml`; the
comments there are authoritative.

## Admitting an agent platform

### 1. Intake

Decide which path the platform uses:

- CIMD (preferred): an https `client_id` document on the platform's own host.
  Admit the exact host; no suffix entries in production. Fetch and inspect the
  document first.
- DCR: a callback host on `OAUTH_ALLOWED_IMPLICIT_HOSTS`. Loopback redirects
  are always accepted; custom schemes such as `cursor://` are refused.
- Byte-exact redirect URI: a gateway with fixed callbacks, admitted through
  `OAUTH_DCR_REDIRECT_URIS`.

### 2. Settings, in this order

Use one gitops PR per step and verify each before the next.

1. `OAUTH_ALLOWED_IMPLICIT_HOSTS`: admit the DCR callback host, so the
   platform works whatever discovery says.
2. `OAUTH_CIMD_ALLOWED_HOSTS`: admit the CIMD host. Keep the implicit entry
   until the platform is confirmed on CIMD and its connections have
   re-authorized.
3. `MCP_CLIENT_PROFILES`: optional. Prefer a `client_id` binding (the CIMD
   URL). A malformed table stops the server at startup. A `redirect_uri`
   record refuses pre-0.87.0 refresh families. See
   [Client tool profiles](../runbook.md#client-tool-profiles) rather than a
   copy here.

### 3. Warning: advertising CIMD

`OAUTH_CIMD_ADVERTISE=true` leaves CIMD-preferring clients (ChatGPT, Codex,
Claude, VS Code) with no DCR fallback: they switch to CIMD on their next new
connection. A CIMD client whose host is not on `OAUTH_CIMD_ALLOWED_HOSTS`
gets a 400 on new authorizations. Production already advertises, so every new
CIMD host must be on the allowlist before that platform's users connect.
Advertise requires accept, and accept requires a non-empty host allowlist;
startup refuses otherwise.

### 4. Verification

- ArgoCD is synced to the new revision.
- `GET /.well-known/oauth-authorization-server` shows
  `client_id_metadata_document_supported`.
- `mctl_oauth_client_registrations_total{outcome="rejected",reason="redirect_host_not_allowed"}`
  stops rising for that host.
- The platform reaches the Telegram sign-in, receives a token and makes one
  read-only tool call.
- Record the result as a dated row update in the
  [compatibility matrix](../platforms/compatibility.md).

### 5. Rollback

- Revert the gitops PR.
- Removing a host from `OAUTH_CIMD_ALLOWED_HOSTS` also cuts off that client's
  refreshes. Turning `OAUTH_CIMD_ACCEPT` off does not.
- Setting `OAUTH_CIMD_ADVERTISE=false` returns clients to DCR at their next
  sign-in.
- Removing a profile binding from `MCP_CLIENT_PROFILES` takes effect at the
  next refresh.

### 6. Measured example: Town

- Integrator time: unknown; not measured.
- Operator time: 3 gitops PRs over about 3 days, including mctl-gitops#2023
  (DCR host) and mctl-gitops#2063 (profile binding). The third PR was not
  identified from the available gitops history.
- Waiting time: sync time plus waiting on the integrator between PRs.
- Outcome: reached the Telegram sign-in; no token or tool call is proven.
