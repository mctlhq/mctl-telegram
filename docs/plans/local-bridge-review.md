# Local Bridge 0.62.1 review and manual verification

Status: code review complete; local login and activation completed, 2026-09-08.
This is the canonical plan and result log. Tracking PR: [#565](https://github.com/mctlhq/mctl-telegram/pull/565).

## Scope and acceptance

Review release `0.62.1` (`2cc03c234be346919735a0e8e0ddacf533f354b5`),
then exercise a Telegram account new to the service using the Intel macOS
release binary, the production relay, and ChatGPT as the OAuth/MCP client.
Do not change application code or production configuration as part of this
review. Record actionable findings separately from untested assumptions.

The lookup path from #400 is a separate code/local-test review. Its only
scope is `admin:users:read`; Telegram Login establishes identity without
the hosted `enable_access` phone/code/2FA flow or an MTProto session. A live
lookup login and the Vault/OpenClaw integration are outside this run: no
dedicated lookup identity is available.

## Review procedure

- Trace CLI init/login, browser activation and consent, device proof of
  possession, first credential/refresh, websocket registration, OAuth owner
  authentication, MCP routing, send consent and device revocation.
- Check replay, identity mismatch, denied/expired activation, ownership,
  reconnect/recovery, absent-daemon behavior and absence of hosted fallback.
- Distinguish the owner's OAuth token from the daemon's device credential.
  The existing CLI E2E stubs Telegram and mints an owner token directly;
  it does not establish that ChatGPT OAuth works after local activation.
- Compare the overview, quick start, owner and architecture documentation
  with actual behavior. Verify lookup allowlist precedence and removal,
  refresh and rejection of messaging/admin-write/token-mint operations.
- Run the relevant Go suites on the release tree. Use synthetic fixtures
  for adversarial cases rather than real third-party accounts or devices.

## Manual procedure and restoration

Use the operator's Intel Mac mini over SSH. It already runs a legacy
Local Bridge launch agent. Temporarily stop the launch agent and preserve
the original binary, complete configuration directory (including SQLite
sidecars), passphrase and plist in an owner-only backup. Restore the
original installation and service after the run, including on interruption.
Never overwrite the original state with a fresh `init`.

1. Download `mctl-telegram-local-0.62.1-darwin-amd64`; verify the release
   checksum before execution. Record the deployed relay image independently.
2. In clean local state, run `init`, `login --phone ...`, and
   `activate --server https://tg.mctl.ai`. The operator enters secrets
   directly in the terminal and completes browser sign-in and Approve.
   Local phone/code/2FA remains necessary for the local MTProto session.
3. Connect ChatGPT to `https://tg.mctl.ai/mcp` as that same identity after
   activation. Expect no hosted MTProto login. With the daemon stopped,
   expect the explicit daemon-not-connected error.
4. Start the daemon. Read dialogs and the account's own test conversation;
   confirm `call_path=local` in the owner's audit log.
5. Verify sending is blocked before consent. Grant owner send consent,
   inspect `get_my_send_status`, refresh the relevant credential if needed,
   then send one marked test message to Saved Messages only. Revoke consent
   and verify that the next send does not deliver.
6. Restart the daemon and verify recovery; repeat activation without
   creating another device. Revoke only the test device and verify both
   disconnection and refusal to reconnect.
7. Stop test processes, preserve test state separately, restore the original
   binary/configuration/passphrase/plist, restart the original launch agent,
   and verify its connection.

Do not persist phone numbers, account identifiers, private messages,
credentials, authorization codes or raw logs in this document. Server-side
session absence is a local-test assertion unless separately observed live.

## Evidence and run log

| Check | Status | Evidence / remaining work |
| --- | --- | --- |
| Source baseline | PASS | Release commit above; task worktree is based on the tag. |
| Production relay version | PASS | Running deployment and pod use `ghcr.io/mctlhq/mctl-telegram:0.62.1`; one ready replica. |
| Mac mini preflight | PASS | Intel macOS; existing launch agent running; current binary differs from release checksum. |
| Automated suites | PASS | CLI, OAuth/auth, bridge, database, MCP and web packages, uncached on the release worktree. |
| Static checks | PASS | `go vet` on the same package set; `git diff --check`. |
| Additional OAuth integration | PASS | Synthetic ChatGPT DCR + S256 PKCE + local-account callback + owner token; no hosted session bytes. Telegram provider is stubbed. |
| Lookup login and refresh | PASS | Initial grant and refresh have only `admin:users:read`; no `telegram_accounts` row created. Removal has a finding below. |
| Code review findings | FAIL | Four confirmed findings below; no application fixes applied. |
| Test binary preparation | PASS | Release checksum `203642c7925ac1b8c63dc2fdbdc0ed66e304053d77f5f2a241e9cbada82df3c4`; `init --help` succeeds. |
| Backup and state replacement | PASS | A failed interrupted attempt was repaired manually; original binary checksum matches preflight, original config is present with `0700`, and launchd is running again. The remote helper now restores based on actual backups rather than `started`/`restored` marker state. |
| Fresh local login and activation | PASS WITH UX BUG | Local Apple Silicon run completed Telegram login and device activation for the review account. The activation form's POST returned the expected 302, but Chromium blocked the redirected Telegram OAuth navigation under `form-action 'self'`; opening the `Location` URL manually completed activation. |
| ChatGPT OAuth and local reads | PASS | ChatGPT connected to `https://tg.mctl.ai/mcp` with the review account; `get_my_identity`, send-status inspection and dialog listing completed while the local daemon held an active websocket. |
| Consent, Saved Messages send, revoke | PASS | Consent enabled and one marked message reached Saved Messages through the local daemon; consent-off produced `sent=false` with `per-account send_enabled=false`; device `dev_6302c0cf42d6ed281106b899975e4c5c` was revoked with denylist refresh and hub eviction, and the daemon's refresh was rejected as a revoked device. |
| Original service restoration | PENDING | Required after any test replacement. |
| Live lookup login | NOT RUN | No dedicated configured identity; local tests only. |

## Findings

### F1 — P1: device revocation can miss an in-flight websocket admission

Locations: [bridge authentication and registration](https://github.com/mctlhq/mctl-telegram/blob/2cc03c234be346919735a0e8e0ddacf533f354b5/internal/bridge/server.go#L54),
[Hub registration](https://github.com/mctlhq/mctl-telegram/blob/2cc03c234be346919735a0e8e0ddacf533f354b5/internal/bridge/server.go#L97),
[owner eviction](https://github.com/mctlhq/mctl-telegram/blob/2cc03c234be346919735a0e8e0ddacf533f354b5/internal/mcp/tools.go#L1336).

`Authenticate` checks the credential before websocket upgrade and
`hub.Register`. If revocation commits, refreshes the denylist and evicts the
device between those two operations, the eviction sees no new connection.
The already-authenticated request subsequently registers the revoked device.
The open connection has no later revocation check and can receive further
owner tool-call payloads. A fresh authentication correctly rejects the same
token, so repeating authentication tests alone misses this containment gap.

Local reproduction used the real `NewBridgeHandler`, SQLite device/lineage
records and JWT provider/cache. Pause immediately after successful provider
authentication; call `RevokeDeviceAndDenylist`, `cache.Refresh` and
`hub.EvictDevice` in the production order; release admission. The revoked
socket registers and completes a `list_dialogs` round trip. No real Telegram
account or production revocation was used. `TestReviewRevokeDuringBridgeAuthentication`
fails the expected no-post-revoke-admission assertion.

Recommended follow-up: synchronize admission with revocation, ensuring a
revoked device cannot become routable after eviction. Merely refreshing the
cache sooner does not close the race. Add a deterministic regression for
this exact interleaving and a control for a different, legitimate device.

### F2 — P2: local pinning bypasses the documented send-consent gate

Locations: [pin handler](https://github.com/mctlhq/mctl-telegram/blob/2cc03c234be346919735a0e8e0ddacf533f354b5/internal/mcp/tools.go#L666),
[local dispatch](https://github.com/mctlhq/mctl-telegram/blob/2cc03c234be346919735a0e8e0ddacf533f354b5/internal/mcp/tools.go#L691),
[daemon pin RPC](https://github.com/mctlhq/mctl-telegram/blob/2cc03c234be346919735a0e8e0ddacf533f354b5/cmd/local/daemon.go#L823).

The quick start promises a read-only daemon until the owner enables sending
or pinning. However, a regular OAuth client receives `telegram:messages:pin`
independently of `send_enabled`. After a valid prepare/confirmation,
`pin_message` checks that scope but not the live consent flag, then forwards
the call. The daemon invokes the pin RPC without an additional consent gate.
The read-only first device credential does not restrict the owner's token.

Local reproduction provisions a fresh local account (`send_enabled=false`),
registers an in-process daemon and invokes the real pin handler with ordinary
client pin scope and a valid confirmation. The daemon receives `pin_message`
and the result is successful, even with server `ALLOW_SEND=false` as well.
`TestReviewLocalPinWithoutSendConsent` fails the no-dispatch assertion. The
confirmation requirement remains enforced; this is specifically the separate
account-consent boundary. No real message was pinned.

Recommended follow-up: enforce the documented live account gate before
dispatching pin/unpin, with coverage for consent never granted and revoked
after a token was issued. Keep the scopes and confirmation checks too.

### F3 — P2: removing a lookup identity can broaden its refresh-token scopes

Locations: [open-registration fallback](https://github.com/mctlhq/mctl-telegram/blob/2cc03c234be346919735a0e8e0ddacf533f354b5/internal/oauth/server.go#L1089),
[refresh scope resolution](https://github.com/mctlhq/mctl-telegram/blob/2cc03c234be346919735a0e8e0ddacf533f354b5/internal/oauth/server.go#L2125),
[lookup materialization exemption](https://github.com/mctlhq/mctl-telegram/blob/2cc03c234be346919735a0e8e0ddacf533f354b5/internal/oauth/server.go#L1537).

While the identity is in `TG_LOGIN_LOOKUP_ADMINS`, both initial issuance and
refresh correctly grant only `admin:users:read`. The exemption from persisting
`access_tier=client` is insufficient for deprovisioning: with
`AUTO_APPROVE_CLIENTS=true`, removing the allowlist entry makes the unset
tier fall through to the automatic client grant. Refresh re-resolves scopes
without bounding them to the original grant.

Local reproduction completes DCR, browser callback, PKCE token exchange and
a successful narrow refresh for a synthetic lookup account with no MTProto
row. Remove only its lookup allowlist entry and refresh again. The token now
has dialogs/messages read, messages send/pin and `account:manage`.
`TestReviewLookupRefreshAndRemoval` fails the no-scope-expansion assertion.
The two admin lookup privileges disappear; this is expansion into the
identity's own messaging/owner permissions, not access to another account.
Actual messaging still requires an available session/daemon and applicable
send gates.

Recommended follow-up: define and enforce deprovisioning for open registration.
Until fixed, removal alone must not be described as revocation: explicitly
set the identity's DB tier to `none` and revoke its refresh-token family when
retiring the lookup integration. Do not change these values during this review.

### F4 — P2: activation form CSP blocks the Telegram OAuth redirect

Locations: [activation page CSP](https://github.com/mctlhq/mctl-telegram/blob/2cc03c234be346919735a0e8e0ddacf533f354b5/internal/oauth/local_bridge_activate_page.go#L24),
[activation verification redirect](https://github.com/mctlhq/mctl-telegram/blob/2cc03c234be346919735a0e8e0ddacf533f354b5/internal/oauth/local_bridge_activate.go#L119).

The activation page sends its same-origin code form with
`Content-Security-Policy: ... form-action 'self'`. The verification handler
returns a 302 to the external Telegram OAuth origin. In Chromium, submitting
the form from the rendered page produced the 302 in DevTools but the browser
then blocked the navigation with `form-action 'self'`; the page appeared to do
nothing. Copying the response `Location` URL and opening it directly allowed
Telegram Login and activation to complete, confirming that the code and server
redirect were valid.

Recommended follow-up: make the activation transition compatible with the CSP
policy. For example, allow the exact Telegram OAuth origin in `form-action`
if the browser behavior is retained, or submit the verification with a
same-origin script/navigation pattern whose redirect is not governed as an
external form action. Add a browser-level regression covering the POST,
302 and Telegram OAuth landing page; the current Go tests do not exercise
browser CSP enforcement.

## Test evidence and limitations

The unchanged release suites passed:

```sh
go test ./cmd/local ./internal/oauth ./internal/auth/... ./internal/bridge \
  ./internal/db ./internal/mcp ./internal/web -count=1
```

Additional review-only tests were injected with Go's `-overlay`, leaving
application and existing test sources unchanged. The three failures above
are deliberate assertions of the required behavior, not failures of the
baseline suite. `TestReviewLocalAccountChatGPTOAuth` passes. These tests
replace Telegram itself; they do not prove delivery or ChatGPT UI behavior.

The manual run is still required. A prepared terminal helper preserves the
original Mac mini installation and restores it on normal exit, interruption
or SSH hangup. It records only stage markers for remote progress checks;
credential input is not captured in the repository or this report.

The latest recovery check confirms the original launch agent is running and
the original binary checksum is unchanged. The helper was corrected after an
interrupted run: `restore.sh` now examines actual backup paths and can recover
even when the phase markers are stale or missing. The live scenario still
requires a fresh interactive run; the helper must be run with a TTY and will
restore the original installation on exit.
