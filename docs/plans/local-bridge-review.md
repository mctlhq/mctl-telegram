# Local Bridge 0.62.1 review and manual verification

Status: in progress, 2026-09-08. This is the canonical plan and result log.

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
| Automated suites | IN PROGRESS | CLI, OAuth/auth, bridge, database, MCP and web packages. |
| Code review findings | IN PROGRESS | See findings below as they are confirmed. |
| Backup and test binary | PENDING | Preserve the working installation before replacing state. |
| Fresh local login and activation | PENDING | Requires operator terminal and browser input. |
| ChatGPT OAuth and local reads | PENDING | Must be exercised with the new account. |
| Consent, Saved Messages send, revoke | PENDING | Only the test account/device is in scope. |
| Original service restoration | PENDING | Required after any test replacement. |
| Live lookup login | NOT RUN | No dedicated configured identity; local tests only. |

## Findings

Review in progress. A green mocked test suite is not a completed live test.
