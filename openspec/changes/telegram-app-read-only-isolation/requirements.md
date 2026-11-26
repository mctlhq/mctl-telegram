# Isolated read-only MCP Apps profile requirements

Status is proposed. [Implementation issue #1483](https://github.com/mctlhq/mctl-telegram/issues/1483) supports [operator issue #650](https://github.com/mctlhq/mctl-telegram/issues/650).

- An explicitly selected isolated profile SHALL register only the reviewed tool names and SHALL refuse dispatch of every other name. The same rule SHALL apply to direct callers and App-originated requests.
- The profile SHALL refuse startup on invalid configuration or unsafe combinations, including enabled send or missing mandatory auth. Discovery and invocation SHALL still apply caller scope checks.
- The endpoint SHALL have a distinct OAuth issuer/audience, keys, grants, database, sessions, and Telegram test or synthetic identity. A credential for another environment SHALL fail. The host-facing surface SHALL expose only the required MCP and OAuth routes.
- Existing profiles, deployed environments and flags SHALL preserve their behavior. Implementation approval does not authorize provisioning or a production rollout.

Acceptance requires complete registered-tool inventory, authenticated dispatch-denial and no-side-effect tests, caller isolation and audit proof, and independent security and contract review of the pinned implementation and deployment plan.
