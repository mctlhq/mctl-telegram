# Design

Keep the current MCP route and OAuth transport. The Workspace-only mode serves one versioned HTML resource and sets explicit host visibility for every tool. The four authorized reads and the trust boundary are defined in the [validation plan](../../../docs/plans/telegram-workspace.md#shared-connector-authorization).

The host bridge authorizes calls from the iframe. The server validates the normal OAuth principal and existing policy at discovery and invocation. The iframe receives no credentials. The origin allowlist, resource CSP and safe rendering remain in force.

Deploy the server release with Apps off. Activate via the existing production GitOps PR. Rollback disables Apps and preserves normal tools and OAuth.
