# Isolated read-only MCP Apps profile tasks

- [ ] Independently review the exact allowlist, per-tool scopes and side effects, route inventory, isolated OAuth/Telegram identity, and rollout boundaries. Obtain the applicable human approval.
- [ ] Implement and validate the new registration profile in the existing Go server. Pin its exact inventory and cover any direct registration entry point.
- [ ] Test documented discovery and valid-shape direct calls to all excluded registered names with synthetic data. Confirm no handler side effects, even for mismatched annotations, and retain audit correlation. Cover scoped reads, missing scopes, invalid config, foreign/revoked credentials, and unauthenticated resource denial.
- [ ] Review effective endpoint manifests and runtime isolation independently before provisioning. Verify explicit flags, isolated credentials/data, and route policy. Record approval and attestation in #650. Halt with `BLOCKED_SECURITY` if any boundary remains unproven.
- [ ] Handoff to the operator runbook. Keep both existing GitOps activation PRs outside this work.
