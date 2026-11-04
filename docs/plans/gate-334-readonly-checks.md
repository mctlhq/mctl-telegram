# Read-only checks for gate #334: Nebius scope and Vault isolation

Status: PLANNED, NOT APPROVED FOR EXECUTION for the Vault and Nebius parts
(2026-11-04). The Kubernetes part is read-only and was run on 2026-11-04. No
check here changes a key, a limit, a policy or any infrastructure. Plan:
`gate-334-quota-isolation.md`, matrix rows 1 and 2.

Rules for every check: print metadata only, never a secret value, never `-o yaml`
or `-o json` of a Secret's `data`, never paste a token into chat. Record
non-secret identifiers only.

## 1. Kubernetes (done, read-only kubectl)

Results on preview, 2026-11-04:

- The Secret `labs-agent-worker-managed-preview-openai` exists only in namespace
  `labs`; its only annotation of interest is the ExternalSecrets data hash, so
  it is not reflected into other namespaces.
- The only ExternalSecret that references the `openai-nebius` Vault path is
  `labs/labs-agent-worker-managed-preview-openai`, Ready, store `vault-backend`.
- The only pod that references that Secret is the pool worker pod in `labs`.
- The worker Deployment has no environment variable with `ANTHROPIC` or `CLAUDE`
  in its name (checked on the Deployment `env` names); its `envFrom` is three
  Secrets: `-api`, `-openai` and `-gateway`. The key names inside those Secrets
  (`AGENT_API_TOKEN`, `AGENT_OPENAI_API_KEY`, `AGENT_GATEWAY_TOKEN`) are taken
  from the values file, not read from the Secrets.
- Only `ExternalSecret` objects were listed. `ClusterExternalSecret`,
  `PushSecret` and namespaced `SecretStore` objects were not, and are added to
  the checks below.
- `vault-backend` is the one ClusterSecretStore in the cluster, and any namespace
  may reference a ClusterSecretStore, which is an isolation question in itself. It authenticates
  to Vault with the `external-secrets` role (Kubernetes auth). Which Vault paths
  that role can read is the open question below.

Disclosure: on 2026-11-04 the first of these reads used `-o json` on the Secret
object, so the Secret's `data` was fetched into the local pipe, although only
metadata keys were printed and nothing was displayed, logged or stored. That is
below this document's own bar, so the command is replaced below. The Nebius key
was not shown anywhere; the owner may still treat that read as an exposure of
the object to the client and rotate under the rotation drill if preferred.

Commands to use (names and counts only). An output format such as
`-o custom-columns` changes only what kubectl prints: the API server still returns
the whole Secret, `data` included, so it is not a metadata-only read and is not
used here. Default table output asks the server for a Table, whose rows carry
object metadata only. Do not add `-o`, and do not use a verbosity that prints
response bodies.

- `kubectl get secret -A --field-selector metadata.name=<name>` (namespace, name,
  type, key count, age; the request's `Accept` header is `as=Table`);
- `kubectl get externalsecret -A -o json`, then `jq` on `remoteRef.key` and status;
- `kubectl get pods -A -o json`, then `jq` on `secretKeyRef`, `secretRef` and
  secret volumes (Pod specs hold references, never secret values);
- `kubectl -n labs get deploy <worker> -o json`, then `jq` on env variable names.

## 2. Vault (read-only, needs the owner's login)

Purpose: show who can read `secret/platform/labs/agent-worker-managed-preview/`.
The owner logs in first with the OIDC login command documented in
`docs/runbook.md`; the agent then runs only read operations. If the token cannot read policies, the
owner runs the commands and shares the policy names, not secret values.

1. `vault kv metadata get secret/platform/labs/agent-worker-managed-preview/openai-nebius`
   shows versions, timestamps and custom metadata. It does not show values. Do
   not use `vault kv get` on this path.
2. `vault read auth/kubernetes/role/external-secrets` shows bound service
   accounts, namespaces and attached policies.
3. `vault policy read <policy>` for each attached policy: does any rule grant
   read on `secret/data/platform/*`, `secret/data/platform/labs/*` or the exact
   path? A wildcard means every ExternalSecret that the store accepts can read
   this key, which is the isolation gap to record.
4. `vault auth list` to enumerate every auth mount (kubernetes, oidc, approle,
   jwt, userpass). For each mount, list its roles (`vault list auth/<mount>/role`)
   and `vault read` each one, checking the attached policies for the same paths.
   Then `vault list identity/group/name` and `vault list identity/entity/name`,
   reading the policies attached to groups and entities, and `vault policy read
   default` and any admin or root-like policy.
5. `vault token capabilities secret/data/platform/labs/agent-worker-managed-preview/openai-nebius`
   for the owner's own token, to know what the owner's role can do (informational).
6. Also in the cluster (read-only kubectl, metadata only): `kubectl get
   clusterexternalsecret,pushsecret,secretstore -A` and the `ClusterSecretStore`
   conditions, to know which namespaces may reference `vault-backend` and
   whether anything else can read or copy the path.

Record: role names, policy names, the exact path patterns granted, and a
yes/no for "only the ExternalSecret of the worker can read this path". If the
answer is no, the record states which other roles can and whether that is by
design; whether to tighten it is a separate owner decision and a separate gitops
or Vault change that this document does not make.

## 3. Nebius project and quota scope (read-only, owner console)

No Nebius CLI is installed here and the agent does not call the Nebius API with
the production key for this check. The owner reads the console, or runs a
read-only CLI command of their own, and reports non-secret facts:

1. Project and folder that the managed-runtime key (Vault `openai-nebius`)
   belongs to. Record the project id.
2. Project and folder of the support agent key (Vault
   `secret/platform/mctl-support/model`, `nebius-api-key`). Same or different
   project than item 1?
3. Every other key in the project of item 1 and its consumers, if the console shows them.
4. Quota and rate-limit pages for that project: model, requests per minute,
   tokens per minute, and whether the limit is per key, per project or per
   organisation. Record the numbers.
5. Billing: whether the project has a budget or a usage alert and who receives it.
6. Region of the endpoint used (the support pilot recorded FI).

Result table to fill in:

| Fact | Value (non-secret) | Who read it | Date |
|---|---|---|---|
| Managed key project id | | | |
| Support key project id | | | |
| Same project? | | | |
| Limit scope (key / project / org) | | | |
| RPM / TPM for GLM-5.1 | | | |
| Budget or alert at Nebius | | | |

Decision rule: if the managed key and any other consumer share the project (or
the limit scope is the organisation), row 1 of the #334 matrix stays open and the
neighbour test stays mandatory. A separate Vault path is not a separate quota.

## 4. Cloudflare AI Gateway (read-only)

The gateway `mctl-telegram` and the Cloudflare account are shared with the
support agent. The owner records, from the Cloudflare dashboard, the gateway rate
limit settings and whether the custom provider `nebius` is referenced by other
gateways. No setting is changed. Logging stays disabled by design.
