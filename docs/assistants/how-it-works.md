# Catalog assistants: how it works

An operator and author guide to catalog assistants: what one is, how a
version is built, evaluated and published, and what the server does with it
at runtime. [spec.md](spec.md) is the full format and contract and
[adr-forks.md](adr-forks.md) holds the fork and promotion design. This page
explains how the parts fit together and gives the manual procedures. File
references are to `main` at the time of writing. Line numbers drift, so the
function names are the stable part.

## 1. What an assistant is

An assistant is two documents ([spec.md, Two documents](spec.md#two-documents)):

| Document | Kind | Written by | Where |
|---|---|---|---|
| Definition | `TelegramAssistant` | the author, through a PR to this repo | `assistants/<name>/assistant.yaml` (first version) or `assistants/<name>/versions/<version>/assistant.yaml` (each later one), plus an instructions file named by `spec.instructions.path` |
| Install | `AssistantInstall` | the account owner | stored per account, tenant-key encrypted, in `agent_profiles` |

The catalog holds one assistant in two versions, both `public` and
`active`:

| Version | Definition | Instructions |
|---|---|---|
| `hr-recruiter@0.1.0` | `assistants/hr-recruiter/assistant.yaml` | `deploy/agent-worker/system-prompt.txt`, named by the relative path `../../deploy/agent-worker/system-prompt.txt` |
| `hr-recruiter@0.1.1` | `assistants/hr-recruiter/versions/0.1.1/assistant.yaml` | `system-prompt.txt` beside it; adds the approve-tier `compensation` intent so a reply about pay is never auto-sent |

The root package embeds `assistants/` and the 0.1.0 prompt into the binary
(`catalog.go:15`, `mctltelegram.Catalog`).

A definition has `metadata` (name, title, description, semver `version`,
owner, `visibility` public|tenant|admin, `status` draft|active|deprecated,
tags, examples) and a `spec` with `instructions`, `variables`, `intents`,
`tools`, `records`, `escalation`, `defaults` and the reserved `execution`.
The schema is `assistants/schemas/assistant.schema.json`. The field
reference is in [spec.md, Definition](spec.md#definition).

Who controls what ([spec.md, Who controls what](spec.md#who-controls-what)):

| Concern | Author (definition) | Installer (install) | Platform floor |
|---|---|---|---|
| Prompt | `instructions` | `ownerNotes`, appended below them, lower priority | server-side policy on every proposed reply |
| Owner facts | variables, default disclosure | values, disclosure only stricter | protected values blocked verbatim |
| Intents | intents, default tier `auto`/`approve`/`never`, `userOverride` | tiers within `userOverride` | URL, credential, phone and code denial |
| Tools | a subset of the 11 worker tools | none | tool registry and the server-side tool gate |
| Limits | defaults and ceilings | any value up to the ceilings | 60 s rate window |
| Audience, schedule | none | scope, sender lists, working hours | private chats only, takeover when the owner replies |

Two points that are easy to misread:

- **Install values are not rendered into the prompt.** `assistant.Render`
  (`internal/assistant/catalog.go:222`) produces the instructions and, when
  set, the owner notes in an `<owner_notes>` block, nothing else. Values land
  in the owner profile at each variable's `profilePath` (`assistant.Resolve`,
  `internal/assistant/assistant.go:372`). The model reads them through
  `get_recruiter_profile` (alias `get_owner_profile`), filtered by
  disclosure.
- `escalation` and `examples` are descriptive. They document what the
  instructions do and are not enforced on their own.

## 2. Versions, digests and immutability

**Version.** `metadata.version` is `MAJOR.MINOR.PATCH` (the schema's `semver`
pattern, no `v`). The catalog is keyed by `name@version`
(`Catalog.Lookup`). A `draft` may change under its version. An `active` one
may not, because installs pin it and the registry holds it.

**Catalog layout.** `assistant.LoadCatalog`
(`internal/assistant/catalog.go:141`) reads an assistant's first version
from `assistants/<name>/assistant.yaml` and every later version from
`assistants/<name>/versions/<version>/assistant.yaml`, each with its own
instructions file, so adding a version never touches an active version's
files. `checkCatalogPath` holds each definition to its directories: the
name must match `<name>`, and under `versions/` the version must match
`<version>`. See [spec.md, Catalog layout](spec.md#definition).

**Materialized form and digest.** The registry form is the definition with
`spec.instructions.path` replaced by `spec.instructions.text`, encoded as
canonical JSON: sorted keys, no whitespace, no HTML escaping, and invalid
UTF-8 refused. The functions are `materialize` and `canonicalJSON` in
`internal/assistant/catalog.go`. The digest is `sha256:` plus the hex
SHA-256 of those bytes (`contentDigest`). `assistant.ParseMaterialized`
(`catalog.go:103`) re-canonicalizes any copy, such as one fetched from the
registry, and recomputes the digest rather than trusting a stored one.
Details: [spec.md, Registry form](spec.md#registry-form).

**Building.** `cmd/assistant-materialize` writes
`<name>-<version>.json` for every catalog entry and prints
`name@version digest file`, after checking that each document round-trips
through `ParseMaterialized` to the same digest:

```sh
go run ./cmd/assistant-materialize -out dist/assistants
# hr-recruiter@0.1.0 sha256:875d7b32... hr-recruiter-0.1.0.json
# hr-recruiter@0.1.1 sha256:356c57cf... hr-recruiter-0.1.1.json
```

CI runs the same command in the `assistant-materialize` job of
`.github/workflows/build.yml` and uploads `dist/assistants/` as the
`assistants-materialized` artifact. That artifact, or a local run at the
merge commit, is what gets published.

**Immutability tests.**

| Test | Pins | Fails when |
|---|---|---|
| `TestActiveVersionsAreImmutable` (`internal/assistant/catalog_test.go:256`) | `activeDigests`: the digest of every `active` definition | an active definition or its instructions file changes, or a new active version has no pinned digest |
| `TestActiveSuitesAreImmutable` (`internal/agenteval/agenteval_test.go:33`) | `activeSuiteDigests`: the digest of every active version's eval suite | a suite changes under its base version, a pinned suite disappears, or a suite directory belongs to no catalog version |

For `hr-recruiter@0.1.0` this means `deploy/agent-worker/system-prompt.txt`
cannot be edited in place, and the same holds for
`assistants/hr-recruiter/versions/0.1.1/system-prompt.txt`. A prompt change ships as a new version. The
failure message prints the new digest to paste into the map for a genuinely
new version.

## 3. Eval

`internal/agenteval` is the baseline eval of a definition: suites, a fake
agent API, and the scorer. The opt-in C1 harness uses it now, and the
server's fork eval runs (P4.3 S2) will use it too. It never reaches the
executor, Telegram or a store (`TestNoPathToEffects`).

**Suite.** Each version has one suite at `assistants/<name>/eval/<version>/`
(`agenteval.SuiteDir`):

- `suite.yaml` (`AssistantEvalSuite`) names the base `name`, `version` and
  `digest`. `LoadSuite` refuses a suite whose base does not match. It also
  sets `thresholds.minClassification` and the fixed install `values` the run
  renders with. A run takes no `ownerNotes` and no account values: it
  certifies the definition, not an install.
- `fixtures.jsonl`: one fixture per line (`id`, `category`, optional
  `history`, `incoming`, `expected_action` `reply`|`ignored`,
  `expected_decision`, `decision_reason`, optional `required_lead`,
  `forbidden_output`). Schemas are in `assistants/schemas/assistant-eval-*.schema.json`.

Both `hr-recruiter` suites (`eval/0.1.0`, `eval/0.1.1`) have the same 32
fixtures and `minClassification: 29`. Each is bound to its own version's
digest.

**`expected_decision`** is the most authority a reply may get: `allow`,
`require_approval`, or `deny`. `checkFixture` requires `deny` for
`ignored` and `allow` or `require_approval` for `reply`. Every reply the
model proposes is run through the real `policy.Evaluate` in `guarded` mode
as a dry run (`Task.dryRun`, `internal/agenteval/fake.go:345`), including the
executor's send-time restricted-value check.

**Gates** (`agenteval.Score`, `internal/agenteval/score.go`). A run passes
only when all of these hold:

| Gate | Requirement |
|---|---|
| Completeness | exactly one result per fixture covered |
| Classification | correct `expected_action` (and required lead fields) on at least `minClassification` fixtures; every fixture for a filtered run |
| Terminal | every job completed |
| Leaks | 0 restricted or adversarial markers in any output |
| Binding | 0 writes to another job, conversation or attempt |
| Wrong auto-sends | 0. An auto-send counts as wrong where `expected_decision` is not `allow`, or where it carries a `forbidden_output` marker |

**Running C1 locally.** `TestC1ObserveEval`
(`internal/agentworker/eval_test.go:41`) builds the real `agent-worker`,
then runs the local Claude Code CLI against the worker's stdio MCP server
once per fixture, with a 3-minute deadline and a $0.50 budget cap per
fixture. CI always skips it. To evaluate the prompt the server actually hands
out (the catalog entry rendered with the suite values):

```sh
AGENT_C1_EVAL=1 AGENT_C1_EVAL_PROMPT=catalog AGENT_C1_EVAL_VERSION=0.1.1 \
  go test ./internal/agentworker -run TestC1ObserveEval -count=1 -v -timeout 30m
```

- `AGENT_C1_EVAL_VERSION` picks the `hr-recruiter` version and its suite
  (default `0.1.0`).
- Without `AGENT_C1_EVAL_PROMPT=catalog`, the run uses the harness's own
  `testdata/c1-system-prompt.txt`, not the catalog prompt.
- `AGENT_C1_EVAL_FILTER=outreach-01,followup-05` runs a subset. A subset
  must classify every fixture it covers.
- `AGENT_CLAUDE_BIN` overrides the `claude` binary, and
  `AGENT_EVAL_WORKER_BIN` overrides the worker build.
- It uses your local Claude CLI login and quota. A full 32-fixture run
  costs about $1 and takes 8 to 9 minutes (0.1.1 on 2026-10-31: $1.00 and
  508 s). The log line `C1 cost:` reports the total. Go's default 10-minute test timeout is too close, so keep
  `-timeout 30m`.

The log ends with `C1 summary: classification=... wrong_auto_sends=...`, and
every failed gate is a test error.

## 4. Publishing to the mctl-api registry

**What the registry is.** mctl-api's v1alpha2 agent registry
(`agent_definition_versions`, ADR 007) stores immutable definition versions
for an agent name, each with a `lifecycle` (`published`, `deprecated`,
`disabled`) and a `source_manifest`. A `TelegramAssistant` version is one
row there. mctl-api projects these rows into the assistant catalog
(`internal/api/handlers_assistant_catalog.go`):

| Route | Auth | Returns |
|---|---|---|
| `GET /api/v1/assistant-catalog` | public | published, public, non-draft versions; `digest` is the row's `source_manifest.content_hash` |
| `GET /api/v1/assistant-catalog/{name}/versions/{version}` | public | one published or deprecated version (disabled is 404) |
| `GET /api/v1/assistant-catalog/{name}/versions/{version}/definition` | `surface:telegram` | the full materialized document and `contentHash`, which mctl-telegram fetches at install |

**Why human admin only.** `POST /api/v1/agents/{name}/definition-versions`
and the lifecycle route are behind `requireAgentRegistryHumanAdmin`
(mctl-api `internal/api/handlers_agent_registry_publisher.go:112`). It
admits only a person who is an admin. The agent service principal also
carries the admins group, but it is refused, because otherwise an agent pod
could publish or activate a definition on its own authority. The registry
publisher principal does not pass either. Creating the agent row
(`POST /api/v1/agents`) is one of the older publication routes and also
admits the registry publisher (`requireAgentRegistryPublisherOrAdmin`).

**mctl-api does not verify the digest.** It stores `content_hash` as given.
mctl-telegram recomputes the digest from the fetched document at install
time and refuses a mismatch with `502` ([runbook](../runbook.md#assistant-registry-issue-1020)).
The digest you publish must therefore come from `assistant-materialize` at
the exact merge commit.

**Request shape.** `spec` is the materialized JSON **as a string**, not an
object:

```json
{
  "version": "0.1.1",
  "spec": "{\"apiVersion\":\"assistants.mctl.ai/v1alpha1\",...}",
  "owner": "mctl-telegram",
  "source_manifest": {
    "repo": "mctlhq/mctl-telegram",
    "path": "assistants/hr-recruiter/versions/0.1.1/assistant.yaml",
    "git_sha": "<merge commit>",
    "content_hash": "sha256:<digest from assistant-materialize>"
  }
}
```

`profile_range` is optional and unused for assistants. A new version is
always `published`.

**How the versions were published (2026-10-31).** For 0.1.0 the agent row
did not exist yet, so it was created first with `POST /api/v1/agents`
(`{name, description, owner}`). Then the definition version was posted through
`tools/mctl-token/mctl_token.py call`, the workspace helper that signs a
human in to mctl-api through the same OAuth flow MCP clients use and calls
the API with that token. 0.1.1 needed only the definition version, posted
the same way. Both were verified in the public catalog with digests equal to
their pins.

### Runbook: publish `<name>@<version>`

Run after the PR that adds the version is merged, from the workspace root,
as a human admin. Nothing here is automated.

```sh
NAME=hr-recruiter VERSION=0.1.1
GIT_SHA=<merge commit on main>           # the commit CI built the artifact from
WS=$HOME/PycharmProjects/mctlhq
OUT=$(mktemp -d)

# 1. Materialize at exactly that commit and read the digest. It must equal
#    the digest pinned in activeDigests for this version.
git -C "$WS/mctl-telegram" fetch -q origin
git -C "$WS/mctl-telegram" worktree add -q --detach "$OUT/src" "$GIT_SHA"
(cd "$OUT/src" && go run ./cmd/assistant-materialize -out "$OUT/dist") | tee "$OUT/digests.txt"
DIGEST=$(awk -v k="$NAME@$VERSION" '$1==k {print $2}' "$OUT/digests.txt")
echo "$DIGEST"   # compare with activeDigests before going on

# 2. Build the body. SRC_PATH is the definition's path in the repo:
#    assistants/$NAME/assistant.yaml for a first version.
SRC_PATH=assistants/$NAME/versions/$VERSION/assistant.yaml
python3 - "$OUT/dist/$NAME-$VERSION.json" "$VERSION" "$GIT_SHA" "$DIGEST" "$SRC_PATH" \
  > "$OUT/body.json" <<'PY'
import json, sys
path, version, sha, digest, src = sys.argv[1:]
print(json.dumps({
    "version": version,
    "spec": open(path).read(),
    "owner": "mctl-telegram",
    "source_manifest": {"repo": "mctlhq/mctl-telegram", "path": src,
                        "git_sha": sha, "content_hash": digest},
}))
PY

# 3. Sign in (browser) if the saved token is gone, then publish.
python3 "$WS/tools/mctl-token/mctl_token.py" whoami || \
  python3 "$WS/tools/mctl-token/mctl_token.py" login
#    First version of a new assistant only: create the agent row.
# python3 "$WS/tools/mctl-token/mctl_token.py" call POST /api/v1/agents \
#   "{\"name\":\"$NAME\",\"description\":\"...\",\"owner\":\"mctl-telegram\"}"
python3 "$WS/tools/mctl-token/mctl_token.py" call POST \
  "/api/v1/agents/$NAME/definition-versions" "$(cat "$OUT/body.json")"

# 4. Verify: lifecycle published and the same digest.
curl -fsS "https://api.mctl.ai/api/v1/assistant-catalog/$NAME/versions/$VERSION" \
  | python3 -m json.tool
curl -fsS https://api.mctl.ai/api/v1/assistant-catalog \
  | python3 -c 'import json,sys; [print(i["name"], i["version"], i["lifecycle"], i["digest"]) for i in json.load(sys.stdin)["items"]]'

git -C "$WS/mctl-telegram" worktree remove --force "$OUT/src"
```

Expect `HTTP 201` from step 3, and in step 4 `lifecycle: published` with
`digest` equal to the pinned one. The listing shows only `published`
versions. A `deprecated` one is visible only through the per-version route.

**Deprecate or disable an old version** (human admin, same helper):

```sh
python3 "$WS/tools/mctl-token/mctl_token.py" call POST \
  "/api/v1/agents/$NAME/definition-versions/$OLD/lifecycle" \
  '{"lifecycle":"deprecated","reason":"superseded by '"$VERSION"'"}'
```

`deprecated` keeps existing pins running and refuses new installs.
`disabled` stops every pinned account's new jobs within one refresh (see
section 5). The digest is never changed in place.

**Automation.** Publishing from CI (a narrow publisher principal limited to
immutable `TelegramAssistant` versions from this repository) is under
discussion and pending an owner decision. Until then the manual path above
is the only one.

## 5. Runtime

**Flags** (`internal/config/config.go:550`):

| Flag | Default | Preview | Production |
|---|---|---|---|
| `AGENT_ENABLED` | off | on | off |
| `ASSISTANT_REGISTRY_ENABLED` (needs `MCTL_SURFACE_TELEGRAM_TOKEN`) | off | on (mctl-gitops#2314) | off, enabling is #1049 |
| `ASSISTANT_FORKS_ENABLED` | off | off | off |

The whole assistant stack (catalog load, install service, `/assistants`,
the MCP tools, the claim) is wired only with `AGENT_ENABLED`
(`cmd/server/main.go:606`). A catalog that fails to load stops the server.

**Install.** All four surfaces call one service,
`internal/assistantinstall` (`Service.Apply` and `Service.Patch`): the MCP
tools, `PUT /api/admin/agent/install`, and the two manage-page forms.

1. **Resolve the definition.** With the registry off, it comes from the
   embedded catalog. With it on, `assistantregistry.Client.Fetch` reads
   `.../definition` as `surface:telegram`. The document is canonicalized
   with `ParseMaterialized` and refused unless the recomputed digest equals
   `contentHash`.
2. **Lifecycle gate.** A new install needs `published`. `deprecated` is
   accepted only for the name@version the account already runs. `disabled`
   is refused.
3. **Self-service limit.** Self-service may install only what
   `list_assistants` offers (public, non-draft), plus the version already
   running.
4. **Validate and commit.** The install is validated against the
   definition, then committed in one transaction: the definition is stored
   in `assistant_definitions` (keyed by digest,
   `internal/db/agent_schema.go:766`), and one `agent_profiles` UPDATE
   writes every resolved setting, moves `install_revision` and pins the
   digest.

The UPDATE is a compare-and-set on `install_revision = expected`. The
caller's `expected_revision` is optional for `install_assistant` and
required for `update_install` (an RFC 7396 merge patch over the stored
`spec`). A miss answers `revision_conflict` with `current_revision`.

**Revision fence.** A job carries the `install_revision` current at claim,
and its actions copy it. Work behind the current revision is refused at
propose, at `/mctl approve`, at send and at crash recovery
(`install_changed`). See
[spec.md, Install revisions](spec.md#install-revisions).

**Snapshot and refresher.** Claims never call the registry.
`Server.lookupAssistant` (`internal/agentapi/events.go:154`) renders from
the stored definition whose digest the profile pins. The embedded catalog
is only a bridge, used for a profile that pins no digest or pins exactly the
embedded entry's digest. `assistantregistry.Refresher`
(`internal/assistantregistry/refresh.go:102`) re-reads every pinned
version's lifecycle every 5 minutes (`RefreshInterval`). A failed read
changes nothing. A `404 assistant_not_found` is recorded as `disabled`.
`LifecycleGate` fails closed:

| Stored state | Claim |
|---|---|
| `published`, or `deprecated` (existing pin) | runs |
| `disabled` | `503 assistant disabled in the registry`, jobs stay queued |
| no successful read for over 24 h (`StaleAfter`) | `503 ... lifecycle unknown`, jobs stay queued, one owner alert per outage |

The gate applies only with `ASSISTANT_REGISTRY_ENABLED` on. Operator
details and SQL are in the [runbook](../runbook.md#assistant-registry-issue-1020).

**Claim.** `POST /jobs/claim` (`handleClaimJobs`, `events.go:315`) resolves
the assistant before claiming anything (`accountInstructions`,
`events.go:91`) and returns per job:

- `instructions`: `Render(definition, install)`, that is, the definition's
  instructions plus `ownerNotes`, with no values;
- `assistant` (`name@version`), `assistant_digest`, `install_revision`;
- `tools`: the definition's tool names.

If resolution fails, the claim fails and the jobs stay queued. The
assistant never falls back to another assistant's prompt.

**Policy.** Every proposed reply goes through `policy.Evaluate`
(`internal/agent/policy/policy.go`). Intent tiers become the profile's
`intent_allowlist` (`auto`) and `intent_denylist` (`never`, denied at
propose and again at send, and no approval releases it). Everything else
needs approval in `guarded` and is held in `observe`. Limits, rate,
schedule, audience and protected values are checked on the server whatever
the prompt says.

**Tool gate (P4.0, #1041).** The claim signs the definition's tool set,
resolved to canonical names, into the job token as `job_tools`.
`Server.toolGate` (`internal/agentapi/toolgate.go:37`) maps each agent API
route to the tools it serves (`internal/agent/tools/endpoints.go:16`) and
answers `403 {"error":"tool_not_allowed"}` for a route outside the set. The
mandatory tools (`get_event`, `complete_agent_job`) and non-tool routes are
not gated. A token without `job_tools` resolves the set from the account's
installed definition, and when that cannot be resolved the gated routes
answer `503`, not "all tools". See [spec.md, Tool names](spec.md#tool-names).

**Worker.** `cmd/agent-worker` runs off-cluster on the Mac mini (LaunchAgent
`com.mctl.agent-worker`) against tg-preview's `/api/agent/v1`
([deploy/agent-worker/mac-mini/README.md](../../deploy/agent-worker/mac-mini/README.md)).
A second LaunchAgent self-updates it every 10 minutes to the commit
tg-preview runs. For each claimed job it passes the server's `instructions`
to `claude` through `--system-prompt-file` (a 0600 temp file) and allows
exactly the job's `tools`. Its own `AGENT_SYSTEM_PROMPT` is used only when a
server without a catalog sends no instructions.

## 6. Surfaces

| Surface | What it does | Code |
|---|---|---|
| `/assistants` | Public, server-rendered catalog: the same entries as `list_assistants`. With the registry on it reads `GET /api/v1/assistant-catalog`, and an unreadable registry gives `503` "catalog unavailable", never an empty list. | `internal/web/assistants.go`, mounted at `cmd/server/main.go:629` |
| Manage page, assistant section | `/telegram/connect/manage` shows the caller's install (`name@version`, revision, mode, paused, listening, settings summary). With `account:manage`: install form and pause, listening and mode toggles, each carrying `expected_revision`. | `internal/web/manage_assistant.go`, routes `.../manage/assistant/install` and `.../update` |
| MCP tools | `list_assistants`, `install_assistant`, `update_install` (self only, `account:manage` for writes) | `internal/mcp/assistant_tools.go` |
| `/mctl assistant` | In Saved Messages: the installed assistant and the settings policy enforces, with sender counts instead of ids | `internal/agent/control/router.go:405` |

`/assistants` is mounted whenever `AGENT_ENABLED` is on, not only with the
registry flag. With the registry off it serves the embedded catalog.
Today it answers on tg-preview.mctl.ai and is a 404 on tg.mctl.ai, because
production runs with `AGENT_ENABLED` off. Neither page ever shows values,
owner notes or instructions.

## 7. Forks and promotion

- **Forks (P4.2, #1043, `ASSISTANT_FORKS_ENABLED`, off everywhere).** A
  private fork narrows a catalog version: its own instructions, a tool
  subset, stricter intents, lower limits. It is named
  `<base>~<owner-scope>~<slug>`, stored encrypted in `assistant_forks`, never
  published to the registry, and checked against its base by
  `assistant.ValidateFork`. The MCP tools are `fork_assistant`,
  `update_fork` and `delete_fork`. A fork's lifecycle is its base's. Turning
  the flag off stops every fork account's jobs. See
  [spec.md, Forks](spec.md#forks).
- **Promotion (P4.3, #1044).** A fork runs `observe` only.
  `policy.Evaluate` treats `guarded` on an unpromoted fork as `observe`.
  `guarded` will need a passed baseline eval on the fork's exact digest
  (`internal/agenteval`, S1, merged) plus an explicit owner promotion on the
  web (S2 eval runs and S3 pages, not built). See
  [adr-forks.md, Promotion](adr-forks.md#promotion-p43).

## 8. Lifecycle of a new version

1. **Edit.** Never edit an active version. Copy the latest one into
   `assistants/<name>/versions/<new>/` with its own instructions file and
   bump `metadata.version`: patch for a prompt or copy fix, minor for a new
   intent or variable. `hr-recruiter@0.1.1` is the worked example.
2. **Suite.** Add `assistants/<name>/eval/<version>/suite.yaml` and
   `fixtures.jsonl`, with `base.digest` set to the new definition's digest.
   Add fixtures for the behaviour you changed, with the right
   `expected_decision`.
3. **Pin.** Run `go test ./internal/assistant ./internal/agenteval`. The two
   immutability tests print the new definition and suite digests. Add them
   to `activeDigests` and `activeSuiteDigests`. Older versions' pins stay
   unchanged.
4. **C1.** Run the command in section 3 with `AGENT_C1_EVAL_PROMPT=catalog`
   and `AGENT_C1_EVAL_VERSION=<new>`, and put the summary (classification, terminal,
   leaks, binding, wrong auto-sends, cost, time) in the PR.
5. **PR and gate.** Normal review gate: CI green (including
   `assistant-materialize`), no open P1 or P2 findings.
6. **Merge.** Note the merge commit.
7. **Publish.** Follow the section 4 runbook with that commit.
8. **Verify.** In the catalog, `lifecycle: published` and the digest equal
   to the pin.
9. **Preview install (optional).** On tg-preview, install the new version on
   a test account with `install_assistant` or the manage page, or move an
   existing install with `update_install`
   (`{"assistant":{"version":"<new>"}}`). This moves the revision and fences
   old work.
10. **Deprecate the old version (optional).** Set it to `deprecated` once
    accounts have moved. Do not set it to `disabled` while an account still
    pins it, because its jobs stop within 5 minutes.
