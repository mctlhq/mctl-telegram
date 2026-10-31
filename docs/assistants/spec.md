# Assistant definitions (assistants.mctl.ai/v1alpha1)

Status: draft (P2 done, pending release). The server compiles the catalog in, an
account's install is applied through `PUT /api/admin/agent/install`, and
every claimed job carries its assistant's instructions. Of the P2 policy
settings, policy enforces the `never` tier, `outside_hours` schedules and
the audience scope so far; see [What the runtime enforces](#what-the-runtime-enforces) and
[Phases](#phases).

The communication agent that answers recruiters is the first of a family of
assistants a person can install into their own Telegram account. Today its
definition is spread across a global prompt (`AGENT_SYSTEM_PROMPT`), the
`agent_profiles` row, the encrypted owner profile, a fixed tool set in
`internal/agentworker/mcpserver.go` and floors in `internal/agent/policy`.
This document gives it one declarative shape, so that:

- a catalog can list assistants a user picks from;
- installing one is a document of values and overrides, validated before it
  is applied;
- the split between what the author decides, what the user may change and
  what the platform never lets either relax is written down, not implied.

## Two documents

Following ADR 007's definition / execution-profile split (mctl-agents), an
assistant is two documents:

| Document | Kind | Who writes it | Lifecycle |
|---|---|---|---|
| Definition | `TelegramAssistant` | assistant author | versioned (semver); a `draft` may still change under its version, an `active` one may not |
| Install | `AssistantInstall` | the account owner | one per account, pins an exact definition version |

Schemas: [`assistants/schemas/assistant.schema.json`](../../assistants/schemas/assistant.schema.json)
and [`assistants/schemas/assistant-install.schema.json`](../../assistants/schemas/assistant-install.schema.json)
(JSON Schema 2020-12). `internal/assistant` validates both, checks the install
against its definition and maps it onto today's profile.

Worked example: [`assistants/hr-recruiter/assistant.yaml`](../../assistants/hr-recruiter/assistant.yaml)
and [`install.example.yaml`](../../assistants/hr-recruiter/install.example.yaml).

## Definition

```yaml
apiVersion: assistants.mctl.ai/v1alpha1
kind: TelegramAssistant
metadata:      # catalog listing: name, title, description, version, owner,
               # visibility (public|tenant|admin), status (draft|active|deprecated),
               # tags, examples
spec:
  instructions: {path: ...}  # persona and workflow (markdown or text)
  variables: [...]           # what the install fills in
  intents: [...]             # reply intents, each with a tier
  tools: [...]               # subset of the platform tool registry
  records: {kind: job_lead}  # what the assistant saves
  escalation: [...]          # when the owner is pulled in
  defaults: {mode, limits, ceilings, disclosure}
  execution: {model, budgetUsd, timeoutSeconds}  # reserved, see below
```

**instructions.path** is relative to the definition's directory and may not
leave the repository. The recruiter agent's points at
`deploy/agent-worker/system-prompt.txt`, the file the Mac mini worker's
self-update also installs, so there is one copy of that prompt. Because a
`draft` definition's instructions can change under the same version, the
catalog computes a digest of the definition with its instructions (see
[Registry form](#registry-form)); the claim response reports it next to
`name@version`, so a job's behaviour is traceable to exact content, not
only to a version.

**execution** is reserved: the worker's model, budget and timeout still come
from its own environment. A definition that sets any of them cannot be
installed (`ErrUnsupported`), so nothing looks enforced that is not.

**variables** generalise the owner profile. Each has a `type` (string,
number, boolean, string_list), `required`, optional `choices`, and a
`profilePath` into the profile document (`identity.*`, `public_profile.*`,
`preferences.*`, `skills`, `restricted.*`). Ordinary fields carry a
`disclosure` level (public, after_owner_engaged, never) — the same levels
`internal/agent/profile` enforces. Restricted fields carry `send` instead
(`approval` or `never`): the value is never sent automatically and is used to
block a reply that would reveal it.

A variable without a `disclosure` gets the runtime's default level
(public for `identity.name`, `identity.role` and `skills`,
after_owner_engaged otherwise), and an install may only make it stricter.

**intents** are the controlled vocabulary of reply intents. `tier` says
what happens to a reply with that intent:

| Tier | Meaning | Today |
|---|---|---|
| `auto` | sent without the owner (guarded mode) | `intent_allowlist` |
| `approve` | waits for the owner's approval | every intent not in the allowlist |
| `never` | the assistant may not send it at all, not even with the owner's approval | `intent_denylist` |

`userOverride` limits what the install may change: `none`, `tighten`
(default: only towards approve/never) or `any`. The install changes settings
inside the envelope the author set and the platform enforces; it is not
always a tightening. `any` lets it loosen a tier, and a limit can rise from
its default up to the ceiling.

**defaults.ceilings** cap what an install may set; an install cannot raise a
limit above them. **defaults.disclosure.policy** is `required` (the user
cannot turn the "sent by an AI assistant" line off) or `optional`.

## Install

```yaml
apiVersion: assistants.mctl.ai/v1alpha1
kind: AssistantInstall
spec:
  assistant: {name: hr-recruiter, version: 0.1.0}
  mode: guarded            # observe | guarded | off; default: the definition's
  paused: false            # default: true
  listening: true          # default: false
  values: {...}            # variable values
  disclosureLevels: {...}  # per variable, stricter only
  intentTiers: {...}       # per intent, within userOverride
  limits: {...}            # at most the ceilings
  audience:                # Telegram chat-automation recipients model
    scope: {contacts, nonContacts, newChats, existingChats}
    onlySenders: [...]
    blockedSenders: [...]
  disclosure: {enabled, text}
  schedule: {mode: always | outside_hours, timezone, hours}
  ownerNotes: "..."        # the user's own instructions, max 2000 chars
```

`ownerNotes` are appended after the definition's instructions in a delimited
block, introduced as lower priority than everything before them; the notes
cannot close that block early. Variable values are never rendered into the
prompt: the model sees the owner's details only through
`get_recruiter_profile`, which returns what the current conversation may be
told. The owner's notes are the owner's own words and are rendered as
written, so they should not hold anything the owner would not want the model
to read.

An install that leaves out `mode`, `paused` or `listening` starts the way a
new account does today: in the definition's default mode, paused, and not
listening. Going live is an explicit change, never a side effect of a
minimal install.

## Who controls what

| Setting | Author (definition) | User (install) | Platform (never relaxable) |
|---|---|---|---|
| Persona and workflow | `instructions` | `ownerNotes`, appended below them | policy checks every proposed reply on the server, whatever the prompt says |
| Owner facts | which variables, default disclosure | values; disclosure only stricter | the model only sees fields the conversation may be told; a reply quoting a protected value verbatim is blocked |
| Reply intents | intents, default tiers, `userOverride` | tiers within `userOverride` | URL, credential, phone and code deny; injection handling |
| Tools | subset of the registry | — | tool registry, server-side validation |
| Limits | defaults and ceilings | any value up to the ceilings | 60 s rate window, fallbacks |
| Disclosure line | `required` or `optional`, default text | text and off switch, only if optional | — |
| Who it answers | — | audience scope, only/blocked senders | private chats only; groups and channels never |
| When it answers | — | schedule | takeover when the owner replies |
| Model and budget | `execution` (reserved) | — | the worker's per-job budget cap |

## What the runtime enforces

`PUT /api/admin/agent/install` (admin scope) takes
`{"telegram_id": ..., "install": {...}}`, validates the install against its
catalog definition, and writes in one UPDATE every profile setting it
resolves to, the owner profile, the assistant reference and the install
itself (tenant-key encrypted, like the owner profile). It replaces all of
them; `PUT /api/admin/agent/profile` remains for single-field changes.

Accounts that existed before the catalog are migrated by the column defaults:
`assistant_name` = `hr-recruiter`, `assistant_version` = `0.1.0`, no stored
install. Their jobs run exactly the prompt the worker used to read from
`AGENT_SYSTEM_PROMPT`.

`POST /jobs/claim` returns, per job, `instructions` (the rendered prompt),
`assistant` (`name@version`) and `assistant_digest`. They are resolved
before anything is claimed: if the account's assistant is missing from the
catalog or its stored install no longer parses, the claim fails and the jobs
stay queued, rather than running with another assistant's prompt. The worker
uses the server's instructions and falls back to its own
`AGENT_SYSTEM_PROMPT` only when a server without a catalog sends none. The
prompt reaches `claude` through `--system-prompt-file` (a 0600 temp file),
not argv, since it can carry the owner's notes.

### Install revisions

Every install, whether it reconfigures, re-versions or switches the
assistant, moves `agent_profiles.install_revision` in the same UPDATE as the
settings and records the definition's digest. A job takes the revision
current when it is claimed (the claim envelope carries it as
`install_revision`), and an action copies its job's revision, or the
profile's when it has no job. Work behind the current revision is refused:

- at propose (`propose_reply`, `request_owner_approval`,
  `send_owner_summary`), as the policy denial `install_changed`;
- at `/mctl approve`, which denies the draft and tells the owner the
  assistant or its settings changed since it was written;
- at send and at crash recovery, as the same policy denial.

The revision check is the source of truth. After an install the server
also denies proposed and approved actions from earlier revisions, but that
is cleanup: a race with it cannot let stale work act. Drafts awaiting the
owner's approval are left for `/mctl approve` to refuse, so the owner is
told the assistant changed rather than that the code was not found;
approval expiry clears the ones never approved. A job that is claimed
again after the change takes the new revision and runs with the new
assistant.

Switching to another assistant is therefore allowed. Its install time is
reset to the switch, so its new chats start then; a reinstall of the same
assistant keeps the first install time. Conversation transcripts stay as
account history: the new assistant can read earlier messages through
`get_conversation_context`, and nothing claims otherwise. Saved records
stay as they are; only `job_lead` exists today.

### Mapping

`assistant.Resolve` turns an install into profile settings, and
`assistant.ProfileRequest` into the body of `PUT /api/admin/agent/profile`.
A test applies the HR example through the real handler and checks the stored
profile equals the configuration the agent runs with today.

| Today | New field |
|---|---|
| `AGENT_SYSTEM_PROMPT` (global env) | definition `instructions` + install `ownerNotes`, per account, via the claim |
| `mode` | install `mode` |
| `autopilot_paused` | install `paused` |
| `listener_enabled` | install `listening` |
| `disclosure_text`, `disclosure_disabled` | install `disclosure` within definition `defaults.disclosure` |
| `max_autonomous_turns`, `max_msgs_per_minute`, `max_reply_chars` | install `limits` within definition `ceilings` |
| `intent_allowlist` (CSV) | intents whose resolved tier is `auto` |
| `intent_denylist` (CSV) | intents whose resolved tier is `never` |
| `working_hours` | install `schedule` with mode `outside_hours` |
| `sender_allowlist`, `blocked_senders` | install `audience.onlySenders`, `audience.blockedSenders` |
| `audience_excludes` (CSV) | install `audience.scope` classes set to `false` |
| owner profile document | install `values` placed by each variable's `profilePath` |
| owner profile `disclosure` map | variable `disclosure`, install `disclosureLevels` |
| fixed MCP tool set | definition `tools`, by canonical name or alias |
| `job_leads` table | definition `records.kind` |
| worker model and budget env | definition `execution` (reserved, rejected if set) |

Settings the runtime cannot enforce yet fail with `ErrUnsupported` instead of
being dropped: record kinds other than `job_lead` and any `execution`
setting. A tool subset is enforced (see [Tool names](#tool-names)). An install is applied entirely or not at all.

The guarantee is about this mapping: every setting either reaches the
profile or the install fails. It does not extend to the definition's
descriptive parts (`escalation`, `examples`), which document behaviour the
instructions produce and are not enforced on their own.

## Schedules

`schedule.mode: outside_hours` names the owner's working hours, when the
owner answers messages personally:

```yaml
schedule:
  mode: outside_hours
  timezone: Europe/Zurich          # IANA zone, required
  hours: [mon-fri 09:00-18:00, sat 22:00-02:00]
```

Inside those hours every reply the assistant proposes waits for the owner's
approval, whatever its intent tier; outside them the usual rules apply.
Policy checks this when a reply is proposed and again at send time, so a
reply allowed at 17:55 and still queued at 18:05 is not sent on its own:
the executor refuses an automatically allowed reply that now needs
approval. Messages that arrive inside working hours are therefore never
held and replayed in a burst when the hours end; each becomes a draft for
the owner.

- The windows follow the zone's wall clock, so they move with DST.
- A window whose end is not after its start runs past midnight and belongs
  to the day it starts on: `sat 22:00-02:00` covers Saturday night and the
  first two hours of Sunday. Day ranges may wrap (`fri-mon`); `24:00` is
  allowed as an end.
- Changing the zone or the hours is a reinstall; the next evaluation uses
  the new value.
- `always`, or no schedule, means no working hours. A `timezone` or `hours`
  given with `always` is rejected rather than ignored.
- A stored value that fails to parse holds every reply for approval
  instead of letting the assistant act at any time; the admin endpoints
  refuse to store one.

## Audience

`audience.scope` turns classes of chats off; every class is on by default:

```yaml
audience:
  scope: {contacts: true, nonContacts: true, newChats: false, existingChats: true}
```

- **Contacts** are judged by the contact flag Telegram sends with each
  inbound message and stored on the conversation. Removing someone from
  contacts takes effect with their next message, not instantly.
- **Existing chats** are conversations the agent first saw before the
  assistant was installed, plus any chat with a contact. **New chats** are
  everything else. The install moment is stamped on the first install and
  kept on reinstalls of the same assistant, so it does not move.
- Limitation: a chat that began before the install but that the agent never
  saw (the listener was off) has no conversation row from before the
  install and therefore counts as new.
- A chat outside the scope never becomes a job: the listener keeps its
  conversation row and contact flag, so the class stays decidable, but
  stores no message body and spends no model run. Policy checks the scope
  again before every proposal and send (`audience_excluded`), so a peer who
  drops out mid-conversation gets no further replies.
- What the decision needs but cannot see excludes rather than admits: an
  unknown contact status when contacts matter, a missing install time, or a
  class the runtime does not know. Turning off both halves of a pair
  (`contacts` and `nonContacts`, or `newChats` and `existingChats`) answers
  nobody and is rejected.
- `blockedSenders` always wins; an empty `onlySenders` means everyone.

## Tool names

The worker implements eleven tools. Three carry recruiter-specific names,
and a definition may call them by a generic alias instead:

| Canonical | Alias |
|---|---|
| `get_recruiter_profile` | `get_owner_profile` |
| `get_lead` | `get_record` |
| `save_job_lead` | `save_record` |

Each claimed job carries the definition's tool names (`tools` in the
envelope). The worker allows exactly those names on the `claude` command
line and registers each tool under its name in the job's MCP server; the
implementation behind an alias is the same tool. A job from a server
without a catalog carries no names and gets the canonical ones.

A definition names each tool at most once: naming both a tool and its alias
is an error, and so is an unknown name. It may name a **subset** of the
tools, which must include `get_event` and `complete_agent_job`: a job cannot
read its message without the first or finish without the second, so a
definition that leaves either out is refused when it is parsed.

A subset is enforced server-side, not only by what the model is shown
(#1041). The claim resolves the definition's tool set to canonical names and
signs it into the job token as the claim `job_tools`, so a worker cannot
widen it without breaking the signature. Each agent API route a tool calls
is mapped to its tools (`internal/agent/tools.Endpoints`):

| Route | Tools |
|---|---|
| `GET /event/{eventID}` | `get_event` |
| `GET /conversations/{id}/context` | `get_conversation_context` |
| `GET /conversations/{id}/leads` | `get_lead` |
| `GET /leads/{id}` | `get_lead`, `get_conversation_context` |
| `GET /recruiters/{peer}` | `get_recruiter_profile` |
| `GET /policy` | `get_policy` |
| `POST /actions/propose_reply` | `propose_reply` |
| `POST /leads` | `save_job_lead` |
| `POST /actions/request_owner_approval` | `request_owner_approval` |
| `POST /notify/summary` | `send_owner_summary` |
| `POST /autopilot/pause` | `pause_autopilot` |
| `POST /jobs/{id}/complete` | `complete_agent_job` |

`get_lead` reads `GET /conversations/{id}/leads`, bound to the job's own
conversation, which returns the conversation's leads and no messages
(#1043). A tool set with `get_lead` but without `get_conversation_context`
therefore reads leads and nothing of the conversation; the context route,
which returns the leads too, serves `get_conversation_context` alone. A
worker that meets a server without the leads route falls back to the
context route, which the gate still decides on.

A request to a route none of whose tools is in the caller's set is refused
with 403 `{"error":"tool_not_allowed","tool":"<canonical name>"}`, audited as
denied, and counted as the policy denial `tool_not_allowed` on surface
`tool_gate`. A forged MCP config, or a direct request with the job's own
token, reaches no further than the definition allows. Routes that serve no
tool (`POST /jobs/claim`, `GET /events`, `GET /jobs/{id}`,
`POST /jobs/{id}/cost`) and the routes of the mandatory tools are not gated.

An account-wide worker token carries no tool set. For it, and for a job
token minted before `job_tools` existed, the set is resolved on each request
from the account's installed definition, the same one a claim would bind
(without the registry lifecycle gate, which decides whether jobs start, not
what they may call). An account with no configured assistant, or a server
without a catalog, has every tool. A definition that cannot be resolved
refuses the gated routes with 503 rather than allowing every tool.

## Registry form

The registry (mctl-api, P3) stores an assistant in its **materialized**
form: the definition document with `spec.instructions.path` replaced by
`spec.instructions.text`, the full system prompt, encoded as canonical JSON:
object keys sorted by byte order, no whitespace between tokens, strings
escaped only where JSON requires it (`"`, `\`, control characters; `<`, `>`
and `&` stay literal), except U+2028 and U+2029, which are always written
as `\u2028` and `\u2029`; integers without a fraction, UTF-8, no trailing
newline. A document or instructions file that is not valid UTF-8 is
refused, never repaired. An authored definition
in this repository names its instructions by path; a materialized one
carries the text and no path, so it is complete without the repository.

- **Digest.** `sha256:` and the hex SHA-256 of the canonical materialized
  JSON. Re-encoding any copy of the document (pretty-printed, keys in
  another order) gives the same bytes and the same digest, so mctl-telegram
  recomputes it from a fetched copy instead of trusting a stored value. The
  claim's `assistant_digest` and the profile's
  `assistant_definition_digest` use this form. (Before P3.2 the digest was
  taken over the authored YAML and the instructions file; the value for
  `hr-recruiter@0.1.0` changed once with that switch.)
- **Building.** `go run ./cmd/assistant-materialize -out dist/assistants`
  writes `<name>-<version>.json` for every catalog assistant and prints its
  digest, after checking that each document parses back
  (`assistant.ParseMaterialized`) to the same digest. CI runs it on every
  build and keeps the output as the `assistants-materialized` artifact.
- **Visibility.** P3 serves `public` and `admin` only. `tenant` needs a
  tenant-binding model that does not exist yet, so a tenant-visible
  definition is refused when the catalog loads and when a materialized
  document is parsed.
  Account-private forks (P4) are not registry entries; see
  [adr-forks.md](adr-forks.md).
- **Status and lifecycle.** The registry's own lifecycle has three states
  (`published`, `deprecated`, `disabled`), and a new version is always
  `published`. Whether the public catalog offers an assistant is decided by
  the definition's `metadata.visibility` (only `public`) and
  `metadata.status` (not `draft`); the registry lifecycle then decides
  whether it can be installed (`published`), kept by an existing pin
  (`deprecated`), or must stop (`disabled`).
- **Active versions are immutable.** A `draft` may change under its
  version; an `active` one may not, since installs pin it and the registry
  holds it. `TestActiveVersionsAreImmutable` pins every active version's
  digest, so editing an active definition or its instructions (for
  `hr-recruiter`, `deploy/agent-worker/system-prompt.txt`) fails CI until the
  change ships as a new version. `hr-recruiter@0.1.0` is `public` and
  `active` since P3.2.
- **Install from the registry (P3.4).** With `ASSISTANT_REGISTRY_ENABLED`
  on, an install fetches
  `GET /api/v1/assistant-catalog/{name}/versions/{version}/definition` from
  mctl-api as the `surface:telegram` principal, canonicalizes the returned
  definition with `assistant.ParseMaterialized` and refuses it unless the
  recomputed digest equals the registry's `contentHash`. A new install needs
  lifecycle `published`; `deprecated` is accepted only for the name@version
  the account already runs; `disabled` is refused. The definition is stored
  in `assistant_definitions` (keyed by digest) in the same transaction as
  the profile UPDATE that moves the install revision and pins the digest.
  Install answers `404` for an unknown version, `409` for a lifecycle it may
  not take, `502` for a digest mismatch or an invalid document, and `503
  assistant registry unavailable` when the registry cannot be read (network
  error, 5xx, auth failure, or a 404 without `assistant_not_found`).
- **Claims.** A claim renders from the stored definition whose digest the
  profile pins and never calls the registry, so a restart with mctl-api
  down serves every installed assistant. The embedded catalog is a bridge
  for migration and rollback only: it serves a profile that pins no digest
  yet, or pins exactly the embedded entry's digest (`hr-recruiter@0.1.0`).
  A pinned digest with neither a stored definition nor a matching embedded
  entry fails the claim (`500`), leaving the jobs queued. The one
  exception is hr-recruiter@0.1.0's digest in the scheme used before P3.2,
  which installs made between P3.1 and P3.2 carry: a migration clears that
  exact value, so those accounts take the embedded catalog.
- **Staleness (P3.4).** Every 5 minutes the server reads the lifecycle of
  each stored definition a profile pins and records it with the time of the
  read. A `404 assistant_not_found` for a pinned version is an answer and is
  recorded as `disabled`; a network error, a timeout, a 5xx or any other
  answer is a failed read and changes nothing, so a known lifecycle is
  never replaced by an unknown one. At claim time `disabled` stops new jobs
  (`503`, jobs stay queued), so a disable takes effect within one refresh.
  `deprecated` keeps running for pinned installs. If the last successful
  read is older than 24 hours, the lifecycle is unknown; unknown is not
  `published`, so new jobs stop the same way and the owner gets one alert
  per outage saying the registry could not be reached. The lifecycle gate
  applies only while `ASSISTANT_REGISTRY_ENABLED` is on; with it off,
  claims still render from stored definitions but no lifecycle is read or
  enforced.
- **Publishing.** In P3 it is manual and transitional: the owner publishes
  the CI artifact through the human-admin mctl-api tool, with the digest as
  the version's `contentHash`. A narrow publisher principal that may only
  publish immutable `TelegramAssistant` versions from this repository is a
  follow-up.

## Forks

P4.2 (#1043) lets an account owner make a **private fork** of a catalog
assistant: their own instructions, fewer tools, stricter intents, lower
limits. The model and its reasons are in [adr-forks.md](adr-forks.md); this
section is what the code does. Everything here is off unless
`ASSISTANT_FORKS_ENABLED` is set, and turning it off also stops the jobs of
every account that runs a fork; `delete_fork` keeps working.

**Document.** A fork version is a complete `TelegramAssistant` in
materialized form, so it parses, canonicalizes and hashes with the same
functions as a catalog version (`assistant.ParseMaterialized`). It is the
base's document with the fork's changes applied and:

- `metadata.name` `<base>~<owner-scope>~<slug>`. The owner scope is 10
  characters of lowercase base32 of the server's keyed HMAC of the account
  id; the slug is the user's, `^[a-z0-9][a-z0-9_-]{0,31}$`. A catalog name
  cannot hold `~`.
- `metadata.owner` `acct:<owner-scope>`, `visibility: private`,
  `status: active`, and `metadata.fork.base` `{name, version, digest}`, the
  catalog version it narrows. The parser accepts a `~` name only with
  `metadata.fork` and `private`, and refuses either without the other; the
  catalog refuses to load a fork.

**Rules.** `assistant.ValidateFork(base, fork)` holds every version to its
base, on top of the checks every definition passes:

| Part | A fork may |
|---|---|
| instructions | replace them; at most 16 KiB of UTF-8, without the `owner_notes` markers. `ownerNotes` are still appended below. |
| intents | leave one out; make a tier stricter (`auto` → `approve` → `never`) and `userOverride` narrower (`any` → `tighten` → `none`); add one at `approve` or `never`, never `auto`. An intent the base has keeps its description. |
| tools | name a subset of the base's, by canonical name or alias, still with `get_event` and `complete_agent_job`. The tool gate enforces it. |
| limits, ceilings | lower them: each at most the base's ceiling. |
| disclosure | make the policy `required`; never `optional` where the base requires it. The text is the base's. |
| variables | make a variable's default disclosure stricter; nothing else. |
| everything else | nothing: records, escalation, tags, examples, `defaults.mode` and the reserved `execution` are the base's. |

**Versions.** A fork version is immutable and numbered by the server: a new
fork is `0.1.0`; an edit is a **patch** when only the instructions changed
and a **minor** when anything else did (the authority diff). An edit that
changes nothing is refused.

**Storage.** `assistant_forks` holds one row per version: `user_id`, name,
version, digest, the base's name, version and digest, the document sealed
with the owner's per-user key, `promotion` (`observe`) and `created_at`. It
is read only by `(user_id, digest)` or `(user_id, name)`, never across
accounts, and the account purge deletes it. Writes take a lock on the
account, under which the quotas hold: at most **10 forks** per account and
**50 versions** per fork. A write past either is refused with `fork_limit`
and changes nothing.

**Install.** `install_assistant` and `update_install` name a fork by its
full name and version, through the same `assistantinstall` service. Only
the owner can install it: the service resolves forks only for the calling
account, the admin route (which installs for another account) never
resolves one, and the store checks the fork row under the account lock in
the install transaction, so a concurrent delete cannot leave the pin
pointing at nothing. The base's lifecycle is read as for a catalog install
(the registry with `ASSISTANT_REGISTRY_ENABLED`, else the embedded
catalog), and the base's snapshot is stored with the install. The profile
pins the fork's name, version and digest and moves `install_revision` as
for any install.

**Observe only.** A fork version starts in `observe`, and in P4.2 nothing
promotes one: promotion to `guarded` is P4.3 (#1044) and a human step, not
an MCP tool. An install or `update_install` that resolves a fork to
`guarded` is refused. The claim refuses a fork account whose mode column is
`guarded` (503, jobs stay queued), and the policy engine evaluates `guarded`
on a fork as `observe`, so no write path to the mode column can make a fork
auto-send.

**Claim.** The claim resolves a fork from `assistant_forks` by
`(user_id, digest)`, decrypts it with the owner's key (forks are not
cached), checks its digest and that it still narrows its base, and renders
it with `ownerNotes` as usual. The fork's lifecycle is its base's: with the
registry on, the refresh reads the base of every pinned fork and the claim
gates on the base's stored lifecycle, so disabling the base stops every
fork of it within one refresh. The job token binds the fork's tool subset.

**Notices and audit.** Every fork write queues an owner alert in the bot
chat in the same transaction, naming the fork, version and digest, and is
audited with the same reference. No output, log line, audit row or notice
carries the instructions.

## MCP tools

P3.5 (#1021) lets the account owner manage their own install from an MCP
client. The three tools and `PUT /api/admin/agent/install` call one service,
`internal/assistantinstall`, so resolving the definition, the lifecycle
gate, the snapshot and the revision move happen in one place; the web pages
(P3.6, see [Web pages](#web-pages)) call it too. Every tool acts on the caller's own account and has
no `telegram_id` argument. They refuse when `AGENT_ENABLED` is off.

- **`list_assistants`** (any signed-in connection) returns `source`
  (`registry` with `ASSISTANT_REGISTRY_ENABLED`, read from
  `GET /api/v1/assistant-catalog`; else `embedded`, the public, non-draft
  entries of the built-in catalog), `assistants` (name, version, title,
  description, tags, examples, lifecycle, variables with name, type, required,
  choices, description and, from the registry, a non-secret default;
  intents with their default tier; defaults: mode, limits, disclosure
  policy), `mine`: `{assistant, version, install_revision, installed}`, and
  `forks`: the caller's own forks, never anyone else's, each
  `{name, base, latest, versions: [{name, version, digest, base,
  promotion}]}`. It never returns stored values, owner notes, instructions,
  tools or profile paths.
- **`install_assistant`** (`account:manage`) takes the exact `name` and
  `version` (no "latest": the schema requires `MAJOR.MINOR.PATCH`),
  `values`, any of the install settings (`mode`, `paused`, `listening`,
  `limits`, `intentTiers`, `disclosureLevels`, `audience`, `disclosure`,
  `schedule`, `ownerNotes`) and an optional `expected_revision`. It builds a
  whole AssistantInstall from them, leaving omitted settings omitted, so a
  new install starts paused and not listening as [Install](#install) says.
  `name` may be the full name of one of the caller's forks; see
  [Forks](#forks).
- **`update_install`** (`account:manage`) takes a `patch`, an RFC 7396 JSON
  merge patch over the stored install's `spec`, and a required
  `expected_revision`. The server decrypts the stored install, applies the
  patch, validates the result as a whole install against its definition and
  saves it. Patching `assistant.name` or `assistant.version` switches or
  upgrades through the same path as an install. The client never reads
  private values back to change one setting.

Every install, the admin route's included, is a compare-and-set: the
profile UPDATE carries `install_revision = expected` in its `WHERE`, inside
the same transaction as the definition snapshot, and a miss changes nothing.
`expected` is the caller's `expected_revision` or, without one, the
revision the service read when it decided the lifecycle and visibility
gates, so a concurrent install cannot slip under them. An account with no
agent profile yet reports `install_revision` 1, the revision its profile
starts at. They
answer `{assistant, version, install_revision, settings}`, where `settings`
is what the install resolved to (mode, paused, listening, disclosure,
limits, auto and never intents, working hours, audience exclusions, sender
list sizes), never the values or notes. A successful write moves the
revision, so work queued under the earlier one is fenced as in
[Install revisions](#install-revisions).

Self-service installs are limited to what `list_assistants` offers: a
`public`, non-draft definition. The one exception is the name@version the
account already runs, which its owner may keep reconfiguring, the same rule
that keeps a `deprecated` version installable for its existing accounts. The
admin route has no such limit.

Errors are a JSON envelope `{error, message, retryable, current_revision?}`:

| `error` | When |
|---|---|
| `invalid_install` | the install, or the patched one, does not validate; a schema failure names the location and rule, never the value |
| `assistant_not_found` | no such name@version for this caller |
| `lifecycle_refused` | `disabled`, or `deprecated` for an account not already running it |
| `revision_conflict` | the install is no longer at `expected_revision`; carries `current_revision` |
| `no_install` | `update_install` on an account with no stored install |
| `registry_unavailable` | the registry could not be read; `retryable: true`, nothing changed |
| `registry_invalid` | the registry answered a definition or catalog that failed its checks |
| `internal_error` | a database or encryption fault |

Audit rows record the error kind only, never the message.

The fork tools (P4.2, #1043) are self-only and need `account:manage` too.
They refuse with `forks_disabled` while `ASSISTANT_FORKS_ENABLED` is off,
except `delete_fork`. None returns a fork's instructions.

- **`fork_assistant`** takes `base` and `base_version` (resolved as an
  install would: the registry's lifecycle, `published`, or `deprecated` only
  for the version the account runs), `slug`, and the changes:
  `instructions`, `intents`, `tools` (each list replaced as a whole),
  `limits` and `ceilings` (complete objects) and `disclosure_policy`. It
  answers `{name, version, digest, base: {name, version, digest},
  promotion}`.
- **`update_fork`** takes the fork's full `name` and the same changes, and
  writes the next version on top of the latest one, numbered as in
  [Forks](#forks). It answers the same with `bump` (`patch` or `minor`). It
  does not move the install: the owner installs the new version.
- **`delete_fork`** takes `name` and an optional `version` (without it,
  every version) and answers `{name, version?, deleted_versions}`. The
  version the install pins is never deleted.

Their errors use the same envelope, with four more codes:

| `error` | When |
|---|---|
| `fork_limit` | 10 forks per account or 50 versions per fork; nothing changed |
| `fork_conflict` | `fork_assistant` on a name that exists, or the fork moved while `update_fork` was prepared; `retryable: true` |
| `fork_in_use` | `delete_fork` of the version the install pins; nothing deleted |
| `forks_disabled` | `ASSISTANT_FORKS_ENABLED` is off |

A fork rule broken is `invalid_install`, whose message names the rule. The
audit row of a successful write names `fork:<name>@<version> <digest>`.

## Web pages

P3.6 (#1022) puts the same catalog and install on tg.mctl.ai. Both pages
exist only with `AGENT_ENABLED`, and both call `internal/assistantinstall`,
so they have no semantics the MCP tools do not have.

- **`/assistants`** is public and read-only. It lists exactly what
  `list_assistants` lists, from the same `ListCatalog` call: per entry the
  title, description, `name@version`, tags, examples, lifecycle, the
  variables (name, type, choices, required, description, and a registry
  default where the registry gives one; it gives none for a secret
  variable), the intents with their default tier, and the defaults (mode,
  limits, disclosure policy). It is server-rendered and needs no
  JavaScript. A registry that cannot be read answers `503` with an explicit
  "catalog unavailable" section, never an empty catalog.
- **The assistant section of `/telegram/connect/manage`** (local-jwt only,
  like the rest of the page) shows the caller's install: `name@version`,
  install revision, mode, paused, listening and the same settings summary
  the MCP tools answer. It never shows values, owner notes or
  instructions, and a failed read shows neither an install nor "none
  installed". With `account:manage`, exactly as the MCP write tools
  require (the browser sign-in exception that lets disconnect through does
  not apply), it offers HTML form posts:
  - `POST /telegram/connect/manage/assistant/install`: one form per catalog
    version, with an empty input per variable (never prefilled). It is
    `Apply` with `SelfService`, building the install the way
    `install_assistant` does, with `paused` and `listening` left out so the
    install starts paused and not listening.
  - `POST /telegram/connect/manage/assistant/update`: pause or unpause,
    listening on or off, and mode. Each is `Patch` with a one-member merge
    patch (`{"paused": false}`, `{"listening": true}`, `{"mode":
    "guarded"}`); anything else is refused with `400`.

  Every form carries the revision the page was rendered at as
  `expected_revision`. A conflict re-renders the page with `409`, the
  current install and a message that nothing changed; other refusals
  re-render it with the service's message (never `Detail`) and a matching
  status. Cross-site submission is refused by the `SameSite=Lax`
  connect-session cookie, as for the other manage forms. Each submission
  writes an audit row with the error kind only.

## Customization tiers

| Tier | The user | Gate |
|---|---|---|
| T0 Install | picks a catalog assistant, fills the required values | schema validation |
| T1 Tune | mode, tiers (tighten), limits, audience, schedule, disclosure, `ownerNotes` | schema and definition checks |
| T2 Fork | own instructions, stricter intents, a tool subset and lower limits on a catalog base (P4.2, see [Forks](#forks)); records inherited ([adr-forks.md](adr-forks.md)) | private visibility; observe mode only until P4.3 promotion |
| T3 Connectors | adds MCP servers (calendar, CRM), each tool with a tier, approve by default | admin review |
| T4 Own runtime | runs their own worker against the agent job API (claim, propose, complete) | account-scoped token; policy enforced server-side |

## Phases

- **P0 (done, #1003):** format, schemas, HR example, validation and mapping
  tests, this document.
- **P1 (done, #1005, 0.112.0):** the profile row gets `assistant_name`,
  `assistant_version` and an encrypted install; `PUT /api/admin/agent/install`;
  the claim response carries the rendered instructions (definition +
  `ownerNotes`, never variable values) and a content digest; existing
  profiles default to `hr-recruiter@0.1.0`.
- **P2:** tiers including `never` (done: a reply whose intent is on the
  profile's `intent_denylist` is denied when proposed and again at send
  time, and no approval releases it), the audience scope and schedules in
  `policy.go` (both done: see [Schedules](#schedules) and
  [Audience](#audience)); `/mctl` gets unpause and shows the install (done:
  `/mctl unpause`, `/mctl assistant`); recruiter-specific
  tool names get generic aliases (done: see [Tool names](#tool-names)).
- **P3:** definitions published to the mctl-api agent registry, a
  per-account install binding, MCP tools `list_assistants`,
  `install_assistant`, `update_install`, and a page on tg.mctl.ai.
- **P4:** forks, user connectors with review, own-runtime documentation.
  The fork model and the storage of private definitions (in mctl-telegram,
  encrypted per account) are decided in [adr-forks.md](adr-forks.md)
  (P4.1, #1042; accepted 2026-10-31). Forks are implemented (P4.2, #1043:
  see [Forks](#forks)); promotion to guarded is P4.3 (#1044).

## How this compares

The product is not "AI that answers Telegram messages"; Telegram itself now
offers that. It is a governed delegation runtime: the author defines an
envelope, the owner configures inside it and may only tighten, the runtime
enforces rules neither can relax, and every action is checked against the
current install revision before it is sent. The comparison is split by what
each product is to that thesis. Facts were checked against public,
preferably first-party documentation on 2026-10-31; a cell reads "not
verified" when documentation does not settle it, never "no".

### Telegram Chat Automation (official)

Since 2026-05-07 every Telegram user can connect a bot to their profile to
answer messages on their behalf (Settings > Chat Automation; Telegram blog
"AI bot revolution"), and since Bot API 10.0 (2026-05-08) a business bot does
not need Telegram Premium. It is a real personal-account delegation
primitive, with a narrower envelope than this runtime's MTProto path:

| Dimension | Chat Automation | Source |
|---|---|---|
| Acts in the owner's personal account with third parties | yes: private chats, `can_reply` covers chats "that had incoming messages in the last 24 hours" | Bot API `BusinessBotRights` |
| Audience | yes: the owner picks the chats at connection time, e.g. excluding contacts or only new chats | Telegram blog, 2026-05-07 |
| Tell the bot's own sends apart | yes: `Message.sender_business_bot` on outgoing messages sent by the bot | Bot API `Message` |
| Owner takeover | not verified: documentation does not say whether the owner's own manual messages reach the bot as `business_message` | spike in #1026 |
| History, groups, channels, global search | no: managed private chats only | Bot API, Bot Features |
| Bot-to-bot | yes, opt-in; Telegram requires loop safeguards (dedup, rate limits, maximum depth or timeouts) | Bot Features, "Bot-to-Bot Communication" |
| Versioned definitions, tighten-only installs, per-intent tiers, revision fence | no: the platform provides the connection; any policy is the bot's own | |

Its risk profile differs from MTProto: an official API with no user session
held by the operator, so materially lower platform and account risk, while a
bot remains subject to Telegram's platform rules and Bot Developer Terms
(section 5.4 for business bots). Whether it can serve as a transport for
these assistants without weakening the guarantees above is the subject of
the spike tracked in #1026, outside P3.

### Direct alternatives: delegating a Telegram identity

All three are self-hosted, MIT-licensed open-source projects. SmarTel
(github.com/AliZakaee/SmarTel; its README also names ITheEqualizer/SmarTel)
and tg-secretary (github.com/sepehr071/tg-secretary) connect as business
bots; Iva (github.com/smixs/iva-agent) runs an MTProto userbot. Sources are
each project's README and docs as of 2026-10-31.

| Dimension | MCTL | Chat Automation | SmarTel | tg-secretary | Iva |
|---|---|---|---|---|---|
| Transport | MTProto, server-held session | business bot | business bot | business bot | MTProto userbot, self-hosted |
| Replies to third parties autonomously | yes | yes (the bot's logic) | yes, opt-in | yes | not verified (sends found only in owner-started or scheduled turns) |
| History, groups, channels, search | yes | no | no | no | yes |
| Versioned assistant definition with digest | yes | no | not verified | not verified | not verified |
| Author envelope, installer may only tighten | yes | no | not verified | not verified | not verified |
| Approval before send | per intent: `auto` / `approve` / `never` | no | global mode; sensitive topics forced to approval | global mode; close-contact gate | global read-only switch |
| Owner takeover | yes | not verified (see above) | yes, 30 min pause | yes, cooldown and re-check before send | not verified |
| Approval bound to the install revision | yes (#1023, not yet released) | no | not verified | not verified | not verified |
| Per-field disclosure of owner details | yes | no | not verified | not verified | not verified |
| AI disclosure line to the counterparty | yes, required or optional per assistant | no | not verified | no, by design | not verified |
| Audience scope | yes | yes | partial (Telegram chat selection) | partial (chat selection, relationship tags) | not verified |
| Working hours | yes | no | not verified | yes | not verified |
| Conversation limits | turns and rate per conversation | no | 20 messages per customer per hour | delays and a spend cap | anti-flood pacing only |

In the Chat Automation column, "no" means the platform does not provide it;
a connected bot may implement it itself, as the next two projects do.

The two business-bot projects implement a takeover pause, which suggests the
owner's activity is observable through the business connection; the spike
in #1026 confirms that against Telegram itself before the official column
changes.

### Benchmarks for packaging and isolation

OpenClaw with its ClawHub registry (docs.openclaw.ai) and NanoClaw
(github.com/nanocoai/nanoclaw) are not substitutes for delegating a
Telegram identity; both connect to Telegram as an ordinary bot. They set the
bar for distributing and running agent packages:

| Dimension | ClawHub / OpenClaw | NanoClaw |
|---|---|---|
| Versioned, immutable releases | yes (semver, changelogs, compatibility metadata) | partial (templates, no registry) |
| Integrity digest | partial (plugins) | not verified |
| Security scan, moderation | yes (scan state shown before install) | not verified |
| Publisher provenance | partial (GitHub account-age gate) | not verified |
| Update that respects local changes | yes (lockfile, pins, refuses over modified files) | yes (dry-run plan flags customized files) |
| Permission or authority diff on update | not verified | partial (per-surface plan, not framed as authority) |
| Runtime isolation | partial (sandbox off by default) | yes (container per agent) |
| Credentials kept out of the agent | partial | yes (injected by a gateway at request time) |

What this runtime takes from them for P3 and later: immutable versions with
a digest (done in P3.2), scan and provenance before third-party publishers,
and an update that shows how authority changes rather than a text diff.

### Design precedents

Formats and products that informed this one; they are not competitors for
delegating a person's own account:

| Product | What we took | What it lacks for this use |
|---|---|---|
| Microsoft 365 declarative agents | instructions + capabilities + disclaimer; user overrides that can only remove | runs in the user's own chat, not on their behalf with third parties |
| Claude subagents, Agent Skills | markdown instructions with frontmatter, tool lists | no owner, counterparty or disclosure model |
| OpenAI GPT Actions, Lindy, Relevance, n8n | per-tool approval: auto, approve, never | approval is per tool, not per reply intent |
| Voiceflow, Respond.io, Wati | exit conditions, handoff with a summary | business inboxes, not a person's account |
| MCP `server.json`, Oracle Agent Spec, Letta `.af` | typed variables, secrets kept out of the definition | no catalog-to-account install step |
| A2A agent card | public listing: name, version, examples | describes an agent to other agents, not to an owner |

### What the combination is

Among the products reviewed here, we did not find another documented system
combining all of: delegation through a personal account; an author-defined
authority envelope; owner-side tightening only; platform rules neither can
override; per-intent `auto` / `approve` / `never`; per-field disclosure of the
owner's details; owner takeover; refusal of work from an older install
revision (#1023, merged, not yet released); and a policy re-check at send
time. This compares documented features of the products named here, not the
whole market. Known limits stay as stated above: protected values are
guarded by context filtering and an exact-value match, which does not catch
paraphrase or translation, and a reply mixing intents is judged by the
model's single label (#602).

## Acceptance scenarios for later phases

These cases come from review of the format and must have tests before the
features they touch go live. None is a known defect today.

1. The owner replies while a reply is being prepared or sent: takeover is
   checked again at send time, and pending drafts and approvals for that
   chat are invalidated. A message Telegram has already accepted cannot be
   recalled.
2. A stale approval: an approval binds to account, peer, payload, install
   revision and an expiry; policy is evaluated again at send time.
3. `after_owner_engaged` after a takeover and resume: the scope and lifetime
   of engagement are defined, per conversation and per assistant.
4. Switching assistants: an atomic revision change, cancellation of
   incompatible jobs, and rules for carrying history over. (Covered since
   P3.1, see [Install revisions](#install-revisions): stale work is fenced
   by revision, open actions are denied as cleanup, history stays.)
5. A reply that mixes intents ("thanks, Tuesday works, €X is fine"): the
   strictest applicable tier wins; a model-chosen intent is not evidence of
   safe content; an unknown intent is never sent automatically.
6. A retried job after an ambiguous send result: a stable action id and an
   "outcome unknown" state, never a second message.
7. Audience changes mid-flight (blocked, removed contact, outside hours):
   eligibility is checked at send time; blocked wins; empty `onlySenders`
   means everyone; "new chat" is defined against a fixed moment. (Covered
   since P2, see [Audience](#audience).)
8. Schedules across midnight and DST, and a change of timezone; messages
   that arrive outside the window are skipped, queued or escalated by an
   explicit rule, never replayed in a burst. (Covered since P2: the rule is
   escalate, see [Schedules](#schedules).)
9. Account-level limits: a spend budget, concurrency, owner-notification
   rate and a circuit breaker for bot-to-bot loops, beyond per-conversation
   limits.
10. Protected facts already present in history, records or summaries: the
    verbatim matcher does not catch paraphrase or translation, so promises
    about disclosure are scoped to what the matcher and context filtering
    actually cover.
