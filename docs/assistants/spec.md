# Assistant definitions (assistants.mctl.ai/v1alpha1)

Status: draft (P0). The format is defined and validated, and the HR agent is
expressed in it. The runtime does not read it yet; see [Phases](#phases).

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
| Definition | `TelegramAssistant` | assistant author | versioned (semver), immutable once published |
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
  execution: {model, budgetUsd, timeoutSeconds}
```

**variables** generalise the owner profile. Each has a `type` (string,
number, boolean, string_list), `required`, optional `choices`, and a
`profilePath` into the profile document (`identity.*`, `public_profile.*`,
`preferences.*`, `skills`, `restricted.*`). Ordinary fields carry a
`disclosure` level (public, after_owner_engaged, never) — the same levels
`internal/agent/profile` enforces. Restricted fields carry `send` instead
(`approval` or `never`): the value is never sent automatically and is used to
block a reply that would reveal it.

**intents** are the controlled vocabulary of reply intents. `tier` says
what happens to a reply with that intent:

| Tier | Meaning | Today |
|---|---|---|
| `auto` | sent without the owner (guarded mode) | `intent_allowlist` |
| `approve` | waits for the owner's approval | every intent not in the allowlist |
| `never` | the assistant may not send it at all | not expressible yet (P2) |

`userOverride` limits what the install may change: `none`, `tighten`
(default: only towards approve/never) or `any`.

**defaults.ceilings** cap what an install may set; an install cannot raise a
limit above them. **defaults.disclosure.policy** is `required` (the user
cannot turn the "sent by an AI assistant" line off) or `optional`.

## Install

```yaml
apiVersion: assistants.mctl.ai/v1alpha1
kind: AssistantInstall
spec:
  assistant: {name: hr-recruiter, version: 0.1.0}
  mode: guarded            # observe | guarded | off
  paused: false
  listening: true
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

## Who controls what

| Setting | Author (definition) | User (install) | Platform (never relaxable) |
|---|---|---|---|
| Persona and workflow | `instructions` | `ownerNotes` appended below (P1) | safety rules prepended, override both |
| Owner facts | which variables, default disclosure | values; disclosure only stricter | restricted values never auto-sent |
| Reply intents | intents, default tiers, `userOverride` | tiers within `userOverride` | URL, credential, phone and code deny; injection handling |
| Tools | subset of the registry | — | tool registry, server-side validation |
| Limits | defaults and ceilings | up to the ceilings | 60 s rate window, fallbacks |
| Disclosure line | `required` or `optional`, default text | text; off only if optional | — |
| Who it answers | — | audience scope, only/blocked senders | private chats only; groups and channels never |
| When it answers | — | schedule | takeover when the owner replies |
| Model and budget | `execution` | — | per-job budget cap |

## Mapping to today's runtime

`assistant.ProfileRequest` turns an install into the body of
`PUT /api/admin/agent/profile`. A test applies the HR example through the
real handler and checks the stored profile equals the configuration the agent
runs with today.

| Today | New field |
|---|---|
| `AGENT_SYSTEM_PROMPT` (global env) | definition `instructions` |
| `mode` | install `mode` |
| `autopilot_paused` | install `paused` |
| `listener_enabled` | install `listening` |
| `disclosure_text`, `disclosure_disabled` | install `disclosure` within definition `defaults.disclosure` |
| `max_autonomous_turns`, `max_msgs_per_minute`, `max_reply_chars` | install `limits` within definition `ceilings` |
| `intent_allowlist` (CSV) | intents whose resolved tier is `auto` |
| `sender_allowlist`, `blocked_senders` | install `audience.onlySenders`, `audience.blockedSenders` |
| owner profile document | install `values` placed by each variable's `profilePath` |
| owner profile `disclosure` map | variable `disclosure`, install `disclosureLevels` |
| fixed MCP tool set | definition `tools` |
| `job_leads` table | definition `records.kind` |
| worker model and budget env | definition `execution` |

Settings the runtime cannot enforce yet fail with `ErrUnsupported` instead of
being dropped: `ownerNotes`, the `never` tier, a narrowed audience scope, a
schedule other than `always`, a tool subset and record kinds other than
`job_lead`. An install is applied entirely or not at all.

## Customization tiers

| Tier | The user | Gate |
|---|---|---|
| T0 Install | picks a catalog assistant, fills the required values | schema validation |
| T1 Tune | mode, tiers (tighten), limits, audience, schedule, disclosure, `ownerNotes` | schema and definition checks |
| T2 Fork | own instructions, intents and records on a catalog base; tools from the registry | private visibility; observe mode first |
| T3 Connectors | adds MCP servers (calendar, CRM), each tool with a tier, approve by default | admin review |
| T4 Own runtime | runs their own worker against the agent job API (claim, propose, complete) | account-scoped token; policy enforced server-side |

## Phases

- **P0 (this change):** format, schemas, HR example, validation and mapping
  tests, this document.
- **P1:** the profile row gets `assistant_ref` and `install_json`; the claim
  response carries the rendered instructions (definition + values +
  `ownerNotes`), so the worker no longer needs a global prompt; existing
  profiles are migrated to an HR install.
- **P2:** tiers including `never`, the audience scope and schedules in
  `policy.go`; `/mctl` gets unpause and shows the install; recruiter-specific
  tool names get generic aliases (`save_record`, `get_owner_profile`).
- **P3:** definitions published to the mctl-api agent registry, a
  per-account install binding, MCP tools `list_assistants`,
  `install_assistant`, `update_install`, and a page on tg.mctl.ai.
- **P4:** forks, user connectors with review, own-runtime documentation.

## How this compares

Formats that informed this one, and where it differs:

| Product | What we took | What it lacks for this use |
|---|---|---|
| Microsoft 365 declarative agents | instructions + capabilities + disclaimer; user overrides that can only remove | runs in the user's own chat, not on their behalf with third parties |
| Claude subagents, Agent Skills | markdown instructions with frontmatter, tool lists | no owner, counterparty or disclosure model |
| OpenAI GPT Actions, Lindy, Relevance, n8n | per-tool approval: auto, approve, never | approval is per tool, not per reply intent |
| Telegram Business chat automation (Bot API 10.0) | recipients model: contacts, non-contacts, new and existing chats, include and exclude | 24 h reply window, one bot, private chats only, no view of the owner's own replies |
| Voiceflow, Respond.io, Wati | exit conditions, handoff with a summary | business inboxes, not a person's account |
| MCP `server.json`, Oracle Agent Spec, Letta `.af` | typed variables, secrets kept out of the definition | no catalog-to-account install step |
| A2A agent card | public listing: name, version, examples | describes an agent to other agents, not to an owner |

What none of them covers and this runtime already has: automatic takeover
when the owner replies in a chat, a disclosure line to the counterparty,
per-conversation rate limits, and per-field disclosure of the owner's
details depending on whether the owner has engaged.
