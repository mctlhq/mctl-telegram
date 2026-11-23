# Bounty Fix

**Reward:** $20.00
**Issue:** https://github.com/mctlhq/mctl-telegram/issues/1401
**Repo:** https://github.com/mctlhq/mctl-telegram

---

## Issue

spike(partner): AgentsPodium × MCTL — Telegram MCP compatibility, distribution and Local Bridge hosting

## Context
Follow-up to #1384 (closed *not planned* on 2026-11-22 because user-specific redirect hosts were unsafe). AgentsPodium operator RadianceTeam replied on 2026-11-22 that the hosted Hermes agent now supports **vendor-owned stable-domain OAuth callback and Client ID Metadata Documents (CIMD)**. This is a new client-identity fact, **not evidence of successful MCTL sign-in**.

Vendor-reported paths (verify as live public HTTPS content before admission):
- CIMD prefix: `https://agentspodium.com/oauth/mcp/clients/`
- Example client ID: `https://agentspodium.com/oauth/mcp/clients/personal-assistant-ae0764/mctl.json`
- Callback prefix: `https://agentspodium.com/oauth/mcp/cb/` with `<pod>/<server>` suffix
- Reported enabled for newly created or updated pods from **2026-11-22**; older pods need update
- Vendor reports end-to-end with **Notion MCP**, not tg.mctl.ai.

The operator's external email has been answered with https://tg.mctl.ai/platforms and https://tg.mctl.ai/docs/local-bridge and a request for a test pod plus custom Go-binary hosting details. **Do not copy private mail into public artifacts.**

## Product positioning / primary hypothesis

> **AgentsPodium gives your agent a home. MCTL gives it access to your Telegram account.**
>
> **AgentsPodium can bring new users to MCTL. MCTL makes AgentsPodium agents more useful.**

**What we are testing:** not "another Telegram integration" but an *agent runtime + account-data tool* combination. AgentsPodium's documented Telegram bot-token channel is an **agent conversation surface** (users talk to a bot). MCTL's OAuth-protected Telegram MCP is an **authorized user-account capability surface** (the agent can read the user's existing Telegram dialogs and message history and, only with separate opt-in, perform writes). Avoid saying AgentsPodium cannot access user history via any other plugin; only claim that its *native bot-channel integration does not by itself grant that access*.

| Customer question | AgentsPodium native Telegram bot channel | AgentsPodium agent + MCTL Telegram MCP |
| --- | --- | --- |
| "Can I chat with my agent in Telegram?" | Yes, this is the native channel use case | Also possible via the existing bot channel; MCP is not needed just for chatting |
| "What did I miss in LBX or across my chats?" | Not provided merely by registering a BotFather bot token; other integrations must be checked separately | Via the **user's own** Telegram account and MCTL read-only tools, if that account has access to the chats |
| "Find the agreement from last week in an existing chat" | Bot-channel access alone does not grant historical personal-account search | `search_messages` via MCTL **hosted mode** (Local Bridge search is currently unsupported) |
| "Reply as me" | Bot sends as the bot, not automatically as the user's account | MCTL may send as the connected personal account **only after explicit send consent, granted scope and server gate** |
| "Where is my Telegram session stored?" | Platform's bot secret / pod runtime custody to be verified | MCTL-hosted session in server-side sealed storage, **or** Local Bridge on a user-controlled device; relay still sees request/response payloads |

**User-visible pilot story:** A person creates/opens an AgentsPodium Hermes agent and asks in plain language: *"Summarize unread messages in my Telegram groups, including LBX, and give me the important action items."* The agent has a user-authorized MCTL connection; it calls `get_unread_messages` and `get_messages` for chats the user can actually access; it cites chat/message context without inventing unseen content. Read-only by default. For demo evidence use synthetic fixtures/test account, not personal conversation transcripts. Sending is strictly out of the initial end-user pilot.

**Partnership positioning, proposed outbound copy (not yet a published partner claim):**
- Headline: **"Give your AgentsPodium agent access to your Telegram conversations with MCTL."**
- Body: **"Use AgentsPodium to keep an AI agent running. Connect MCTL Telegram MCP to securely grant access to the messages and chats your Telegram account can see, with read-only defaults and separate consent for sending. Prefer not to host a Telegram session? Explore MCTL Local Bridge for a device you control."**
- CTA 1: `https://tg.mctl.ai/platforms` (hosted MCP integration)
- CTA 2: `https://tg.mctl.ai/docs/local-bridge` (optional self-hosted session custody, not a requirement to connect)
- Do **not** say "official Telegram", "zero knowledge", "end-to-end encrypted", "works on AgentsPodium" or "100% private" before independent evidence; apply correct operator-trust disclosures.

**Evidence-based differentiation gate (must be reported before claiming product-market fit):**
- [ ] Pin primary vendor evidence that native AgentsPodium Telegram integration uses a bot token/channel, plus its MCP client support, and identify what *other* user-account Telegram integrations are already available there; mark unknowns rather than claiming exclusivity.
- [ ] Compare one exact prompt *with native bot-channel only* versus *with MCTL user-account MCP* in a controlled test: whether existing-chat history and unread messages are accessible, user friction, latency and error handling. Do not infer absent features beyond the tested setup.
- [ ] Verify the user can **connect / revoke** MCTL without transferring their Telegram MTProto session to AgentsPodium; capture the OAuth/CIMD permissions flow and specific read-only tools in a redacted trace.
- [ ] Confirm links/placement and actual **cross-referrals** with the partner; distinguish **published external backlink**, **issued affiliate URL**, **clicks**, **successful first read** and **7-day retained use**. Don't count an email request as a backlink.
- [ ] In the pilot report, state **what value the MCTL integration adds compared with AgentsPodium's built-in bot** and whether the added OAuth and privacy tradeoffs are justified. If no measurable additional value, choose `REVISE_ONBOARDING` or `DEFER_DISTRIBUTION`, not automatic expansion.

**Decision principle:** Integrate as complementary products before considering a competing full personal-assistant hosting offer. Keep MCTL a portable MCP capability provider, so the integration works beyond AgentsPodium.

## GO / scope
**GO_RESEARCH / read-only compatibility verification only.** No approval to add host allowlists or `ALLOWED_ORIGINS`, no production deployment, agent implementation, real-user auth or send consent.

### Gate A — Vendor domain and metadata verification
- [ ] Verify independent, same-operator identity for `agentspodium.com` and RadianceTeam, valid HTTPS and stable production domain.
- [ ] GET the example CIMD document from an independent client; save **sanitized** evidence of `client_id`, `redirect_uris`, `token_endpoint_auth_method`, JSON/content-type, status, chain, redirects, and document cache; refuse if the URL is inaccessible/mismatched or references another domain.
- [ ] Check exact path `/oauth/mcp/clients/<pod>/<server>.json` binds to the callback `/oauth/mcp/cb/<pod>/<server>`; verify no arbitrary callback, open redirect, reassigned pod or insecure cross-pod authorization-code forwarding. Vendor claims are not a substitute for tests.
- [ ] Evaluate the impact of admitting **one vendor-owned host** under current `OAUTH_ALLOWED_IMPLICIT_HOSTS` and CIMD policy, including negatives (unregistered pod, invalid CID, host mismatch, multi-tenant cross-pod, PKCE mismatch, replay); avoid wildcard subdomain.
- [ ] Independently review P1/P2 security implications and a narrow candidate GitOps PR if justified. **Human authorization required before allowlist/production change.**

### Gate B — Read-only hosted Hermes integration test (only after Gate A + approved admission)
- [ ] Use vendor-updated isolated test pod and a designated test Telegram account. Never use another user's real account, session, secrets or production write.
- [ ] Complete the existing #1384 matrix: approved host synced; CIMD accepted; login; exact scopes; tools/list; one `list_dialogs`; send denied when unconsented; refresh; revocation; user-visible errors. Timestamp source/commit and evidence links, redact tokens.
- [ ] Update `docs/platforms/compatibility.md` and https://tg.mctl.ai/platforms **only to the evidenced status** (not tested/works/caveats). A vendor's Notion result is not MCTL verification.

### Gate C — Optional deployment research (separate decision)
- [ ] Check whether AgentsPodium permits customer-controlled custom `linux/amd64` / `linux/arm64` Go binary, persistent `0600` config/session, backup, restart, outbound websocket to `wss://tg.mctl.ai/bridge`, operator visibility of secrets, and exit/export.
- [ ] Distinguish **third-party hosted binary** from the documented **Local Bridge on a user-controlled machine**. Do not market the former as a private local session or claim a successful deployment without a real test. No real Telegram-session migration/deployment authorized.
- [ ] Partner terms (25% recurring per vendor email) and link placement are a separate commercial decision; no unsupported financial or KYC promises.

## Acceptance
One evidence-linked matrix for the hosted Hermes path, unambiguous PASS/HOLD and outstanding security issues. No allowlist mutation until owner explicitly approves the reviewed change; no deploy/merge/paid pod creation or external account sign-in as part of this issue.

---

## Product / distribution expansion — AgentsPodium ↔ MCTL
**Owner hypothesis (2026-11-22):** *AgentsPodium can bring new users to MCTL, while MCTL makes AgentsPodium agents more useful.* These services currently have complementary primary jobs: AgentsPodium provides a persistent agent pod/catalog, while MCTL provides governed MCP tools and Telegram account access. The potential competition in personal-assistant UX must not prevent a bounded, reversible integration pilot.

### Two independent acquisition and value loops
| Loop | User journey | MCTL value | AgentsPodium value | Evidence to collect |
|---|---|---|---|---|
| **A. AgentsPodium → MCTL** | Discover Hermes/Personal Assistant/Tech Assistant pod → learn about **tg.mctl.ai** → OAuth connect to Telegram MCP → `list_dialogs` / `get_unread_messages` read-only | New qualifying Telegram MCP connections and retained active users | Useful Telegram capabilities beyond a generic chatbot | Referral click → landing → consent → first successful read-only call → 7-day retained usage |
| **B. MCTL → AgentsPodium** | Read MCTL integrations / Local Bridge docs → need an always-on agent → follow attributed partner link → launch pod → connect MCTL | Better onboarding/completion and a partner hosting option, without building consumer pod hosting | Paid, running pods referred by MCTL | Outbound click → pod activated → retained paid running pod → validated partner payout (where observable) |
| **C. Catalog distribution / authored agent** | Publish a narrowly scoped **Telegram Research Assistant powered by MCTL** or an integration recipe as an AgentsPodium agent | Discoverability, trusted integration example | Useful publishable persona for catalog | Listing approved, live URL, successful test journey, installs and retention |

**Do not assume** their generic Telegram chat/channel integration is equivalent to *user-account* Telegram MCP, personal chat history, read-only scopes, granular consent and MCTL session controls. Verify a real incremental capability, not just an overlapping feature. Their own pages currently advertise published agents, six runtimes, persistent pods, and marketplace features; this does **not** confirm arbitrary Go-binary hosting.

### D. Product smoke test and real user value (after A/B technical gates)
- [ ] Pick **one** flagship scenario: *“What did I miss in my Telegram chats today?”* The agent must use MCTL read-only tools and produce a useful, source-grounded digest. No unattended sends, no export of private raw chat data into public demos/screenshots.
- [ ] Verify whether a native hosted Hermes skill/MCP configuration can reliably discover tools, handle OAuth token refresh/revocation and recover from offline or permissions errors; document pod version and exact repro. Keep authentication on the user's consent flow.
- [ ] Create a simple published installation recipe: **Run an AgentsPodium agent with MCTL Telegram MCP**, with preconditions, URL, granted scopes, example prompts, screenshots/commands (sanitized), disconnect instructions and troubleshooting. Write to MCTL docs only via a separately reviewed PR, not this issue mutation.
- [ ] Ask AgentsPodium to provide a first-party integration listing / linking guide, with a visible, useful link to **https://tg.mctl.ai/docs/local-bridge** and the hosted MCP integration docs (e.g., https://tg.mctl.ai/platforms). Confirm precise placements and URLs before claiming external backlinks.
- [ ] Separately explore listing a MCTL-powered agent in `https://agentspodium.com/personas/new`; document moderation requirements, ownership, allowed data sources, portability, brand presentation and the final published URL. Do not create a paid pod or publish an agent without a separate owner GO.
- [ ] Pilot with **up to five explicit-consent test users** using only approved read scopes *after* technical security GO. No use of production customer accounts or unsanitized chat contents in evidence. Gather friction points and “would you keep it?” feedback; reserve product-wide deployment for a later decision.

### E. Commercial / partner feasibility (terms are evidence, earnings are unproven)
User-supplied [partner terms](https://agentspodium.com/partners) as of 2026-11-22:
- Claimed rate: **25%** of paid running pod revenue monthly. Author gets 100% attribution for own agent; referring someone to another author's agent also advertises 25%. **Clarify collision/priority** if both apply—do not assume two payouts or an effective 50%.
- Payout: monthly **USDT/USDC or Telegram Stars**, minimum **$20**, smaller balances roll forward.
- Partner dashboard claims live deployments, running pods, earned/pending amounts.
- Every published agent reviewed; high-risk categories may require disclaimers.
- The published clause says pre-change agents keep the earlier rate **12 months** after a rate change; this is **not** an unconditional contractual lock at 25% forever.
- [ ] Verify public terms version, who qualifies (individual / entity, jurisdiction), account requirements/KYC/tax documents, prohibited traffic or paid incentives, refund/chargeback treatment, payout fee/conversion and payout-country eligibility (including Montenegro if applicable).
- [ ] Obtain the **actual attributable referral link** and attribution semantics (cookie duration, cross-device, first/last touch, self-referrals, attribution when publishing own agent); never invent a link.
- [ ] Confirm whether integration documentation links can include the referral link and whether the provider will offer reciprocal co-marketing. Keep referral disclosure visible and avoid misleading “free” hosting promises.
- [ ] Measure **paid active pods** and actual partner dashboard accrual as separate from link clicks and MCTL registrations. Estimate economics only after validating data.

### F. Trust, privacy and architecture choices
- **Preferred, first pilot:** AgentsPodium agent uses remote `https://tg.mctl.ai/mcp` over user-consented OAuth, with MCTL owning authorization/role, revocation, tenant binding and audit. No Telegram MTProto session copied to AgentsPodium.
- **Optional, high-risk separate hypothesis:** deploy `mctl-telegram-local` as a Go binary **inside AgentsPodium's infrastructure**. Even if supported, this is *not* “local on your own computer” as defined by [Local Bridge docs](https://tg.mctl.ai/docs/local-bridge). A hosted operator could have access to the filesystem/environment/session unless technical and contractual isolation is verified. Distinguish runtime/persistent storage/encryption/operator access/backup/export, deletion, and session shutdown. Do not deploy user sessions during this research.
- The MCTL Local Bridge relay still sees tool arguments/results in transit, as documented; do not claim end-to-end encryption or complete message privacy from either operator.
- Authorization code must be bound to exactly the requesting pod/client and an exact redirect path, with PKCE, no cross-pod leakage. A shared vendor-owned domain **alone** is insufficient proof of safe CIMD admission.
- Avoid vendor lock-in: installation instructions, tool interface and per-user credentials should work with other agent hosts. Keep A/B pilot instrumentation limited to anonymized aggregate funnel events; no user message bodies or bearer credentials sent to analytics.

### PDLC / acceptance: prove distribution value before scale
**Baseline:** MCTL traffic/conversions attributable to this collaboration are `UNKNOWN` until measurement; no invented counts or ROI.

**Phase 0 — evidence and decision (read-only):**
- Vendor CIMD + callback identity independently verified, threat model and technical compat gate reviewed; exact owner approval required for GitOps allowlist.
- Confirm partner terms and hosting capability; partner link only when actually issued.
- Produce one-page integration journey and instrumentation spec (no tracking tokens inside Telegram content).

**Phase 1 — small external pilot (separate owner GO):**
- One read-only hosted pod + designated test account: all 10 existing compatibility checks evidenced, no unauthorized send or cross-pod access.
- A reproducible “missed Telegram messages” flow that is genuinely distinct from AgentsPodium's built-in chat connector.
- Landing/integration guide and proposed directory/partner placement, with source-linked claims and review.
- With up to five opted-in testers, record connection completion, first value, 7-day return, qualitative feedback, drop-offs and verified referral conversions. Suggested evaluation targets (hypotheses, not existing SLO): >=4/5 successfully complete sign-in + first read, zero unconsented writes, zero credential/session leakage. Sample too small for statistical extrapolation.

**Phase 2 — owner decision:** `PARTNER_PILOT_GO | REVISE_ONBOARDING | TECHNICAL_HOLD | DEFER_DISTRIBUTION`. Record both sides' measurable value, ongoing support/security costs and next 30-day experiment. Do not call a partner listing “growth” without successful user activation and retention.

### Ownership and governance
- **This issue is the source of truth** for proof-of-compatibility + partner/distribution research; avoid a separate duplicate strategic issue until pilot yields specific independently owned work.
- MCTL owns MCP OAuth, Telegram policy, docs and user-facing disclosures. AgentsPodium owns pod-host client identity, callback, agent publication and referral attribution. Each side must provide concrete verification evidence for its domain.
- Keep `GO_RESEARCH` only: do **not** trigger implementer, publish a listing, purchase pods, change production allowlists, access real Telegram accounts, approve or merge without a new owner decision.
- Review P1/P2 security and product claims independently before advancing from Phase 0. Include source URLs, date, exact test pod/client metadata and evidence links in the final report.

**Primary public references:** [AgentsPodium roadmap](https://agentspodium.com/articles/roadmap), [AgentsPodium partners](https://agentspodium.com/partners), [MCTL platforms](https://tg.mctl.ai/platforms), [MCTL Local Bridge](https://tg.mctl.ai/docs/local-bridge), historical [#1384](https://github.com/mctlhq/mctl-telegram/issues/1384).


---

## Process

### 1. Orient yourself first
Before touching any code:
- Read the README and any relevant docs
- Run: find . -type f | grep -v node_modules | grep -v .git | grep -v dist | head -60
- Grep for the key terms from the issue title to find the relevant files
- Read the files around the bug — understand what's currently happening

### 2. Find and read the tests
- Look for test files near the relevant code (*.test.ts, *.spec.js, __tests__, etc.)
- Read them — they tell you what behavior is expected
- Understand what a passing fix looks like before writing a line

### 3. Implement the fix
- Make the MINIMAL change that fixes the issue — nothing more
- Do not refactor, rename, reorganize, or clean up unrelated code
- Do not add dependencies unless the issue explicitly requires it
- Do not modify config files (package.json, tsconfig.json, etc.) unless that IS the fix
- One logical change, one commit

### 4. Verify
- Run the test suite: check package.json scripts for "test", "lint", "typecheck"
  Common commands: npm test, yarn test, pnpm test, pytest, go test ./..., cargo test
- If TypeScript is present: npx tsc --noEmit
- Fix any test failures your change caused — if a test was wrong before, update it

### 5. Commit and document
- git add -A
- git commit -m "fix: spike(partner): AgentsPodium × MCTL — Telegram MCP compatibility, distri"
- Write AGENT_SUMMARY.md with:
  - Root cause: what was wrong and why
  - Fix: what you changed and the reasoning
  - Verification: how to confirm it works
  - Concerns: anything a reviewer should know

---

## Stop conditions

If ANY of these are true, write "UNCERTAIN: [reason]" at the top of AGENT_SUMMARY.md, make NO code changes, and stop:
- The fix requires changing more than ~5 files
- You cannot determine what the correct behavior should be
- The issue requires a database migration, API key, or external service
- You find 3+ open PRs already attempting this fix (high competition)
- The repo is not in a language/framework you can reason about confidently

A clean UNCERTAIN is better than a bad PR.
