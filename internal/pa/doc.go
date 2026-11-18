// Package pa is the Personal Assistant bot (ADR 0011, issue #1313).
//
// It is a separate surface from the auto-reply assistants of
// internal/assistantinstall (AssistantInstall): a dedicated Bot API bot that a
// Telegram user talks to in a private chat. The authoritative design is
// docs/agent-runtime/personal-assistant-threat-model.md; test ids in this
// package's tests (S1-B1, S1-X1, ...) are that document's.
//
// This package currently holds slice (a) of #1313:
//
//   - the webhook ingress filter (threat model T4): constant-time secret
//     check, message and callback_query only, private chats with
//     chat.id == from.id only, no business, sender_chat or via_bot updates,
//     and durable update_id deduplication;
//   - VerifiedUpdate, the only source of a Principal (invariant I2);
//   - ExecutionContext, which every run carries, with an interactive-only
//     constructor for Phase 1;
//   - MemoryStore, an interface with a no-op implementation only;
//   - a getWebhookInfo health helper.
//
// Subpackages: egress (T9 outbound client), catalog (the T8 catalog pin and
// tools/list drift check, #1315) and connector (the executor's pin check and
// fail-closed T12 audit path, #1315; dispatch itself is a later slice).
//
// Nothing here calls a model, a tool or an MCP server, and nothing sends a
// message. Everything is inert unless PA_ENABLED is explicitly true; see
// cmd/server.
package pa
