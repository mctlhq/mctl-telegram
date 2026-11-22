// Copyright 2025 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package safetext

// Template is server-authored message text. Its field is unexported, so
// code outside this package cannot make one from a string, by conversion, a
// type alias or a generic: the only Templates are the variables declared in
// this file, each built by tpl from a string literal
// (TestTemplatesAreLiteralRegistry). That is what keeps model text from
// skipping Render through ServerText. The zero Template is empty.
type Template struct {
	s string
}

// String returns the template text exactly as it will be sent.
func (t Template) String() string { return t.s }

// tpl builds a registry entry. Call it only in this file, only with a
// string literal.
func tpl(s string) Template { return Template{s: s} }

// The registry. Every server text and button label is here, each as a
// literal.
var (
	// LabelCancel is a generic Cancel button label.
	LabelCancel = tpl("Cancel")

	// LabelConfirm is the account-linking confirm card's Confirm button
	// (threat model T1 step 5).
	LabelConfirm = tpl("Confirm")

	// LabelConnect is the /connect web_app button that opens the linking
	// Mini App (T1 step 1).
	LabelConnect = tpl("Connect")

	// TextConnectOpen goes with the /connect web_app button.
	TextConnectOpen = tpl("Tap Connect to link your account. The button works once and expires in 10 minutes.")

	// TextBudgetHold is sent once per held run when a spending limit is
	// reached (#1313 slice d1, S1-R3): no model call was made.
	TextBudgetHold = tpl("The assistant has reached its spending limit for now. Your request is on hold until the limit resets. If the conversation expires first, you will be told and can send it again.")
	// TextRunFailed is sent when a request ended without an answer: the
	// run's lease expired, or it failed repeatedly (#1313 slice d1).
	TextRunFailed = tpl("The assistant could not finish your request. Please send it again.")
	// TextRequestDropped is sent when a queued or held request is dropped
	// because its conversation closed or expired first (#1313 slice d1).
	TextRequestDropped = tpl("Your earlier request could not be answered before the conversation expired. Please send it again.")
	// TextReplyTooLong replaces a model reply that does not fit the message
	// limit. The reply is never truncated (#1313 slice d1).
	TextReplyTooLong = tpl("The answer was too long to send. Please ask for a shorter answer.")

	// LabelConsentAccept is the consent prompt's only button (#1348).
	LabelConsentAccept = tpl("I agree")

	// TextConsentPrompt is convo.ConsentText, verbatim: the text whose hash
	// the prompt's button binds (TestConsentPromptIsConsentText). Change
	// both together, and bump convo.ConsentVersion.
	TextConsentPrompt = tpl("Before the assistant answers you, it needs your consent to this data flow (pa-data-flow/v1).\n\nWhat is sent: the messages you write to this bot, any text you forward, reply to or quote here, and the results the assistant reads from the services you connect (for example your Telegram chats or your smart home).\n\nWhere it goes: to Nebius, the AI model provider that generates the answers, reached through Cloudflare AI Gateway. They process it under their API terms. See https://tg.mctl.ai/privacy.\n\nHow long it is kept: a conversation is kept on our servers for at most 24 hours from its start. /new starts a fresh conversation, /forget deletes all of your conversations now, and /consent withdraw stops the assistant and deletes your conversations.\n\nThe assistant only reads in this version; it cannot send, change or delete anything on your behalf.")
	// TextConsentAccepted answers the consent button. A message sent before
	// consent was not stored, so the principal is asked to send it again.
	TextConsentAccepted = tpl("Thank you, your consent is recorded. Send your request and the assistant will answer it.")
	// TextConsentWithdrawn answers /consent withdraw.
	TextConsentWithdrawn = tpl("Your consent is withdrawn. The assistant has stopped and your conversations are deleted. Send /consent to give it again.")
	// TextConsentStale precedes a fresh prompt when the button pressed was
	// shown with an earlier consent text.
	TextConsentStale = tpl("The consent text has changed since that button was shown. Please read the current text below.")
	// TextNewConversation answers /new.
	TextNewConversation = tpl("A new conversation has started. The assistant no longer sees your earlier messages.")
	// TextForgotten answers /forget.
	TextForgotten = tpl("All of your conversations are deleted.")
	// TextUnknownButton answers a button that is unknown, expired or
	// already used.
	TextUnknownButton = tpl("This button is no longer valid.")
	// TextRateLimited is sent once per rate window, on the first message
	// over the limit.
	TextRateLimited = tpl("You are sending messages faster than the assistant accepts. Please wait a little and send your request again.")
	// TextMessageTooLong refuses a message over the size limit; nothing of
	// it was stored.
	TextMessageTooLong = tpl("Your message is too long. Please send a shorter one.")

	// The account-linking replies (#1318 slice C2). Each is sent after the
	// update's commit, except TextLinkingUnavailable, an outbox row.
	TextLinkingUnavailable = tpl("Connecting accounts is not available.")
	TextConnectUsage       = tpl("Send /connect tg to connect your Telegram account, /connections to see your connections, or /disconnect tg to remove one.")
	TextConnectFailed      = tpl("The connection could not be started. Please try again.")
	TextConnected          = tpl("Your account is connected.")
	TextConnectCancelled   = tpl("The connection is cancelled.")
	TextConnectButtonGone  = tpl("This button is no longer valid. Send /connect to start again.")
	TextDisconnected       = tpl("Your connection is removed and the service revoked its access.")
	// TextDisconnectedLocal: the connection is gone here, but the service
	// did not confirm the revocation (S1-C6): the user is told, never
	// shown a success it cannot back.
	TextDisconnectedLocal = tpl("Your connection is removed here, but the service did not confirm that its access was revoked. You can also revoke it in the service's settings.")
	TextDisconnectNone    = tpl("You have no connection to remove for this service.")
	TextDisconnectFailed  = tpl("The connection could not be removed. Please try again.")
	TextConnectionsNone   = tpl("You have no connected accounts.")
	TextConnectionsFailed = tpl("Your connections could not be read. Please try again.")
	// TextAssistantUnavailable refuses a principal an admin disabled or one
	// not on the preview allowlist, and tells a principal whose queued or
	// running request was stopped for that reason (#1318). The same text
	// for both, so the reply does not say which.
	TextAssistantUnavailable = tpl("The assistant is not available for your account. /forget still deletes your conversations.")
)
