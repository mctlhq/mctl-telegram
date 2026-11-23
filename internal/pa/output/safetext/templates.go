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
	// ru is the Russian translation, "" when there is none (Template.In).
	ru string
}

// String returns the template text exactly as it will be sent.
func (t Template) String() string { return t.s }

// tpl builds a registry entry from the English text and, optionally, its
// Russian translation. Call it only in this file, only with string
// literals.
func tpl(s string, ru ...string) Template {
	t := Template{s: s}
	if len(ru) > 0 {
		t.ru = ru[0]
	}
	return t
}

// The registry. Every server text and button label is here, each as a
// literal.
var (
	// LabelCancel is a generic Cancel button label.
	LabelCancel = tpl("Cancel", "Отмена")

	// LabelConfirm is the account-linking confirm card's Confirm button
	// (threat model T1 step 5).
	LabelConfirm = tpl("Confirm", "Подтвердить")

	// LabelConnect is the /connect web_app button that opens the linking
	// Mini App (T1 step 1).
	LabelConnect = tpl("Connect", "Подключить")

	// TextConnectOpen goes with the /connect web_app button.
	TextConnectOpen = tpl("Tap Connect, then Continue in the browser, and sign in there. Come back here to confirm. The button works once and expires in 10 minutes.", "Нажмите «Подключить», затем «Continue in the browser» и войдите в браузере. Потом вернитесь сюда, чтобы подтвердить. Кнопка срабатывает один раз и действует 10 минут.")

	// TextBudgetHold is sent once per held run when a spending limit is
	// reached (#1313 slice d1, S1-R3): no model call was made.
	TextBudgetHold = tpl("The assistant has reached its spending limit for now. Your request is on hold until the limit resets. If the conversation expires first, you will be told and can send it again.", "Ассистент пока исчерпал лимит расходов. Ваш запрос ждёт, пока лимит не обновится. Если разговор истечёт раньше, вам об этом сообщат, и запрос можно будет отправить снова.")
	// TextRunFailed is sent when a request ended without an answer: the
	// run's lease expired, or it failed repeatedly (#1313 slice d1).
	TextRunFailed = tpl("The assistant could not finish your request. Please send it again.", "Ассистенту не удалось выполнить запрос. Пожалуйста, отправьте его ещё раз.")
	// TextRequestDropped is sent when a queued or held request is dropped
	// because its conversation closed or expired first (#1313 slice d1).
	TextRequestDropped = tpl("Your earlier request could not be answered before the conversation expired. Please send it again.", "На ваш предыдущий запрос не удалось ответить до истечения разговора. Пожалуйста, отправьте его ещё раз.")
	// TextReplyTooLong replaces a model reply that does not fit the message
	// limit. The reply is never truncated (#1313 slice d1).
	TextReplyTooLong = tpl("The answer was too long to send. Please ask for a shorter answer.", "Ответ получился слишком длинным для отправки. Попросите ответить короче.")

	// LabelConsentAccept is the consent prompt's only button (#1348).
	LabelConsentAccept = tpl("I agree", "Согласен")

	// TextConsentPrompt is convo.ConsentText, verbatim: the text whose hash
	// the prompt's button binds (TestConsentPromptIsConsentText). Change
	// both together, and bump convo.ConsentVersion.
	TextConsentPrompt = tpl("Before the assistant answers you, it needs your consent to this data flow (pa-data-flow/v1).\n\nWhat is sent: the messages you write to this bot, any text you forward, reply to or quote here, and the results the assistant reads from the services you connect (for example your Telegram chats or your smart home).\n\nWhere it goes: to Nebius, the AI model provider that generates the answers, reached through Cloudflare AI Gateway. They process it under their API terms. See https://tg.mctl.ai/privacy.\n\nHow long it is kept: a conversation is kept on our servers for at most 24 hours from its start. /new starts a fresh conversation, /forget deletes all of your conversations now, and /consent withdraw stops the assistant and deletes your conversations.\n\nThe assistant only reads in this version; it cannot send, change or delete anything on your behalf.")
	// TextConsentPromptRU is convo.ConsentTextRU, verbatim, sent to a
	// principal whose client is in Russian. It is a template of its own,
	// not a translation of TextConsentPrompt: the prompt's button binds
	// the hash of the text it shows, so each prompt is in exactly one
	// language, fixed when the prompt is queued, whatever the Sender's
	// language for the chat is at send time.
	TextConsentPromptRU = tpl("Прежде чем ассистент ответит вам, ему нужно ваше согласие на эту передачу данных (pa-data-flow/v1).\n\nЧто передаётся: сообщения, которые вы пишете этому боту, любой текст, который вы здесь пересылаете, на который отвечаете или который цитируете, а также результаты, которые ассистент читает из подключённых вами сервисов (например, ваших чатов Telegram или умного дома).\n\nКуда: в Nebius, провайдеру ИИ-модели, которая генерирует ответы, через Cloudflare AI Gateway. Они обрабатывают данные на условиях своих API. Подробнее: https://tg.mctl.ai/privacy.\n\nСколько хранится: разговор хранится на наших серверах не более 24 часов с его начала. /new начинает новый разговор, /forget сразу удаляет все ваши разговоры, а /consent withdraw останавливает ассистента и удаляет ваши разговоры.\n\nВ этой версии ассистент только читает: он не может ничего отправлять, изменять или удалять от вашего имени.")
	// TextConsentAccepted answers the consent button. A message sent before
	// consent was not stored, so the principal is asked to send it again.
	TextConsentAccepted = tpl("Thank you, your consent is recorded. Send your request and the assistant will answer it.", "Спасибо, ваше согласие записано. Отправьте запрос, и ассистент на него ответит.")
	// TextConsentWithdrawn answers /consent withdraw.
	TextConsentWithdrawn = tpl("Your consent is withdrawn. The assistant has stopped and your conversations are deleted. Send /consent to give it again.", "Ваше согласие отозвано. Ассистент остановлен, ваши разговоры удалены. Отправьте /consent, чтобы дать согласие снова.")
	// TextConsentStale precedes a fresh prompt when the button pressed was
	// shown with an earlier consent text.
	TextConsentStale = tpl("The consent text has changed since that button was shown. Please read the current text below.", "Текст согласия изменился с тех пор, как была показана эта кнопка. Пожалуйста, прочитайте актуальный текст ниже.")
	// TextNewConversation answers /new.
	TextNewConversation = tpl("A new conversation has started. The assistant no longer sees your earlier messages.", "Начат новый разговор. Ассистент больше не видит ваши прежние сообщения.")
	// TextForgotten answers /forget.
	TextForgotten = tpl("All of your conversations are deleted.", "Все ваши разговоры удалены.")
	// TextUnknownButton answers a button that is unknown, expired or
	// already used.
	TextUnknownButton = tpl("This button is no longer valid.", "Эта кнопка больше не действует.")
	// TextRateLimited is sent once per rate window, on the first message
	// over the limit.
	TextRateLimited = tpl("You are sending messages faster than the assistant accepts. Please wait a little and send your request again.", "Вы отправляете сообщения быстрее, чем ассистент их принимает. Подождите немного и отправьте запрос снова.")
	// TextMessageTooLong refuses a message over the size limit; nothing of
	// it was stored.
	TextMessageTooLong = tpl("Your message is too long. Please send a shorter one.", "Сообщение слишком длинное. Пожалуйста, отправьте покороче.")

	// The account-linking replies (#1318 slice C2). Each is sent after the
	// update's commit, except TextLinkingUnavailable, an outbox row.
	TextLinkingUnavailable = tpl("Connecting accounts is not available.", "Подключение аккаунтов недоступно.")
	TextConnectUsage       = tpl("Send /connect tg to connect your Telegram account, /connections to see your connections, or /disconnect tg to remove one.", "Отправьте /connect tg, чтобы подключить ваш аккаунт Telegram, /connections, чтобы увидеть подключения, или /disconnect tg, чтобы отключить.")
	TextConnectFailed      = tpl("The connection could not be started. Please try again.", "Не удалось начать подключение. Пожалуйста, попробуйте ещё раз.")
	TextConnected          = tpl("Your account is connected.", "Ваш аккаунт подключён.")
	TextConnectCancelled   = tpl("The connection is cancelled.", "Подключение отменено.")
	TextConnectButtonGone  = tpl("This button is no longer valid. Send /connect to start again.", "Эта кнопка больше не действует. Отправьте /connect, чтобы начать заново.")
	TextDisconnected       = tpl("Your connection is removed and the service revoked its access.", "Подключение удалено, сервис отозвал свой доступ.")
	// TextDisconnectedLocal: the connection is gone here, but the service
	// did not confirm the revocation (S1-C6): the user is told, never
	// shown a success it cannot back.
	TextDisconnectedLocal = tpl("Your connection is removed here, but the service did not confirm that its access was revoked. You can also revoke it in the service's settings.", "Подключение удалено здесь, но сервис не подтвердил, что отозвал доступ. Доступ можно также отозвать в настройках сервиса.")
	TextDisconnectNone    = tpl("You have no connection to remove for this service.", "У вас нет подключения к этому сервису.")
	TextDisconnectFailed  = tpl("The connection could not be removed. Please try again.", "Не удалось удалить подключение. Пожалуйста, попробуйте ещё раз.")
	TextConnectionsNone   = tpl("You have no connected accounts.", "У вас нет подключённых аккаунтов.")
	TextConnectionsFailed = tpl("Your connections could not be read. Please try again.", "Не удалось прочитать ваши подключения. Пожалуйста, попробуйте ещё раз.")
	// TextConnectionExpired tells the principal, once per connection, that
	// the service stopped accepting a connection and it must be linked
	// again (#1318 slice C2b).
	TextConnectionExpired = tpl("One of your connections has expired and can no longer be used. Send /connections to see which one, then /connect to link it again.", "Одно из ваших подключений истекло и больше не работает. Отправьте /connections, чтобы увидеть какое, затем /connect, чтобы подключить снова.")
	// The bot's command menu (setMyCommands, output.Sender.SetCommands):
	// one description per command.
	CmdNew         = tpl("Start a new conversation", "Начать новый разговор")
	CmdForget      = tpl("Delete all of your conversations", "Удалить все ваши разговоры")
	CmdConsent     = tpl("Show or withdraw your consent", "Показать или отозвать согласие")
	CmdConnect     = tpl("Connect your Telegram account", "Подключить ваш аккаунт Telegram")
	CmdConnections = tpl("Show your connected accounts", "Показать подключённые аккаунты")
	CmdDisconnect  = tpl("Disconnect your Telegram account", "Отключить ваш аккаунт Telegram")

	// TextAssistantUnavailable refuses a principal an admin disabled or one
	// not on the preview allowlist, and tells a principal whose queued or
	// running request was stopped for that reason (#1318). The same text
	// for both, so the reply does not say which.
	TextAssistantUnavailable = tpl("The assistant is not available for your account. /forget still deletes your conversations.", "Ассистент недоступен для вашего аккаунта. /forget по-прежнему удаляет ваши разговоры.")
)
