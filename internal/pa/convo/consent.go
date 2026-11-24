package convo

import (
	"crypto/sha256"
	"encoding/hex"
)

// ConsentVersion is the consent the Phase 1 PA requires (threat model T13).
const ConsentVersion = "pa-data-flow/v1"

// ConsentText is the text of ConsentVersion. It names the provider and the
// gateway that reaches it, the data categories and the retention, as T13
// requires; /privacy lists the same recipients.
//
// Changing one character of it changes ConsentTextSHA256, and
// TestConsentTextPinnedToVersion_S1N3 fails until ConsentVersion is bumped
// as well: a principal who agreed to one text is never held to another.
// The retention sentence is why PA_CONVERSATION_TTL is capped at 24 hours.
const ConsentText = `Before the assistant answers you, it needs your consent to this data flow (pa-data-flow/v1).

What is sent: the messages you write to this bot, any text you forward, reply to or quote here, and the results the assistant reads from the services you connect (for example your Telegram chats or your smart home).

Where it goes: to Nebius, the AI model provider that generates the answers, reached through Cloudflare AI Gateway. They process it under their API terms. See https://tg.mctl.ai/privacy.

How long it is kept: a conversation is kept on our servers for at most 24 hours from its start. /new starts a fresh conversation, /forget deletes all of your conversations now, and /consent withdraw stops the assistant and deletes your conversations.

The assistant only reads in this version; it cannot send, change or delete anything on your behalf.`

// ConsentTextRU is ConsentText in Russian, shown to a principal whose
// Telegram client is in Russian. It describes the same data flow, word for
// word, so it is the same ConsentVersion; it has its own hash, and a
// principal is bound to the hash of the text their prompt showed
// (ConsentTextSHA256For). It is pinned like ConsentText: changing it needs
// a version bump too (TestConsentTextPinnedToVersion_S1N3).
const ConsentTextRU = `Прежде чем ассистент ответит вам, ему нужно ваше согласие на эту передачу данных (pa-data-flow/v1).

Что передаётся: сообщения, которые вы пишете этому боту, любой текст, который вы здесь пересылаете, на который отвечаете или который цитируете, а также результаты, которые ассистент читает из подключённых вами сервисов (например, ваших чатов Telegram или умного дома).

Куда: в Nebius, провайдеру ИИ-модели, которая генерирует ответы, через Cloudflare AI Gateway. Они обрабатывают данные на условиях своих API. Подробнее: https://tg.mctl.ai/privacy.

Сколько хранится: разговор хранится на наших серверах не более 24 часов с его начала. /new начинает новый разговор, /forget сразу удаляет все ваши разговоры, а /consent withdraw останавливает ассистента и удаляет ваши разговоры.

В этой версии ассистент только читает: он не может ничего отправлять, изменять или удалять от вашего имени.`

// ConsentTextSHA256 is the hex SHA-256 of ConsentText, the English text.
func ConsentTextSHA256() string { return textSHA256(ConsentText) }

// ConsentTextSHA256RU is the hex SHA-256 of ConsentTextRU.
func ConsentTextSHA256RU() string { return textSHA256(ConsentTextRU) }

// ConsentTextSHA256For is the hash of the text a prompt in Russian (ru)
// or English shows: the hash its button binds and an acceptance stores.
func ConsentTextSHA256For(ru bool) string {
	if ru {
		return ConsentTextSHA256RU()
	}
	return ConsentTextSHA256()
}

func textSHA256(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// Satisfied reports whether rec is consent to the current version and to
// one of its texts, English or Russian. A withdrawn record, another version
// or any other text is not (S1-N3).
func Satisfied(rec ConsentRecord) bool {
	return rec.State == ConsentAccepted && rec.Version == ConsentVersion &&
		(rec.TextSHA256 == ConsentTextSHA256() || rec.TextSHA256 == ConsentTextSHA256RU())
}

// ActionConsentVersion is the consent the PA's actions require on top of
// ConsentVersion (#1320 slice P2-S14c; owner decision 2026-11-21: it is
// asked only while PA_WRITES_ENABLED is on, and the data-flow consent stays
// as it is). It is a record of its own (ActionsSatisfied): accepting or
// changing it never touches the data-flow consent, and a principal with
// the data-flow consent alone keeps every read.
const ActionConsentVersion = "pa-actions/v1"

// ActionConsentText is the text of ActionConsentVersion: what the
// assistant may do, that every action needs the principal's tap unless a
// standing permission covers it, how to revoke, and what is recorded.
//
// It is pinned like ConsentText (TestActionConsentTextPinnedToVersion):
// changing one character, or the set of actions it names, needs a version
// bump, and every principal is then asked again (S1-N3).
const ActionConsentText = `Before the assistant can carry out actions for you, it needs your consent to this (pa-actions/v1). It adds to your consent to the data flow (pa-data-flow/v1), which said the assistant only reads.

What the assistant may do: in a service you connected with access for actions, it may control playback on a speaker, set a speaker's volume, switch a light on or off or change its brightness, color temperature or scene, and start music on a speaker. An action you approve is sent to that service.

Your tap decides: every action is first shown to you on a card with exactly what will be sent, and nothing is sent until you tap Approve. The one exception is a standing permission that you grant yourself with /permissions: it lets the assistant repeat one action on the devices you list, up to the value and until the date it shows, without a card. Starting music always needs a card.

How to stop: /permissions shows and revokes your standing permissions. /disconnect removes a connection and cancels its waiting actions and its permissions. /consent withdraw stops the assistant, cancels every waiting action, revokes every permission and deletes your conversations.

What is recorded: every action, whether carried out, refused or cancelled, is written to an audit log with its time, the service, the name of the action, a fingerprint of its content and the result, not the content itself. The content of an action that waits for your tap is kept encrypted until it is sent, cancelled or expires. An action that was sent cannot be taken back by us.`

// ActionConsentTextRU is ActionConsentText in Russian, with its own hash,
// as ConsentTextRU is for ConsentText.
const ActionConsentTextRU = `Прежде чем ассистент сможет выполнять действия за вас, ему нужно ваше согласие на это (pa-actions/v1). Оно дополняет ваше согласие на передачу данных (pa-data-flow/v1), где сказано, что ассистент только читает.

Что ассистент сможет делать: в сервисе, который вы подключили с доступом для действий, он сможет управлять воспроизведением на колонке, менять громкость колонки, включать и выключать свет, менять его яркость, цветовую температуру или сцену и включать музыку на колонке. Действие, которое вы подтвердили, отправляется в этот сервис.

Решаете вы: каждое действие сначала показывается вам на карточке, где точно указано, что будет отправлено, и ничего не отправляется, пока вы не нажмёте «Подтвердить». Единственное исключение: постоянное разрешение, которое вы сами выдаёте через /permissions. Оно позволяет ассистенту повторять одно действие на перечисленных вами устройствах, не выше указанного значения и до указанной даты, без карточки. Для включения музыки карточка нужна всегда.

Как остановить: /permissions показывает и отзывает ваши постоянные разрешения. /disconnect удаляет подключение и отменяет его ожидающие действия и разрешения. /consent withdraw останавливает ассистента, отменяет все ожидающие действия, отзывает все разрешения и удаляет ваши разговоры.

Что записывается: каждое действие, выполненное, отклонённое или отменённое, записывается в журнал аудита: время, сервис, название действия, отпечаток его содержимого и результат, но не само содержимое. Содержимое действия, которое ждёт вашего нажатия, хранится в зашифрованном виде, пока действие не будет отправлено, отменено или не истечёт. Отправленное действие мы отменить не можем.`

// ActionConsentTextSHA256For is the hash of the action-consent text a
// prompt in Russian (ru) or English shows.
func ActionConsentTextSHA256For(ru bool) string {
	if ru {
		return textSHA256(ActionConsentTextRU)
	}
	return textSHA256(ActionConsentText)
}

// ActionsSatisfied reports whether rec is consent to the current
// action-consent version and to one of its texts. A withdrawn record,
// another version or any other text is not (S1-N3).
func ActionsSatisfied(rec ConsentRecord) bool {
	return rec.State == ConsentAccepted && rec.Version == ActionConsentVersion &&
		(rec.TextSHA256 == ActionConsentTextSHA256For(false) || rec.TextSHA256 == ActionConsentTextSHA256For(true))
}
