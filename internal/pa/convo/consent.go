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
