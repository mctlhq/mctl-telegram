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

// ConsentTextSHA256 is the hex SHA-256 of ConsentText. A stored consent is
// valid only for this exact text.
func ConsentTextSHA256() string {
	sum := sha256.Sum256([]byte(ConsentText))
	return hex.EncodeToString(sum[:])
}

// Satisfied reports whether rec is consent to the current version and text.
// A withdrawn record, another version or another text is not (S1-N3).
func Satisfied(rec ConsentRecord) bool {
	return rec.State == ConsentAccepted && rec.Version == ConsentVersion && rec.TextSHA256 == ConsentTextSHA256()
}
