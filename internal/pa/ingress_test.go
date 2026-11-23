package pa

import (
	"fmt"
	"strings"
	"testing"
)

// Synthetic personas, matching internal/db/agent_turn_claim_test.go
// (Alice=555, Bob=556). groupChat and channelChat are synthetic negative ids.
const (
	aliceID     int64 = 555
	bobID       int64 = 556
	groupChat   int64 = -555
	channelChat int64 = -1000000000555
)

func privateMessage(updateID, user int64, extra string) string {
	return fmt.Sprintf(`{"update_id":%d,"message":{"message_id":7,"date":1,`+
		`"from":{"id":%d,"is_bot":false,"first_name":"Alice"},`+
		`"chat":{"id":%d,"type":"private"},"text":"hello"%s}}`, updateID, user, user, extra)
}

func TestFilter_AcceptsPrivateMessage(t *testing.T) {
	u, outcome := Filter([]byte(privateMessage(10, aliceID, "")))
	if outcome != OutcomeAccepted {
		t.Fatalf("outcome = %q, want accepted", outcome)
	}
	if u.UpdateID() != 10 || u.Kind() != KindMessage || u.Principal().TelegramID() != aliceID || u.MessageID() != 7 {
		t.Fatalf("verified update = %+v", u)
	}
}

func TestFilter_AcceptsPrivateCallback(t *testing.T) {
	body := fmt.Sprintf(`{"update_id":11,"callback_query":{"id":"cb1","chat_instance":"x","data":"opaque-1",`+
		`"from":{"id":%d,"is_bot":false},`+
		`"message":{"message_id":9,"date":1,"chat":{"id":%d,"type":"private"}}}}`, aliceID, aliceID)
	u, outcome := Filter([]byte(body))
	if outcome != OutcomeAccepted {
		t.Fatalf("outcome = %q, want accepted", outcome)
	}
	if u.Kind() != KindCallbackQuery || u.Principal().TelegramID() != aliceID || u.CallbackID() != "cb1" ||
		u.CallbackData() != "opaque-1" || u.MessageID() != 9 {
		t.Fatalf("verified update = %+v", u)
	}
}

// TestFilter_S1B1 is S1-B1: business, group, channel, sender_chat, via_bot
// and chat.id != from.id updates are dropped. Each case names the guard it
// exercises; the mutation runs in the PR disable each guard in turn.
func TestFilter_S1B1(t *testing.T) {
	cases := []struct {
		name, body, want string
	}{
		{
			"business_message update",
			fmt.Sprintf(`{"update_id":1,"business_message":{"message_id":1,"business_connection_id":"bc","from":{"id":%d,"is_bot":false},"chat":{"id":%d,"type":"private"}}}`, bobID, bobID),
			DropBusiness,
		},
		{
			"business_connection update",
			fmt.Sprintf(`{"update_id":1,"business_connection":{"id":"bc","user":{"id":%d,"is_bot":false},"user_chat_id":%d,"date":1,"is_enabled":true}}`, aliceID, aliceID),
			DropBusiness,
		},
		{
			"edited_business_message update",
			fmt.Sprintf(`{"update_id":1,"edited_business_message":{"message_id":1,"from":{"id":%d,"is_bot":false},"chat":{"id":%d,"type":"private"}}}`, bobID, bobID),
			DropBusiness,
		},
		{
			"message with business_connection_id",
			privateMessage(1, aliceID, `,"business_connection_id":"bc"`),
			DropBusiness,
		},
		{
			"message with sender_business_bot",
			privateMessage(1, aliceID, `,"sender_business_bot":{"id":1,"is_bot":true}`),
			DropBusiness,
		},
		{
			"group message",
			fmt.Sprintf(`{"update_id":1,"message":{"message_id":1,"from":{"id":%d,"is_bot":false},"chat":{"id":%d,"type":"group"}}}`, aliceID, groupChat),
			DropNotPrivate,
		},
		{
			"supergroup message",
			fmt.Sprintf(`{"update_id":1,"message":{"message_id":1,"from":{"id":%d,"is_bot":false},"chat":{"id":%d,"type":"supergroup"}}}`, aliceID, channelChat),
			DropNotPrivate,
		},
		{
			"channel_post update",
			fmt.Sprintf(`{"update_id":1,"channel_post":{"message_id":1,"chat":{"id":%d,"type":"channel"}}}`, channelChat),
			DropUnsupportedKind,
		},
		{
			"message in a channel chat",
			fmt.Sprintf(`{"update_id":1,"message":{"message_id":1,"from":{"id":%d,"is_bot":false},"chat":{"id":%d,"type":"channel"}}}`, aliceID, channelChat),
			DropNotPrivate,
		},
		{
			"sender_chat",
			privateMessage(1, aliceID, fmt.Sprintf(`,"sender_chat":{"id":%d,"type":"channel"}`, channelChat)),
			DropSenderChat,
		},
		{
			"sender_chat null is still present",
			privateMessage(1, aliceID, `,"sender_chat":null`),
			DropSenderChat,
		},
		{
			"via_bot",
			privateMessage(1, aliceID, `,"via_bot":{"id":1,"is_bot":true}`),
			DropViaBot,
		},
		{
			"chat.id != from.id (Bob writing into Alice's chat id)",
			fmt.Sprintf(`{"update_id":1,"message":{"message_id":1,"from":{"id":%d,"is_bot":false},"chat":{"id":%d,"type":"private"}}}`, bobID, aliceID),
			DropChatMismatch,
		},
		{
			"callback: Bob pressing a button in Alice's chat",
			fmt.Sprintf(`{"update_id":1,"callback_query":{"id":"cb","data":"opaque-1","from":{"id":%d,"is_bot":false},"message":{"message_id":1,"chat":{"id":%d,"type":"private"}}}}`, bobID, aliceID),
			DropChatMismatch,
		},
		{
			"callback from a group message",
			fmt.Sprintf(`{"update_id":1,"callback_query":{"id":"cb","data":"opaque-1","from":{"id":%d,"is_bot":false},"message":{"message_id":1,"chat":{"id":%d,"type":"group"}}}}`, aliceID, groupChat),
			DropNotPrivate,
		},
		{
			"callback on an inline message",
			fmt.Sprintf(`{"update_id":1,"callback_query":{"id":"cb","inline_message_id":"im","from":{"id":%d,"is_bot":false}}}`, aliceID),
			DropInlineCallback,
		},
		{
			"callback carrying both inline_message_id and a message",
			fmt.Sprintf(`{"update_id":1,"callback_query":{"id":"cb","inline_message_id":"im","from":{"id":%d,"is_bot":false},"message":{"message_id":1,"chat":{"id":%d,"type":"private"}}}}`, aliceID, aliceID),
			DropInlineCallback,
		},
		{
			"callback without a message",
			fmt.Sprintf(`{"update_id":1,"callback_query":{"id":"cb","data":"opaque-1","from":{"id":%d,"is_bot":false}}}`, aliceID),
			DropInlineCallback,
		},
		{
			"callback_data over 64 bytes",
			fmt.Sprintf(`{"update_id":1,"callback_query":{"id":"cb","data":%q,"from":{"id":%d,"is_bot":false},"message":{"message_id":1,"chat":{"id":%d,"type":"private"}}}}`, strings.Repeat("d", 65), aliceID, aliceID),
			DropMalformed,
		},
		{
			"bot sender",
			fmt.Sprintf(`{"update_id":1,"message":{"message_id":1,"from":{"id":%d,"is_bot":true},"chat":{"id":%d,"type":"private"}}}`, aliceID, aliceID),
			DropBotSender,
		},
		{
			"no from",
			fmt.Sprintf(`{"update_id":1,"message":{"message_id":1,"chat":{"id":%d,"type":"private"}}}`, aliceID),
			DropNoSender,
		},
		{
			"edited_message",
			fmt.Sprintf(`{"update_id":1,"edited_message":{"message_id":1,"from":{"id":%d,"is_bot":false},"chat":{"id":%d,"type":"private"}}}`, aliceID, aliceID),
			DropUnsupportedKind,
		},
		{
			"two payloads in one update",
			fmt.Sprintf(`{"update_id":1,"message":{"message_id":1,"from":{"id":%d,"is_bot":false},"chat":{"id":%d,"type":"private"}},"edited_message":{}}`, aliceID, aliceID),
			DropUnsupportedKind,
		},
		{
			"callback on a business message",
			fmt.Sprintf(`{"update_id":1,"callback_query":{"id":"cb","data":"opaque-1","from":{"id":%d,"is_bot":false},"message":{"message_id":1,"business_connection_id":"bc","chat":{"id":%d,"type":"private"}}}}`, aliceID, aliceID),
			DropBusiness,
		},
		{
			"callback on a via_bot message",
			fmt.Sprintf(`{"update_id":1,"callback_query":{"id":"cb","data":"opaque-1","from":{"id":%d,"is_bot":false},"message":{"message_id":1,"via_bot":{"id":1,"is_bot":true},"chat":{"id":%d,"type":"private"}}}}`, aliceID, aliceID),
			DropViaBot,
		},
		{
			"callback on a sender_chat message",
			fmt.Sprintf(`{"update_id":1,"callback_query":{"id":"cb","data":"opaque-1","from":{"id":%d,"is_bot":false},"message":{"message_id":1,"sender_chat":{"id":%d,"type":"channel"},"chat":{"id":%d,"type":"private"}}}}`, aliceID, channelChat, aliceID),
			DropSenderChat,
		},
		{
			"callback from a bot sender",
			fmt.Sprintf(`{"update_id":1,"callback_query":{"id":"cb","data":"opaque-1","from":{"id":%d,"is_bot":true},"message":{"message_id":1,"chat":{"id":%d,"type":"private"}}}}`, aliceID, aliceID),
			DropBotSender,
		},
		{
			"negative from.id",
			fmt.Sprintf(`{"update_id":1,"message":{"message_id":1,"from":{"id":%d,"is_bot":false},"chat":{"id":%d,"type":"private"}}}`, groupChat, groupChat),
			DropNoSender,
		},
		{
			"my_chat_member",
			fmt.Sprintf(`{"update_id":1,"my_chat_member":{"chat":{"id":%d,"type":"private"},"from":{"id":%d,"is_bot":false},"date":1}}`, aliceID, aliceID),
			DropUnsupportedKind,
		},
		{
			"inline_query",
			fmt.Sprintf(`{"update_id":1,"inline_query":{"id":"iq","from":{"id":%d,"is_bot":false},"query":"q","offset":""}}`, aliceID),
			DropUnsupportedKind,
		},
		{
			"chosen_inline_result",
			fmt.Sprintf(`{"update_id":1,"chosen_inline_result":{"result_id":"r","from":{"id":%d,"is_bot":false},"query":"q"}}`, aliceID),
			DropUnsupportedKind,
		},
		// Slice (a) review follow-ups: a callback the PA cannot resolve
		// under (principal, id) is dropped at the filter.
		{
			"callback without data",
			fmt.Sprintf(`{"update_id":1,"callback_query":{"id":"cb","from":{"id":%d,"is_bot":false},"message":{"message_id":1,"chat":{"id":%d,"type":"private"}}}}`, aliceID, aliceID),
			DropCallbackNoData,
		},
		{
			"callback with empty data",
			fmt.Sprintf(`{"update_id":1,"callback_query":{"id":"cb","data":"","from":{"id":%d,"is_bot":false},"message":{"message_id":1,"chat":{"id":%d,"type":"private"}}}}`, aliceID, aliceID),
			DropCallbackNoData,
		},
		{
			"callback with null data",
			fmt.Sprintf(`{"update_id":1,"callback_query":{"id":"cb","data":null,"from":{"id":%d,"is_bot":false},"message":{"message_id":1,"chat":{"id":%d,"type":"private"}}}}`, aliceID, aliceID),
			DropCallbackNoData,
		},
		{
			"callback with game_short_name",
			fmt.Sprintf(`{"update_id":1,"callback_query":{"id":"cb","game_short_name":"g","from":{"id":%d,"is_bot":false},"message":{"message_id":1,"chat":{"id":%d,"type":"private"}}}}`, aliceID, aliceID),
			DropGameCallback,
		},
		{
			"callback with game_short_name and data",
			fmt.Sprintf(`{"update_id":1,"callback_query":{"id":"cb","data":"opaque-1","game_short_name":"g","from":{"id":%d,"is_bot":false},"message":{"message_id":1,"chat":{"id":%d,"type":"private"}}}}`, aliceID, aliceID),
			DropGameCallback,
		},
		{
			"callback data of the wrong type",
			fmt.Sprintf(`{"update_id":1,"callback_query":{"id":"cb","data":7,"from":{"id":%d,"is_bot":false},"message":{"message_id":1,"chat":{"id":%d,"type":"private"}}}}`, aliceID, aliceID),
			DropMalformed,
		},
		{"message text of the wrong type", privateMessage(1, aliceID, `,"caption":{"x":1}`), DropMalformed},
		{"reply_to_message of the wrong type", privateMessage(1, aliceID, `,"reply_to_message":"x"`), DropMalformed},
		{"update_id overflows int64", `{"update_id":9223372036854775808,"message":{}}`, DropMalformed},
		{"float update_id", `{"update_id":1.5,"message":{}}`, DropMalformed},
		{"exponent update_id", `{"update_id":1e3,"message":{}}`, DropMalformed},
		{"negative update_id", `{"update_id":-1,"message":{}}`, DropMalformed},
		{"no update_id", `{"message":{}}`, DropMalformed},
		{"not json", `not json`, DropMalformed},
		{"null message", `{"update_id":1,"message":null}`, DropMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u, outcome := Filter([]byte(tc.body))
			if outcome != tc.want {
				t.Fatalf("outcome = %q, want %q", outcome, tc.want)
			}
			if !u.Principal().IsZero() {
				t.Fatalf("a dropped update carried a principal")
			}
		})
	}
}

// from.language_code is kept for the bot's own texts, on messages and
// button presses; an update without it has "".
func TestFilter_LanguageCode(t *testing.T) {
	msg := fmt.Sprintf(`{"update_id":12,"message":{"message_id":7,"date":1,`+
		`"from":{"id":%d,"is_bot":false,"first_name":"Alice","language_code":"ru"},`+
		`"chat":{"id":%d,"type":"private"},"text":"hello"}}`, aliceID, aliceID)
	cb := fmt.Sprintf(`{"update_id":13,"callback_query":{"id":"cb1","chat_instance":"x","data":"opaque-1",`+
		`"from":{"id":%d,"is_bot":false,"language_code":"ru-RU"},`+
		`"message":{"message_id":9,"date":1,"chat":{"id":%d,"type":"private"}}}}`, aliceID, aliceID)
	for body, want := range map[string]string{msg: "ru", cb: "ru-RU", privateMessage(14, aliceID, ""): ""} {
		u, outcome := Filter([]byte(body))
		if outcome != OutcomeAccepted || u.LanguageCode() != want {
			t.Errorf("outcome %q, language %q, want %q", outcome, u.LanguageCode(), want)
		}
	}
}
