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
			fmt.Sprintf(`{"update_id":1,"callback_query":{"id":"cb","from":{"id":%d,"is_bot":false},"message":{"message_id":1,"chat":{"id":%d,"type":"private"}}}}`, bobID, aliceID),
			DropChatMismatch,
		},
		{
			"callback from a group message",
			fmt.Sprintf(`{"update_id":1,"callback_query":{"id":"cb","from":{"id":%d,"is_bot":false},"message":{"message_id":1,"chat":{"id":%d,"type":"group"}}}}`, aliceID, groupChat),
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
			fmt.Sprintf(`{"update_id":1,"callback_query":{"id":"cb","from":{"id":%d,"is_bot":false}}}`, aliceID),
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
