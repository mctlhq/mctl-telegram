package telegram

import (
	"errors"
	"testing"

	"github.com/gotd/td/tg"
)

func TestReadHistoryRequest_Routing(t *testing.T) {
	ch, chat, err := readHistoryRequest(&tg.InputPeerChannel{ChannelID: 9, AccessHash: 3}, 77)
	if err != nil || chat != nil || ch == nil || ch.MaxID != 77 {
		t.Fatalf("channel: %+v %+v %v", ch, chat, err)
	}
	if ic, ok := ch.Channel.(*tg.InputChannel); !ok || ic.ChannelID != 9 || ic.AccessHash != 3 {
		t.Fatalf("channel input = %#v", ch.Channel)
	}
	if ch, _, _ := readHistoryRequest(&tg.InputPeerChannelFromMessage{ChannelID: 9, MsgID: 5}, 1); ch == nil {
		t.Fatal("channel-from-message did not use channels.readHistory")
	}
	for _, p := range []tg.InputPeerClass{&tg.InputPeerUser{UserID: 7120}, &tg.InputPeerChat{ChatID: 4}} {
		ch, chat, err := readHistoryRequest(p, 12)
		if err != nil || ch != nil || chat == nil || chat.MaxID != 12 || chat.Peer != p {
			t.Errorf("%T: %+v %+v %v", p, ch, chat, err)
		}
	}
	if _, _, err := readHistoryRequest(&tg.InputPeerSelf{}, 1); !errors.Is(err, errReadNotAChat) {
		t.Errorf("self: err = %v", err)
	}
}
