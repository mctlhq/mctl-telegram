package telegram

import (
	"testing"
	"time"

	"github.com/gotd/td/tg"
)

func TestUniqueOutgoingMatch(t *testing.T) {
	since := time.Unix(1_800_000_000, 500_000_000)
	at := int(since.Unix())
	out := func(id, date int, text string) tg.MessageClass {
		return &tg.Message{ID: id, Out: true, Date: date, Message: text}
	}
	cases := []struct {
		name   string
		msgs   []tg.MessageClass
		wantID int
		found  bool
	}{
		{"single match, same second as since", []tg.MessageClass{out(10, at, "hello Bob ")}, 10, true},
		{"none", []tg.MessageClass{out(10, at, "other")}, 0, false},
		{"incoming copy ignored", []tg.MessageClass{&tg.Message{ID: 11, Date: at, Message: "hello Bob"}}, 0, false},
		{"within clock slack before the send", []tg.MessageClass{out(16, at-20, "hello Bob")}, 16, true},
		{"older than the send", []tg.MessageClass{out(12, at-60, "hello Bob")}, 0, false},
		{"two matches are ambiguous", []tg.MessageClass{out(13, at, "hello Bob"), out(14, at+5, "hello Bob")}, 0, false},
	}
	for _, tc := range cases {
		id, found := uniqueOutgoingMatch(tc.msgs, "hello Bob", since, true)
		if found != tc.found || (found && id != tc.wantID) {
			t.Errorf("%s: id=%d found=%v, want id=%d found=%v", tc.name, id, found, tc.wantID, tc.found)
		}
	}
	// Saved Messages history does not reliably set Out, so the self lookup
	// does not require it.
	saved := []tg.MessageClass{&tg.Message{ID: 15, Date: at, Message: "hello Bob"}}
	if id, found := uniqueOutgoingMatch(saved, "hello Bob", since, false); !found || id != 15 {
		t.Errorf("saved message without Out: id=%d found=%v, want 15", id, found)
	}
}
