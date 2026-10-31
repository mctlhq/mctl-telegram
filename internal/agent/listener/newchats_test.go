package listener

import (
	"context"
	"errors"
	"testing"

	"github.com/gotd/td/tg"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

// TestOnMessage_NewChatsOnly: with NewChatsOnly on, a chat is handled only
// when its first message has no earlier history. A chat with history, or one
// whose history cannot be read, is stored closed and its job never runs.
func TestOnMessage_NewChatsOnly(t *testing.T) {
	cases := []struct {
		name      string
		on        bool
		api       *fakeSavedHistoryAPI
		wantState string
	}{
		{"first contact", true, &fakeSavedHistoryAPI{}, db.ConversationActive},
		// Even if Telegram returned the anchor message itself, it is not
		// earlier history.
		{"anchor only", true, &fakeSavedHistoryAPI{results: []historyResult{{messages: []tg.MessageClass{
			&tg.Message{ID: 42, PeerID: &tg.PeerUser{UserID: recruit}, Message: "Hello, Carol here"},
		}}}}, db.ConversationActive},
		{"anchor and earlier", true, &fakeSavedHistoryAPI{results: []historyResult{{messages: []tg.MessageClass{
			&tg.Message{ID: 42, PeerID: &tg.PeerUser{UserID: recruit}, Message: "Hello, Carol here"},
			&tg.Message{ID: 7, PeerID: &tg.PeerUser{UserID: recruit}, Message: "last year"},
		}}}}, db.ConversationClosed},
		{"earlier history", true, &fakeSavedHistoryAPI{results: []historyResult{{messages: []tg.MessageClass{
			&tg.Message{ID: 7, PeerID: &tg.PeerUser{UserID: recruit}, Message: "last year"},
		}}}}, db.ConversationClosed},
		{"earlier service message", true, &fakeSavedHistoryAPI{results: []historyResult{{messages: []tg.MessageClass{
			&tg.MessageService{ID: 7, PeerID: &tg.PeerUser{UserID: recruit}},
		}}}}, db.ConversationClosed},
		{"history unreadable", true, &fakeSavedHistoryAPI{results: []historyResult{{err: errors.New("flood")}}}, db.ConversationClosed},
		{"no client yet", true, nil, db.ConversationClosed},
		{"flag off", false, &fakeSavedHistoryAPI{results: []historyResult{{messages: []tg.MessageClass{
			&tg.Message{ID: 7, PeerID: &tg.PeerUser{UserID: recruit}, Message: "last year"},
		}}}}, db.ConversationActive},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			l, store, acct := newTestListener(t, nil)
			l.NewChatsOnly = tc.on
			if tc.api != nil {
				acct.history = tc.api
			}
			msg := &tg.Message{ID: 42, PeerID: &tg.PeerUser{UserID: recruit}, Message: "Hello, Carol here"}
			if err := l.onMessage(ctx, acct, ents(&tg.User{ID: recruit, AccessHash: 9, Username: "carol_hr", FirstName: "Carol"}), msg, false); err != nil {
				t.Fatalf("onMessage: %v", err)
			}
			conv, err := store.GetConversationByPeer(ctx, acct.userID, recruit)
			if err != nil {
				t.Fatalf("conversation: %v", err)
			}
			if conv.State != tc.wantState {
				t.Fatalf("state = %q, want %q", conv.State, tc.wantState)
			}
			var status string
			if err := store.DB.QueryRowContext(ctx, `SELECT status FROM agent_jobs WHERE conversation_id = $1`, conv.ID).Scan(&status); err != nil {
				t.Fatalf("job: %v", err)
			}
			wantJob := map[string]string{db.ConversationActive: db.JobPending, db.ConversationClosed: db.JobIgnored}[tc.wantState]
			if status != wantJob {
				t.Fatalf("job status = %q, want %q", status, wantJob)
			}
			if tc.on && tc.api != nil {
				if len(tc.api.requests) != 1 {
					t.Fatalf("history requests = %d, want 1", len(tc.api.requests))
				}
				r := tc.api.requests[0]
				p, ok := r.Peer.(*tg.InputPeerUser)
				if !ok || p.UserID != recruit || p.AccessHash != 9 || r.OffsetID != 42 || r.Limit < 2 {
					t.Fatalf("history request = %+v peer %+v", r, r.Peer)
				}
			}

			// A later message in an existing chat never asks Telegram again
			// and keeps the stored state; /mctl continue still reopens it.
			msg2 := &tg.Message{ID: 43, PeerID: &tg.PeerUser{UserID: recruit}, Message: "Any news?"}
			if err := l.onMessage(ctx, acct, ents(&tg.User{ID: recruit, AccessHash: 9}), msg2, false); err != nil {
				t.Fatalf("second onMessage: %v", err)
			}
			if tc.on && tc.api != nil && len(tc.api.requests) != 1 {
				t.Fatalf("history asked again for an existing chat: %d requests", len(tc.api.requests))
			}
			if again, _ := store.GetConversationByPeer(ctx, acct.userID, recruit); again.State != tc.wantState {
				t.Fatalf("state changed to %q", again.State)
			}
		})
	}
}
