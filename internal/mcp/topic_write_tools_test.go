package mcp

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/bridge"
	"github.com/mctlhq/mctl-telegram/internal/telegram"
)

// Slice 4 of #1175: mark_read and save_draft take a forum topic.

func TestMarkRead_PassesTheTopicAndNamesIt(t *testing.T) {
	s, fake, id := markReadServer(t, true)
	fake.result = telegram.MarkReadResult{Ref: "channel:4601", TopicID: 12, TopicTitle: "Releases"}
	res := callMarkRead(t, s, id, map[string]any{"peer": "@carol_team", "max_id": float64(90), "topic_id": float64(12)})
	if res.IsError || fake.topicID != 12 || fake.maxID != 90 {
		t.Fatalf("isError=%v call=%+v %s", res.IsError, fake, contentText(res))
	}
	out := contentText(res)
	if !strings.Contains(out, `"topic_id": 12`) || !strings.Contains(out, `"topic_title": "Releases"`) || !strings.Contains(out, "other topics stay unread") {
		t.Errorf("result does not name the topic: %s", out)
	}
	// Without topic_id nothing about topics is passed or reported.
	fake.result = telegram.MarkReadResult{Ref: "user:7120"}
	res = callMarkRead(t, s, id, map[string]any{"peer": "user:7120", "max_id": float64(41)})
	if res.IsError || fake.topicID != 0 || strings.Contains(contentText(res), "topic_id") {
		t.Fatalf("no topic: topicID=%d %s", fake.topicID, contentText(res))
	}
}

func TestSaveDraft_PassesTheTopicAndNamesIt(t *testing.T) {
	s, fake, id := draftServer(t)
	fake.result = telegram.DraftResult{Ref: "channel:4601", TopicID: 12, TopicTitle: "Releases"}
	res := callSaveDraft(t, s, id, map[string]any{"peer": "@carol_team", "text": "Release notes draft", "topic_id": float64(12)})
	if res.IsError || fake.topicID != 12 {
		t.Fatalf("isError=%v topicID=%d %s", res.IsError, fake.topicID, contentText(res))
	}
	if out := contentText(res); !strings.Contains(out, `"topic_id": 12`) || !strings.Contains(out, `"topic_title": "Releases"`) {
		t.Errorf("result does not name the topic: %s", out)
	}
}

// A topic that is missing, closed or in a chat without topics is a refusal
// with its own audit row, and a malformed topic_id never reaches Telegram.
func TestTopicWrites_Refusals(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{telegram.ErrTopicNotFound, "topic not found"},
		{telegram.ErrTopicClosed, "closed"},
		{telegram.ErrNotAForum, "has no topics"},
	} {
		s, rf, id := markReadServer(t, true)
		rf.err = tc.err
		res := callMarkRead(t, s, id, map[string]any{"peer": "@carol_team", "max_id": float64(9), "topic_id": float64(99)})
		if !res.IsError || !strings.Contains(contentText(res), tc.want) || !strings.Contains(contentText(res), "list_topics") {
			t.Errorf("mark_read %v: %q", tc.err, contentText(res))
		}
		if got := classifyToolResultReason(res); got != ReasonRefused {
			t.Errorf("mark_read %v: reason = %q, want %q", tc.err, got, ReasonRefused)
		}
		assertAuditTool(t, s, id, "mark_read:topic")

		ds, df, did := draftServer(t)
		df.err = tc.err
		res = callSaveDraft(t, ds, did, map[string]any{"peer": "@carol_team", "text": "hi", "topic_id": float64(99)})
		if !res.IsError || !strings.Contains(contentText(res), tc.want) {
			t.Errorf("save_draft %v: %q", tc.err, contentText(res))
		}
		assertAuditTool(t, ds, did, "save_draft:topic")
	}

	for _, bad := range []any{float64(0), float64(-3), 12.5, "12", float64(1 << 32)} {
		s, rf, id := markReadServer(t, true)
		if res := callMarkRead(t, s, id, map[string]any{"peer": "@carol_team", "max_id": float64(9), "topic_id": bad}); !res.IsError || !strings.Contains(contentText(res), "positive topic id") {
			t.Errorf("mark_read topic_id %v: %q", bad, contentText(res))
		}
		ds, df, did := draftServer(t)
		if res := callSaveDraft(t, ds, did, map[string]any{"peer": "@carol_team", "text": "hi", "topic_id": bad}); !res.IsError || !strings.Contains(contentText(res), "positive topic id") {
			t.Errorf("save_draft topic_id %v: %q", bad, contentText(res))
		}
		if rf.calls != 0 || df.calls != 0 {
			t.Errorf("topic_id %v reached Telegram", bad)
		}
	}
}

func assertAuditTool(t *testing.T, s *Server, id *auth.Identity, tool string) {
	t.Helper()
	rows, err := s.Store.ListAuditFor(context.Background(), id.UserID, 10, time.Time{})
	if err != nil || len(rows) == 0 || rows[0].ToolName != tool || rows[0].Status != "error" {
		t.Fatalf("audit = %+v, %v; want a %s error row", rows, err, tool)
	}
}

// Deferred P3s from #1189: the handler branches the first tests left out.

func TestSaveDraft_LocalBridgeIsRefusedBeforeTelegram(t *testing.T) {
	store := newToolsTestStore(t)
	uid := seedAccountWithMode(t, store, 424252, "local")
	fake := &draftFake{}
	s := &Server{Store: store, AllowSend: true, Hub: bridge.NewHub(), draftSave: fake.save}
	id := &auth.Identity{UserID: uid, Subject: "tg:424252", Scopes: []string{"telegram:messages:send"}}
	res := callSaveDraft(t, s, id, map[string]any{"peer": "user:7120", "text": "Hi Bob"})
	if !res.IsError || contentText(res) != "save_draft is not yet supported for local-bridge accounts" {
		t.Fatalf("local bridge: %q", contentText(res))
	}
	if fake.calls != 0 {
		t.Fatal("Telegram was called for a Local Bridge account")
	}
}

func TestSaveDraft_UnchangedReportsNothingSaved(t *testing.T) {
	s, fake, id := draftServer(t)
	fake.result = telegram.DraftResult{Ref: "user:7120", Unchanged: true}
	res := callSaveDraft(t, s, id, map[string]any{"peer": "user:7120", "text": "Hi Bob"})
	out := contentText(res)
	if res.IsError || !strings.Contains(out, `"unchanged": true`) || !strings.Contains(out, `"saved": false`) || !strings.Contains(out, "nothing was changed") {
		t.Fatalf("unchanged: %s", out)
	}
}

func TestSaveDraft_TelegramErrorIsReportedAndAudited(t *testing.T) {
	s, fake, id := draftServer(t)
	fake.err = errors.New("MessagesSaveDraft: rpc error code 400: PEER_ID_INVALID")
	res := callSaveDraft(t, s, id, map[string]any{"peer": "user:7120", "text": "Hi Bob"})
	if !res.IsError || !strings.Contains(contentText(res), "PEER_ID_INVALID") {
		t.Fatalf("error result = %q", contentText(res))
	}
	assertAuditTool(t, s, id, "save_draft")
}
