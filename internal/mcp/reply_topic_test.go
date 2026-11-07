package mcp

import (
	"encoding/json"
	"strings"
	"testing"
)

// A topic named in draft_reply is part of the confirmation: send_reply
// delivers into it and cannot be pointed elsewhere (owner decision on
// mctl-telegram#1175).
func TestReplyTopic_BoundIntoTheConfirmation(t *testing.T) {
	s, f, id := replyServer(t, 9320)
	_, h := s.toolDraftReply()
	res := callReplyTool(t, h, "draft_reply", id, map[string]any{"peer": "@carol_team", "text": "Shipped", "topic_id": float64(12)})
	if res.IsError {
		t.Fatalf("draft_reply: %s", contentText(res))
	}
	var d draftReplyResult
	if err := json.Unmarshal([]byte(contentText(res)), &d); err != nil {
		t.Fatal(err)
	}
	if d.TopicID != 12 || d.TopicTitle != "Releases" || d.Recipient != "channel:4601" {
		t.Fatalf("draft = %+v", d)
	}
	// Extra arguments to send_reply are ignored: only the confirmation counts.
	out := sendReply(t, s, id, map[string]any{"confirmation_id": d.ConfirmationID, "topic_id": float64(99)})
	if out.IsError {
		t.Fatalf("send_reply: %s", contentText(out))
	}
	if len(f.delivered) != 1 || f.delivered[0].target.TopicID != 12 {
		t.Fatalf("delivered = %+v, want one reply into topic 12", f.delivered)
	}
	if !strings.Contains(contentText(out), `"topic_id": 12`) {
		t.Errorf("send_reply result does not name the topic: %s", contentText(out))
	}
}

// Without topic_id nothing about topics is checked or reported.
func TestReplyTopic_AbsentMeansNoTopic(t *testing.T) {
	s, f, id := replyServer(t, 9321)
	d := draftOK(t, s, id, "@carol_team", "hi")
	if d.TopicID != 0 || f.topicChecks != 0 {
		t.Fatalf("draft = %+v, topic checks = %d", d, f.topicChecks)
	}
}

// A topic that is missing, closed, or in a chat without topics is refused
// and leaves no confirmation behind.
func TestReplyTopic_Refusals(t *testing.T) {
	cases := []struct {
		peer  string
		topic any
		want  string
	}{
		{"@carol_team", float64(99), "topic not found"},
		{"@carol_team", float64(13), "closed"},
		{"@alice", float64(12), "has no topics"},
		{"@carol_team", float64(0), "positive topic id"},
		{"@carol_team", float64(-4), "positive topic id"},
	}
	for _, c := range cases {
		s, f, id := replyServer(t, 9322)
		_, h := s.toolDraftReply()
		res := callReplyTool(t, h, "draft_reply", id, map[string]any{"peer": c.peer, "text": "hi", "topic_id": c.topic})
		if !res.IsError || !strings.Contains(contentText(res), c.want) {
			t.Errorf("%s topic %v: isError=%v %q, want %q", c.peer, c.topic, res.IsError, contentText(res), c.want)
		}
		if strings.Contains(contentText(res), "cr_") || len(f.delivered) != 0 {
			t.Errorf("%s topic %v: a confirmation was issued", c.peer, c.topic)
		}
	}
}
