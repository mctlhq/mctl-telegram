package telegram

import (
	"context"
	"encoding/json"
	"testing"
)

// A dry-run (realSend=false) must never touch Telegram and must return a
// self-describing preview: sent=false, mode="draft", a human-readable notice,
// and the dry_reason. The explicit "sent" boolean is what lets any client
// (including ChatGPT mobile) render the preview unambiguously instead of
// mistaking a draft for a failed send.
func TestSendMessage_DryRunShape(t *testing.T) {
	res, err := SendMessage(context.Background(), nil, "@bob", "hello", false, "ALLOW_SEND=false", nil, 0)
	if err != nil {
		t.Fatalf("dry-run must not error: %v", err)
	}
	if res.Sent {
		t.Error("dry-run result must have sent=false")
	}
	if res.Mode != "draft" {
		t.Errorf("mode = %q, want draft", res.Mode)
	}
	if res.Notice == "" {
		t.Error("dry-run result must carry a human-readable notice")
	}
	if res.DryReason != "ALLOW_SEND=false" {
		t.Errorf("dry_reason = %q, want the gate reason", res.DryReason)
	}
	if res.MessageID != 0 {
		t.Errorf("dry-run must not have a message_id, got %d", res.MessageID)
	}

	// The marshalled JSON must expose "sent" as a top-level field.
	b, _ := json.Marshal(res)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	if _, ok := m["sent"]; !ok {
		t.Errorf("serialized result missing \"sent\" field: %s", b)
	}
}
