package mcp

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/gotd/td/tgerr"
	mcplib "github.com/mark3labs/mcp-go/mcp"
)

func TestFloodWaitSeconds(t *testing.T) {
	cases := []struct {
		code   string
		wantN  int
		wantOK bool
	}{
		{"FLOOD_WAIT_0", 0, true},
		{"FLOOD_WAIT_30", 30, true},
		{"FLOOD_WAIT_3600", 3600, true},
		{"SLOWMODE_WAIT_45", 45, true},
		{"PEER_ID_INVALID", 0, false},
		{"", 0, false},
		{"FLOOD_WAIT_", 0, false},
		{"FLOOD_WAIT_abc", 0, false},
	}
	for _, tc := range cases {
		n, ok := floodWaitSeconds(tc.code)
		if ok != tc.wantOK || n != tc.wantN {
			t.Errorf("floodWaitSeconds(%q) = (%d, %v), want (%d, %v)",
				tc.code, n, ok, tc.wantN, tc.wantOK)
		}
	}
}

func contentText(result *mcplib.CallToolResult) string {
	for _, c := range result.Content {
		if tc, ok := c.(mcplib.TextContent); ok {
			return tc.Text
		}
	}
	return ""
}

func TestMtprotoErrResultCatalog(t *testing.T) {
	for key := range mtprotoErrCatalog {
		key := key
		t.Run(key, func(t *testing.T) {
			err := tgerr.New(400, key)
			result := mtprotoErrResult("test_tool", err)
			if result == nil {
				t.Fatalf("mtprotoErrResult(%q) returned nil, want non-nil", key)
			}
			if !result.IsError {
				t.Fatalf("mtprotoErrResult(%q).IsError = false, want true", key)
			}
			text := contentText(result)
			if strings.Contains(text, key) {
				t.Errorf("mtprotoErrResult(%q) content contains raw MTProto code: %q", key, text)
			}
		})
	}
}

func TestMtprotoErrResultFloodWait(t *testing.T) {
	err := tgerr.New(420, "FLOOD_WAIT_30")
	result := mtprotoErrResult("test_tool", err)
	if result == nil {
		t.Fatal("expected non-nil result for FLOOD_WAIT_30")
	}
	if !result.IsError {
		t.Fatal("expected IsError=true")
	}
	text := contentText(result)
	var envelope map[string]any
	if err := json.Unmarshal([]byte(text), &envelope); err != nil {
		t.Fatalf("content is not valid JSON: %v — content: %q", err, text)
	}
	if v, ok := envelope["retry_after_seconds"].(float64); !ok || int(v) != 30 {
		t.Errorf("retry_after_seconds = %v, want 30", envelope["retry_after_seconds"])
	}
	if v, _ := envelope["error"].(string); v != "flood_wait" {
		t.Errorf("error = %q, want %q", v, "flood_wait")
	}
	if v, _ := envelope["message"].(string); v == "" {
		t.Error("message must not be empty")
	}
	if v, _ := envelope["action"].(string); v == "" {
		t.Error("action must not be empty")
	}
}

func TestMtprotoErrResultSlowmodeWait(t *testing.T) {
	err := tgerr.New(400, "SLOWMODE_WAIT_60")
	result := mtprotoErrResult("test_tool", err)
	if result == nil {
		t.Fatal("expected non-nil result for SLOWMODE_WAIT_60")
	}
	if !result.IsError {
		t.Fatal("expected IsError=true")
	}
	text := contentText(result)
	var envelope map[string]any
	if err := json.Unmarshal([]byte(text), &envelope); err != nil {
		t.Fatalf("content is not valid JSON: %v — content: %q", err, text)
	}
	if v, ok := envelope["retry_after_seconds"].(float64); !ok || int(v) != 60 {
		t.Errorf("retry_after_seconds = %v, want 60", envelope["retry_after_seconds"])
	}
	if v, _ := envelope["error"].(string); v != "slowmode_wait" {
		t.Errorf("error = %q, want %q", v, "slowmode_wait")
	}
	if v, _ := envelope["message"].(string); v == "" {
		t.Error("message must not be empty")
	}
	if v, _ := envelope["action"].(string); v == "" {
		t.Error("action must not be empty")
	}
}

func TestMtprotoErrResultUnknownCode(t *testing.T) {
	err := tgerr.New(400, "SOME_UNKNOWN_CODE_XYZ")
	result := mtprotoErrResult("test_tool", err)
	if result != nil {
		t.Errorf("expected nil for unknown code, got %+v", result)
	}
}

func TestMtprotoErrResultNonTgerr(t *testing.T) {
	err := errors.New("plain go error")
	result := mtprotoErrResult("test_tool", err)
	if result != nil {
		t.Errorf("expected nil for non-tgerr error, got %+v", result)
	}
}

func TestMtprotoErrResultPeerFlood(t *testing.T) {
	err := tgerr.New(420, "PEER_FLOOD")
	result := mtprotoErrResult("test_tool", err)
	if result == nil {
		t.Fatal("expected non-nil result for PEER_FLOOD")
	}
	if !result.IsError {
		t.Fatal("expected IsError=true")
	}
	text := contentText(result)
	var envelope map[string]any
	if err := json.Unmarshal([]byte(text), &envelope); err != nil {
		t.Fatalf("content is not valid JSON: %v — content: %q", err, text)
	}
	if v, _ := envelope["error"].(string); v != "RISK_GATED" {
		t.Errorf("error = %q, want %q", v, "RISK_GATED")
	}
	if v, ok := envelope["retry_after_seconds"].(float64); !ok || int(v) != 60 {
		t.Errorf("retry_after_seconds = %v, want 60", envelope["retry_after_seconds"])
	}
	if v, _ := envelope["message"].(string); v == "" {
		t.Error("message must not be empty")
	}
	if v, _ := envelope["action"].(string); v == "" {
		t.Error("action must not be empty")
	}
}
