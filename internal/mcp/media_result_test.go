package mcp

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/telegram"
)

func mediaData(s string) *string { return &s }

// TestMediaJSONResult_BelowCapKeepsLegacyShape (T1) verifies that at or below
// the inline cap, mediaJSONResult is byte-for-byte identical to jsonResult:
// same text bytes (MarshalIndent formatting included) and the same
// StructuredContent value.
func TestMediaJSONResult_BelowCapKeepsLegacyShape(t *testing.T) {
	s := &Server{MediaTextInlineCapBytes: mediaTextInlineCapDefault}
	result := messagesResult{
		Messages: []telegram.Message{{ID: 1, MediaData: mediaData("c21hbGw=")}},
		Notice:   untrustedContentNotice,
	}
	mediaBytes := sumMediaDataBytes(result.Messages)
	if mediaBytes > s.MediaTextInlineCapBytes {
		t.Fatalf("test setup: mediaBytes=%d must be <= cap=%d", mediaBytes, s.MediaTextInlineCapBytes)
	}

	got, err := s.mediaJSONResult(result, mediaBytes, func() any { return messagesTextView(result) })
	if err != nil {
		t.Fatalf("mediaJSONResult error: %v", err)
	}
	want, err := jsonResult(result)
	if err != nil {
		t.Fatalf("jsonResult error: %v", err)
	}
	if resultText(got) != resultText(want) {
		t.Errorf("text content = %q, want byte-identical to jsonResult's %q", resultText(got), resultText(want))
	}
	if !strings.Contains(resultText(got), "c21hbGw=") {
		t.Error("below the cap, the base64 must still appear in the text content block")
	}
	gotSC, _ := json.Marshal(got.StructuredContent)
	wantSC, _ := json.Marshal(want.StructuredContent)
	if string(gotSC) != string(wantSC) {
		t.Errorf("StructuredContent = %s, want %s", gotSC, wantSC)
	}
}

// TestMediaJSONResult_CapZeroAlwaysInlines covers the MEDIA_TEXT_INLINE_CAP_BYTES=0
// escape hatch: with the field at its zero value (unset, or explicitly 0), a
// result is always inlined regardless of mediaBytes.
func TestMediaJSONResult_CapZeroAlwaysInlines(t *testing.T) {
	s := &Server{} // MediaTextInlineCapBytes left at zero value
	result := messagesResult{
		Messages: []telegram.Message{{ID: 1, MediaData: mediaData(strings.Repeat("A", 2_000_000))}},
		Notice:   untrustedContentNotice,
	}
	mediaBytes := sumMediaDataBytes(result.Messages)
	got, err := s.mediaJSONResult(result, mediaBytes, func() any { return messagesTextView(result) })
	if err != nil {
		t.Fatalf("mediaJSONResult error: %v", err)
	}
	if !strings.Contains(resultText(got), strings.Repeat("A", 2_000_000)) {
		t.Error("cap==0 must always inline the base64 in the text content block")
	}
}

// TestMediaJSONResult_AboveCapEmitsBytesOnce (T2) verifies that above the
// cap, the text block contains the placeholder and none of the base64;
// StructuredContent still carries the full payload; and the full result
// marshals to JSON containing the base64 exactly once.
func TestMediaJSONResult_AboveCapEmitsBytesOnce(t *testing.T) {
	s := &Server{MediaTextInlineCapBytes: 10}
	secret := strings.Repeat("B", 100) // > cap of 10
	result := messagesResult{
		Messages: []telegram.Message{{ID: 1, MediaData: mediaData(secret)}},
		Notice:   untrustedContentNotice,
	}
	mediaBytes := sumMediaDataBytes(result.Messages)
	if !s.mediaTextOmitted(mediaBytes) {
		t.Fatalf("test setup: mediaBytes=%d must exceed cap=%d", mediaBytes, s.MediaTextInlineCapBytes)
	}

	got, err := s.mediaJSONResult(result, mediaBytes, func() any { return messagesTextView(result) })
	if err != nil {
		t.Fatalf("mediaJSONResult error: %v", err)
	}
	text := resultText(got)
	if strings.Contains(text, secret) {
		t.Error("text content block must not contain the omitted base64 above the cap")
	}
	if !strings.Contains(text, "omitted") {
		t.Errorf("text content block should carry an omission placeholder, got %q", text)
	}

	sc, ok := got.StructuredContent.(messagesResult)
	if !ok {
		t.Fatalf("StructuredContent = %T, want messagesResult", got.StructuredContent)
	}
	if sc.Messages[0].MediaData == nil || *sc.Messages[0].MediaData != secret {
		t.Error("StructuredContent must still carry the full, non-placeholder base64")
	}

	// The full CallToolResult must marshal with the base64 appearing exactly
	// once — inside structuredContent, not duplicated into the text block.
	full, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal *CallToolResult: %v", err)
	}
	if n := strings.Count(string(full), secret); n != 1 {
		t.Errorf("base64 appears %d times in the marshalled result, want exactly 1", n)
	}
}

// TestBulkMedia_OmittedFlagOnlyWhenOmitted (T3, bulk half) verifies
// media_data_omitted_from_text is true only in omitted mode and absent
// (omitempty) otherwise.
func TestBulkMedia_OmittedFlagOnlyWhenOmitted(t *testing.T) {
	small := mediaData("YQ==") // 4 bytes, well under any realistic cap
	large := mediaData(strings.Repeat("C", 100))

	setFlagIfOmitted := func(s *Server, summary *FetchMediaSummary, msgs []telegram.Message) []byte {
		mediaBytes := sumMediaDataBytes(msgs)
		if s.mediaTextOmitted(mediaBytes) {
			summary.MediaDataOmittedFromText = true
		}
		result := messagesResult{Messages: msgs, Notice: untrustedContentNotice, FetchMediaSummary: summary}
		res, err := s.mediaJSONResult(result, mediaBytes, func() any { return messagesTextView(result) })
		if err != nil {
			t.Fatalf("mediaJSONResult error: %v", err)
		}
		b, err := json.Marshal(res.StructuredContent)
		if err != nil {
			t.Fatalf("marshal StructuredContent: %v", err)
		}
		return b
	}

	t.Run("under cap: flag absent", func(t *testing.T) {
		s := &Server{MediaTextInlineCapBytes: 1000}
		summary := &FetchMediaSummary{Fetched: 1}
		b := setFlagIfOmitted(s, summary, []telegram.Message{{ID: 1, MediaData: small}})
		if strings.Contains(string(b), "media_data_omitted_from_text") {
			t.Errorf("flag must be absent (omitempty) when nothing was omitted, got %s", b)
		}
	})

	t.Run("over cap: flag true", func(t *testing.T) {
		s := &Server{MediaTextInlineCapBytes: 10}
		summary := &FetchMediaSummary{Fetched: 1}
		b := setFlagIfOmitted(s, summary, []telegram.Message{{ID: 1, MediaData: large}})
		if !strings.Contains(string(b), `"media_data_omitted_from_text":true`) {
			t.Errorf("flag must be true when media was omitted, got %s", b)
		}
	})
}

// TestGetMediaResult_AboveCapSetsOmittedFlag (T3, get_media half) mirrors the
// bulk case for getMediaResult.DataOmittedFromText.
func TestGetMediaResult_AboveCapSetsOmittedFlag(t *testing.T) {
	buildResult := func(s *Server, data string) []byte {
		result := getMediaResult{MediaType: "document", Size: int64(len(data)), Data: data}
		mediaBytes := int64(len(data))
		if s.mediaTextOmitted(mediaBytes) {
			result.DataOmittedFromText = true
		}
		res, err := s.mediaJSONResult(result, mediaBytes, func() any { return getMediaTextView(result) })
		if err != nil {
			t.Fatalf("mediaJSONResult error: %v", err)
		}
		b, err := json.Marshal(res.StructuredContent)
		if err != nil {
			t.Fatalf("marshal StructuredContent: %v", err)
		}
		return b
	}

	t.Run("under cap: flag absent", func(t *testing.T) {
		b := buildResult(&Server{MediaTextInlineCapBytes: 1000}, "YQ==")
		if strings.Contains(string(b), "data_omitted_from_text") {
			t.Errorf("flag must be absent (omitempty) when nothing was omitted, got %s", b)
		}
	})

	t.Run("over cap: flag true", func(t *testing.T) {
		b := buildResult(&Server{MediaTextInlineCapBytes: 10}, strings.Repeat("D", 100))
		if !strings.Contains(string(b), `"data_omitted_from_text":true`) {
			t.Errorf("flag must be true when data was omitted, got %s", b)
		}
	})
}

// TestMessagesTextView_CopiesNotMutatesOriginal guards messagesTextView's
// documented no-mutation contract.
func TestMessagesTextView_CopiesNotMutatesOriginal(t *testing.T) {
	original := "originalbase64"
	result := messagesResult{Messages: []telegram.Message{{ID: 1, MediaData: mediaData(original)}}}
	view := messagesTextView(result)
	if view.Messages[0].MediaData == nil || *view.Messages[0].MediaData == original {
		t.Error("messagesTextView must replace MediaData with a placeholder in the copy")
	}
	if result.Messages[0].MediaData == nil || *result.Messages[0].MediaData != original {
		t.Error("messagesTextView must not mutate the original result")
	}
}

// TestGetMediaTextView_CopiesNotMutatesOriginal mirrors the above for
// getMediaTextView.
func TestGetMediaTextView_CopiesNotMutatesOriginal(t *testing.T) {
	original := getMediaResult{MediaType: "document", Data: "originalbase64"}
	view := getMediaTextView(original)
	if view.Data == original.Data {
		t.Error("getMediaTextView must replace Data with a placeholder in the copy")
	}
	if original.Data != "originalbase64" {
		t.Error("getMediaTextView must not mutate the original result")
	}
}
