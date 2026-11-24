package agentworker

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func streamServer(t *testing.T, status int, body string, gotBody *string) *OpenAIClient {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if gotBody != nil {
			*gotBody = string(b)
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return &OpenAIClient{BaseURL: srv.URL, APIKey: "k", Model: "m"}
}

func TestChatStream_AssemblesTextToolCallsAndUsage(t *testing.T) {
	sse := strings.Join([]string{
		`data: {"choices":[{"delta":{"reasoning_content":"thinking about it"}}]}`,
		`data: {"choices":[{"delta":{"content":"Let me "}}]}`,
		`data: {"choices":[{"delta":{"content":"check."}}]}`,
		`data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"c1","function":{"name":"tg__get","arguments":"{\"a\":"}}]}}]}`,
		`data: {"choices":[{"delta":{"tool_calls":[{"index":1,"id":"c2","function":{"name":"tg__obj","arguments":{"x":1}}}]}}]}`,
		`data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"1}"}}]},"finish_reason":"tool_calls"}]}`,
		`data: {"choices":[],"usage":{"prompt_tokens":10,"completion_tokens":5}}`,
		`data: [DONE]`, ``,
	}, "\n\n")
	var sent string
	c := streamServer(t, 200, sse, &sent)
	var texts []string
	res, err := c.chatStream(context.Background(), []ChatMessage{{Role: "user", Content: "hi"}}, nil, func(s string) { texts = append(texts, s) })
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(texts, "|") != "Let me |Let me check." {
		t.Fatalf("texts %q", texts)
	}
	if len(res.Message.ToolCalls) != 2 || res.Message.ToolCalls[0].Arguments != `{"a":1}` || res.Message.ToolCalls[1].Arguments != `{"x":1}` {
		t.Fatalf("tool calls %+v", res.Message.ToolCalls)
	}
	if !res.UsageReported || res.Usage.PromptTokens != 10 || res.FinishReason != "tool_calls" {
		t.Fatalf("result %+v", res)
	}
	var req map[string]any
	_ = json.Unmarshal([]byte(sent), &req)
	opts, _ := req["stream_options"].(map[string]any)
	if req["stream"] != true || opts["include_usage"] != true {
		t.Fatalf("request %s", sent)
	}
}

func TestChat_NonStreamBodyHasNoStreamOptions(t *testing.T) {
	var sent string
	c := streamServer(t, 200, `{"choices":[{"message":{"role":"assistant","content":"x"}}]}`, &sent)
	if _, err := c.chat(context.Background(), nil, nil); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sent, "stream_options") || !strings.Contains(sent, `"stream":false`) {
		t.Fatalf("body %s", sent)
	}
}

func TestChatStream_FailureModes(t *testing.T) {
	c := streamServer(t, 429, "echoed secret", nil)
	_, err := c.chatStream(context.Background(), nil, nil, nil)
	var pe *ProviderError
	if !errors.As(err, &pe) || pe.Status != 429 || strings.Contains(err.Error(), "secret") {
		t.Fatalf("err %v", err)
	}
	c = streamServer(t, 200, `data: {"choices":[{"delta":{"content":"half"}}]}`+"\n\n", nil)
	if _, err := c.chatStream(context.Background(), nil, nil, nil); err == nil {
		t.Fatal("truncated stream accepted")
	}
	c = streamServer(t, 200, "data: {not json}\n\ndata: [DONE]\n\n", nil)
	if _, err := c.chatStream(context.Background(), nil, nil, nil); err == nil {
		t.Fatal("malformed chunk accepted")
	}
	// No usage chunk: unknown spend, fail closed.
	c = streamServer(t, 200, `data: {"choices":[{"delta":{"content":"ok"},"finish_reason":"stop"}]}`+"\n\ndata: [DONE]\n\n", nil)
	res, err := c.chatStream(context.Background(), nil, nil, nil)
	if err != nil || res.UsageReported {
		t.Fatalf("res %+v err %v", res, err)
	}
}

func TestPADrafter_BatchesLatestWinsAndStops(t *testing.T) {
	var mu sync.Mutex
	var texts []string
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b struct{ Text string }
		_ = json.NewDecoder(r.Body).Decode(&b)
		mu.Lock()
		texts = append(texts, b.Text)
		st := status
		mu.Unlock()
		w.WriteHeader(st)
		_, _ = io.WriteString(w, `{"shown":true}`)
	}))
	defer srv.Close()
	w := &PAWorker{BaseURL: srv.URL}
	d := newPADrafter(context.Background(), w, "tok")
	d.minInterval = 20 * time.Millisecond
	d.minDelta = 10
	d.update("Hello")
	waitUntil(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(texts) == 1 })
	d.update("Hello w")                                 // below min delta
	d.update("Hello world, this is a longer text now.") // latest wins
	waitUntil(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(texts) == 2 })
	mu.Lock()
	if texts[1] != "Hello world, this is a longer text now." {
		t.Fatalf("texts %q", texts)
	}
	status = http.StatusNotFound
	mu.Unlock()
	d.update("Hello world, this is a longer text now. And even more text here.")
	waitUntil(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(texts) == 3 })
	d.update(strings.Repeat("more text. ", 40))
	time.Sleep(80 * time.Millisecond)
	d.close()
	mu.Lock()
	n := len(texts)
	mu.Unlock()
	d.update("after close, long enough to be posted for sure")
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if len(texts) != n || n != 3 {
		t.Fatalf("posts after a 404 or close: %d %q", len(texts), texts)
	}
}

func waitUntil(t *testing.T, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(time.Millisecond)
	}
}
