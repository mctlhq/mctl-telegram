package agentworker

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	mcplib "github.com/mark3labs/mcp-go/mcp"
)

func TestOpenAIClient_GatewayHeadersAndToolSchema(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/chat/completions" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer provider-key" {
			t.Fatalf("Authorization=%q", got)
		}
		if got := r.Header.Get("cf-aig-authorization"); got != "Bearer gateway-key" {
			t.Fatalf("cf-aig-authorization=%q", got)
		}
		if got := r.Header.Get("cf-aig-collect-log"); got != "false" {
			t.Fatalf("cf-aig-collect-log=%q", got)
		}
		if got := r.Header.Get("cf-aig-skip-cache"); got != "true" {
			t.Fatalf("cf-aig-skip-cache=%q", got)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"done"},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":2}}`))
	}))
	defer srv.Close()

	tool := mcplib.NewTool("get_event", mcplib.WithString("x", mcplib.Required()))
	c := &OpenAIClient{BaseURL: srv.URL, APIKey: "provider-key", GatewayToken: "gateway-key", Model: "model", HTTP: srv.Client()}
	out, err := c.Chat(context.Background(), []ChatMessage{{Role: "user", Content: "hi"}}, []toolDef{{Tool: tool}})
	if err != nil {
		t.Fatal(err)
	}
	if out.Usage.PromptTokens != 10 || out.Usage.CompletionTokens != 2 {
		t.Fatalf("usage=%+v", out.Usage)
	}
	toolsRaw, ok := got["tools"].([]any)
	if !ok || len(toolsRaw) != 1 {
		t.Fatalf("tools=%#v", got["tools"])
	}
	fn := toolsRaw[0].(map[string]any)["function"].(map[string]any)
	params := fn["parameters"].(map[string]any)
	props := params["properties"].(map[string]any)
	if _, ok := props["x"]; !ok {
		t.Fatalf("schema lost x: %#v", params)
	}
}

func TestOpenAIClient_ProviderErrorNeverCarriesBody(t *testing.T) {
	const secret = "telegram message content must not leak"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "3")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(secret))
	}))
	defer srv.Close()
	c := &OpenAIClient{BaseURL: srv.URL, APIKey: "k", Model: "m", HTTP: srv.Client()}
	_, err := c.Chat(context.Background(), []ChatMessage{{Role: "user", Content: secret}}, nil)
	var pe *ProviderError
	if !errors.As(err, &pe) {
		t.Fatalf("err=%T %v", err, err)
	}
	if pe.Status != 429 || pe.RetryAfter != 3*time.Second {
		t.Fatalf("provider error=%+v", pe)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaked body: %v", err)
	}
}

func TestToolCall_ObjectArgumentsAreAccepted(t *testing.T) {
	var tc ToolCall
	if err := json.Unmarshal([]byte(`{"id":"1","type":"function","function":{"name":"x","arguments":{"a":1}}}`), &tc); err != nil {
		t.Fatal(err)
	}
	if tc.Name != "x" || tc.Arguments != `{"a":1}` {
		t.Fatalf("tool call=%+v", tc)
	}
}
