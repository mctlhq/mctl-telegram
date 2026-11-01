package agentworker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type ChatMessage struct {
	Role       string     `json:"role"`
	Content    string     `json:"content,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
}

type ToolCall struct {
	ID        string
	Name      string
	Arguments string
}

func (t ToolCall) MarshalJSON() ([]byte, error) {
	type fn struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	}
	return json.Marshal(struct {
		ID       string `json:"id"`
		Type     string `json:"type"`
		Function fn     `json:"function"`
	}{ID: t.ID, Type: "function", Function: fn{Name: t.Name, Arguments: t.Arguments}})
}

func (t *ToolCall) UnmarshalJSON(data []byte) error {
	var raw struct {
		ID       string `json:"id"`
		Function struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		} `json:"function"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	t.ID, t.Name = raw.ID, raw.Function.Name
	if len(raw.Function.Arguments) == 0 || string(raw.Function.Arguments) == "null" {
		t.Arguments = "{}"
		return nil
	}
	var s string
	if err := json.Unmarshal(raw.Function.Arguments, &s); err == nil {
		t.Arguments = s
		return nil
	}
	// Some OpenAI-compatible providers return an object here even though the
	// OpenAI wire contract says this is a JSON string. Preserve the object as
	// compact JSON rather than rejecting an otherwise usable tool call.
	var v any
	if err := json.Unmarshal(raw.Function.Arguments, &v); err != nil {
		return err
	}
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	t.Arguments = string(b)
	return nil
}

type ChatUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
}

type ChatResult struct {
	Message      ChatMessage
	Usage        ChatUsage
	FinishReason string
}

// ProviderError carries only transport-safe metadata. It deliberately never
// retains or returns the provider body because an error body may echo model
// input, tool arguments, or other message content.
type ProviderError struct {
	Status     int
	RetryAfter time.Duration
}

func (e *ProviderError) Error() string {
	return fmt.Sprintf("openai provider returned HTTP %d", e.Status)
}

type OpenAIClient struct {
	BaseURL      string
	APIKey       string
	GatewayToken string
	Model        string
	UserAgent    string
	HTTP         *http.Client
}

type openAITool struct {
	Type     string         `json:"type"`
	Function openAIFunction `json:"function"`
}

type openAIFunction struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Parameters any    `json:"parameters"`
}

// Chat performs one non-streaming OpenAI-compatible chat-completions request.
// Error bodies are drained for connection reuse but are never retained,
// decoded, logged, or included in returned errors.
func (c *OpenAIClient) Chat(ctx context.Context, msgs []ChatMessage, tools []toolDef) (*ChatResult, error) {
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	wireTools := make([]openAITool, 0, len(tools))
	for _, d := range tools {
		wireTools = append(wireTools, openAITool{Type: "function", Function: openAIFunction{
			Name: d.Tool.Name, Description: d.Tool.Description, Parameters: d.Tool.InputSchema,
		}})
	}
	body, err := json.Marshal(struct {
		Model      string        `json:"model"`
		Messages   []ChatMessage `json:"messages"`
		Tools      []openAITool  `json:"tools,omitempty"`
		ToolChoice string        `json:"tool_choice,omitempty"`
		Stream     bool          `json:"stream"`
	}{Model: c.Model, Messages: msgs, Tools: wireTools, ToolChoice: "auto", Stream: false})
	if err != nil {
		return nil, fmt.Errorf("encode chat request: %w", err)
	}
	url := strings.TrimRight(c.BaseURL, "/") + "/chat/completions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build chat request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("cf-aig-collect-log", "false")
	req.Header.Set("cf-aig-skip-cache", "true")
	if c.GatewayToken != "" {
		req.Header.Set("cf-aig-authorization", "Bearer "+c.GatewayToken)
	}
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("chat request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		return nil, &ProviderError{Status: resp.StatusCode, RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After"), time.Now())}
	}
	var out struct {
		Choices []struct {
			Message      ChatMessage `json:"message"`
			FinishReason string      `json:"finish_reason"`
		} `json:"choices"`
		Usage ChatUsage `json:"usage"`
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, 8<<20))
	if err := dec.Decode(&out); err != nil {
		return nil, fmt.Errorf("decode chat response: %w", err)
	}
	if len(out.Choices) == 0 {
		return nil, fmt.Errorf("decode chat response: no choices")
	}
	return &ChatResult{Message: out.Choices[0].Message, Usage: out.Usage, FinishReason: out.Choices[0].FinishReason}, nil
}

func parseRetryAfter(raw string, now time.Time) time.Duration {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0
	}
	if sec, err := strconv.Atoi(raw); err == nil && sec >= 0 {
		return time.Duration(sec) * time.Second
	}
	if t, err := http.ParseTime(raw); err == nil && t.After(now) {
		return t.Sub(now)
	}
	return 0
}
