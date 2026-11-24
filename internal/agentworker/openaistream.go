package agentworker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

const (
	// maxStreamBytes bounds one streamed response, as the non-streaming
	// body is bounded.
	maxStreamBytes = 8 << 20
	// maxStreamLine bounds one SSE line.
	maxStreamLine = 1 << 20
)

// streamToolCall assembles one tool call from its deltas.
type streamToolCall struct {
	id, name string
	args     strings.Builder
	object   string // arguments given whole, as an object
}

// chatStream is chat with stream: true. onText, when non-nil, gets the
// accumulated answer text after every content delta; tool-call deltas and
// reasoning_content never reach it. A non-2xx answer is a *ProviderError as
// in chat. A stream that breaks, is malformed, is over the bound or ends
// without [DONE] is a plain error. UsageReported keeps chat's rule: a
// stream without a usage chunk is unknown spend.
func (c *OpenAIClient) chatStream(ctx context.Context, msgs []ChatMessage, wireTools []openAITool, onText func(string)) (*ChatResult, error) {
	resp, err := c.post(ctx, msgs, wireTools, true)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(io.LimitReader(resp.Body, maxStreamBytes))
	sc.Buffer(make([]byte, 0, 64<<10), maxStreamLine)
	var (
		content strings.Builder
		calls   = map[int]*streamToolCall{}
		finish  string
		usage   *ChatUsage
		done    bool
	)
	for sc.Scan() && !done {
		line := bytes.TrimSpace(sc.Bytes())
		data, ok := bytes.CutPrefix(line, []byte("data:"))
		if !ok {
			continue
		}
		data = bytes.TrimSpace(data)
		if string(data) == "[DONE]" {
			done = true
			break
		}
		var chunk struct {
			Choices []struct {
				Delta struct {
					Content   string `json:"content"`
					ToolCalls []struct {
						Index    int    `json:"index"`
						ID       string `json:"id"`
						Function struct {
							Name      string          `json:"name"`
							Arguments json.RawMessage `json:"arguments"`
						} `json:"function"`
					} `json:"tool_calls"`
				} `json:"delta"`
				FinishReason *string `json:"finish_reason"`
			} `json:"choices"`
			Usage *ChatUsage      `json:"usage"`
			Error json.RawMessage `json:"error"`
		}
		if err := json.Unmarshal(data, &chunk); err != nil {
			return nil, errors.New("decode chat stream: malformed chunk")
		}
		if len(chunk.Error) > 0 && string(chunk.Error) != "null" {
			// A provider fault reported inside a 200 stream. Its text is
			// not kept: it may echo the request.
			return nil, errors.New("read chat stream: provider reported an error")
		}
		if chunk.Usage != nil {
			usage = chunk.Usage
		}
		for _, ch := range chunk.Choices {
			if ch.FinishReason != nil && *ch.FinishReason != "" {
				finish = *ch.FinishReason
			}
			if ch.Delta.Content != "" {
				content.WriteString(ch.Delta.Content)
				if onText != nil {
					onText(content.String())
				}
			}
			for _, tc := range ch.Delta.ToolCalls {
				a := calls[tc.Index]
				if a == nil {
					a = &streamToolCall{}
					calls[tc.Index] = a
				}
				if tc.ID != "" {
					a.id = tc.ID
				}
				if tc.Function.Name != "" {
					a.name = tc.Function.Name
				}
				raw := bytes.TrimSpace(tc.Function.Arguments)
				switch {
				case len(raw) == 0 || string(raw) == "null":
				case raw[0] == '"':
					var frag string
					if err := json.Unmarshal(raw, &frag); err != nil {
						return nil, errors.New("decode chat stream: malformed arguments")
					}
					a.args.WriteString(frag)
				default:
					var v any
					if err := json.Unmarshal(raw, &v); err != nil {
						return nil, errors.New("decode chat stream: malformed arguments")
					}
					b, err := json.Marshal(v)
					if err != nil {
						return nil, errors.New("decode chat stream: malformed arguments")
					}
					a.object = string(b)
				}
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read chat stream: %w", err)
	}
	if !done {
		return nil, errors.New("read chat stream: ended before [DONE]")
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	res := &ChatResult{Message: ChatMessage{Role: "assistant", Content: content.String()}, FinishReason: finish}
	idx := make([]int, 0, len(calls))
	for i := range calls {
		idx = append(idx, i)
	}
	sort.Ints(idx)
	for _, i := range idx {
		a := calls[i]
		args := a.args.String()
		if a.object != "" {
			args = a.object
		}
		if strings.TrimSpace(args) == "" {
			args = "{}"
		}
		res.Message.ToolCalls = append(res.Message.ToolCalls, ToolCall{ID: a.id, Name: a.name, Arguments: args})
	}
	if usage != nil {
		res.Usage = *usage
		res.UsageReported = usage.PromptTokens > 0 || usage.CompletionTokens > 0
	}
	return res, nil
}
