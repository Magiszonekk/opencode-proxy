package main

// SSE reassembly: Zen's free-tier gate requires "stream": true, but callers
// (CLIProxyAPI's non-streaming Execute path) may have asked for a plain JSON
// completion. When that happens the router streams from upstream and folds the
// deltas back into a single chat.completion object, so the caller sees exactly
// the non-streaming shape it asked for.

import (
	"bufio"
	"encoding/json"
	"io"
	"strings"
)

type sseDelta struct {
	Role             string             `json:"role"`
	Content          string             `json:"content"`
	ReasoningContent string             `json:"reasoning_content"`
	ToolCalls        []sseToolCallDelta `json:"tool_calls"`
}

type sseToolCallDelta struct {
	Index    int    `json:"index"`
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

// toolCallAcc accumulates streamed tool_call fragments keyed by index.
type toolCallAcc struct {
	id, typ, name string
	args          strings.Builder
}

type sseChoice struct {
	Index        int      `json:"index"`
	Delta        sseDelta `json:"delta"`
	FinishReason *string  `json:"finish_reason"`
}

type sseChunk struct {
	ID      string          `json:"id"`
	Object  string          `json:"object"`
	Created int64           `json:"created"`
	Model   string          `json:"model"`
	Choices []sseChoice     `json:"choices"`
	Usage   json.RawMessage `json:"usage"`
}

// collapseResponsesSSE reads a Responses-API SSE stream (events such as
// response.output_text.delta / response.completed) and returns a single
// non-streaming `response` object. Kept separate from the chat/completions
// collapser because the two APIs use different event and body shapes.
func collapseResponsesSSE(body io.Reader) ([]byte, error) {
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)

	var (
		text    strings.Builder
		final   json.RawMessage
		lastErr json.RawMessage
		sawAny  bool
	)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "" || payload == "[DONE]" {
			continue
		}

		var ev map[string]json.RawMessage
		if err := json.Unmarshal([]byte(payload), &ev); err != nil {
			continue
		}
		sawAny = true

		if raw, ok := ev["error"]; ok && len(raw) > 0 && string(raw) != "null" {
			lastErr = json.RawMessage(payload)
			continue
		}

		var evType string
		if raw, ok := ev["type"]; ok {
			_ = json.Unmarshal(raw, &evType)
		}

		switch {
		case strings.HasSuffix(evType, ".output_text.delta"), evType == "response.output_text.delta":
			var delta string
			if raw, ok := ev["delta"]; ok && json.Unmarshal(raw, &delta) == nil {
				text.WriteString(delta)
			}
		case evType == "response.completed", evType == "response.incomplete", evType == "response.failed":
			if raw, ok := ev["response"]; ok {
				final = raw
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if !sawAny {
		return nil, io.ErrUnexpectedEOF
	}
	if lastErr != nil {
		return lastErr, nil
	}

	// Prefer the terminal response object; ensure it carries the accumulated
	// text so callers reading output[].content[].text see the answer.
	if final != nil {
		var obj map[string]any
		if err := json.Unmarshal(final, &obj); err == nil {
			if text.Len() > 0 && !responsesHasText(obj) {
				obj["output"] = []any{
					map[string]any{
						"type":   "message",
						"role":   "assistant",
						"status": "completed",
						"content": []any{
							map[string]any{"type": "output_text", "text": text.String()},
						},
					},
				}
			}
			return json.Marshal(obj)
		}
		return final, nil
	}

	return json.Marshal(map[string]any{
		"object": "response",
		"status": "completed",
		"output": []any{
			map[string]any{
				"type":   "message",
				"role":   "assistant",
				"status": "completed",
				"content": []any{
					map[string]any{"type": "output_text", "text": text.String()},
				},
			},
		},
	})
}

// responsesHasText reports whether a Responses object already carries visible
// output text (as opposed to only reasoning items).
func responsesHasText(obj map[string]any) bool {
	out, ok := obj["output"].([]any)
	if !ok {
		return false
	}
	for _, item := range out {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		content, ok := m["content"].([]any)
		if !ok {
			continue
		}
		for _, c := range content {
			cm, ok := c.(map[string]any)
			if !ok {
				continue
			}
			if t, _ := cm["text"].(string); strings.TrimSpace(t) != "" {
				return true
			}
		}
	}
	return false
}

// collapseSSEToCompletion reads an SSE stream and returns one JSON body shaped
// like a normal /chat/completions response.
func collapseSSEToCompletion(body io.Reader) ([]byte, error) {
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)

	var (
		id, object, model string
		created           int64
		content           strings.Builder
		reasoning         strings.Builder
		finishReason      *string
		usage             json.RawMessage
		sawAny            bool
		toolCalls         = map[int]*toolCallAcc{}
		toolOrder         []int
	)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "" || payload == "[DONE]" {
			continue
		}

		var chunk sseChunk
		if err := json.Unmarshal([]byte(payload), &chunk); err != nil {
			// A mid-stream error object is surfaced verbatim so the caller
			// sees the real upstream failure instead of an empty completion.
			var probe map[string]json.RawMessage
			if json.Unmarshal([]byte(payload), &probe) == nil {
				if _, isErr := probe["error"]; isErr {
					return []byte(payload), nil
				}
			}
			continue
		}

		sawAny = true
		if chunk.ID != "" {
			id = chunk.ID
		}
		if chunk.Model != "" {
			model = chunk.Model
		}
		if chunk.Created != 0 {
			created = chunk.Created
		}
		if len(chunk.Usage) > 0 && string(chunk.Usage) != "null" {
			usage = chunk.Usage
		}
		for _, ch := range chunk.Choices {
			content.WriteString(ch.Delta.Content)
			reasoning.WriteString(ch.Delta.ReasoningContent)
			for _, tc := range ch.Delta.ToolCalls {
				acc, ok := toolCalls[tc.Index]
				if !ok {
					acc = &toolCallAcc{}
					toolCalls[tc.Index] = acc
					toolOrder = append(toolOrder, tc.Index)
				}
				if tc.ID != "" {
					acc.id = tc.ID
				}
				if tc.Type != "" {
					acc.typ = tc.Type
				}
				if tc.Function.Name != "" {
					acc.name = tc.Function.Name
				}
				acc.args.WriteString(tc.Function.Arguments)
			}
			if ch.FinishReason != nil {
				fr := *ch.FinishReason
				finishReason = &fr
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if !sawAny {
		return nil, io.ErrUnexpectedEOF
	}

	object = "chat.completion"
	if finishReason == nil {
		stop := "stop"
		finishReason = &stop
	}

	message := map[string]any{
		"role":    "assistant",
		"content": content.String(),
	}
	if reasoning.Len() > 0 {
		message["reasoning_content"] = reasoning.String()
	}
	if len(toolOrder) > 0 {
		calls := make([]any, 0, len(toolOrder))
		for _, idx := range toolOrder {
			acc := toolCalls[idx]
			typ := acc.typ
			if typ == "" {
				typ = "function"
			}
			calls = append(calls, map[string]any{
				"id":   acc.id,
				"type": typ,
				"function": map[string]any{
					"name":      acc.name,
					"arguments": acc.args.String(),
				},
			})
		}
		message["tool_calls"] = calls
		if content.Len() == 0 {
			message["content"] = nil
		}
		if *finishReason == "stop" {
			tc := "tool_calls"
			finishReason = &tc
		}
	}

	out := map[string]any{
		"id":      id,
		"object":  object,
		"created": created,
		"model":   model,
		"choices": []any{
			map[string]any{
				"index":         0,
				"message":       message,
				"finish_reason": *finishReason,
			},
		},
	}
	if len(usage) > 0 {
		out["usage"] = usage
	}
	return json.Marshal(out)
}
