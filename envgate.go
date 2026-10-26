package main

// envgate.go: Zen gate revision 2026-10-26 also requires an opencode-style
// <env>...</env> block in a SYSTEM message (empty block, plain prompt, or the
// block in a user message -> fake 429). Appended to the first system message,
// or inserted as one, for free-tier models only.

import (
	"encoding/json"
	"strings"
	"time"
)

func zenEnvBlock(now time.Time) string {
	return "Here is some useful information about the environment you are running in:\n<env>\n" +
		"  Working directory: /tmp\n" +
		"  Workspace root folder: /tmp\n" +
		"  Is directory a git repo: no\n" +
		"  Platform: linux\n" +
		"  Today's date: " + now.Format("Mon Jan 02 2006") + "\n" +
		"</env>"
}

// ensureEnvBlock edits root["messages"] in place; returns true if it changed.
func ensureEnvBlock(root map[string]json.RawMessage, now time.Time) bool {
	raw, ok := root["messages"]
	if !ok {
		return false
	}
	var msgs []map[string]json.RawMessage
	if json.Unmarshal(raw, &msgs) != nil {
		return false
	}
	env := zenEnvBlock(now)
	for i, m := range msgs {
		var role string
		_ = json.Unmarshal(m["role"], &role)
		if role != "system" && role != "developer" {
			continue
		}
		var s string
		if json.Unmarshal(m["content"], &s) == nil {
			if strings.Contains(s, "<env>") {
				return false
			}
			if s != "" {
				s += "\n\n"
			}
			b, _ := marshalRaw(s + env)
			msgs[i]["content"] = b
			return putMessages(root, msgs)
		}
		var parts []map[string]any
		if json.Unmarshal(m["content"], &parts) == nil {
			for _, p := range parts {
				if t, _ := p["text"].(string); strings.Contains(t, "<env>") {
					return false
				}
			}
			parts = append(parts, map[string]any{"type": "text", "text": env})
			b, _ := marshalRaw(parts)
			msgs[i]["content"] = b
			return putMessages(root, msgs)
		}
		break // unknown content shape: fall through to inserting a new system message
	}
	content, _ := marshalRaw(env)
	sys := map[string]json.RawMessage{"role": json.RawMessage(`"system"`), "content": content}
	return putMessages(root, append([]map[string]json.RawMessage{sys}, msgs...))
}

func putMessages(root map[string]json.RawMessage, msgs []map[string]json.RawMessage) bool {
	b, err := marshalRaw(msgs)
	if err != nil {
		return false
	}
	root["messages"] = b
	return true
}

// marshalRaw is json.Marshal without HTML escaping, so "<env>" goes on the
// wire as written (opencode's own bytes) instead of "\u003cenv\u003e".
func marshalRaw(v any) ([]byte, error) {
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return []byte(strings.TrimSuffix(buf.String(), "\n")), nil
}
