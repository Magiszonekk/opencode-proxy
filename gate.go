package main

// gate.go: OpenCode Zen free-tier gate, revision 2026-10-14.
//
// Zen changed the gate around 2026-10-08. Measured by replaying a captured
// request from the real opencode 1.18.32 CLI and bisecting one field at a time:
//
//   - x-opencode-session must be an OpenCode *descending* identifier:
//     "ses_" + 12 hex of (^(unix_ms*0x1000+counter) & 0xFFFFFFFFFFFF) + 14 base62.
//     A random-hex id (the old newZenSessionID) and an ascending id both 403.
//   - The request must carry tools named "bash" AND "read" (either one alone
//     403s; descriptions/schemas are not checked, stubs pass). Applies to both
//     /chat/completions and /responses.
//   - "stream": true is still required.
//   - The compaction system prompt is NO LONGER required: a plain system
//     prompt (or none) passes. So the old prompt-prefix + user-frame hacks
//     (zenfix.go / musespark.go) are switched off via zenLegacyPromptGate,
//     which also gives normal, non-summary answers again.
//   - Auth header, x-opencode-client/project/request are not checked.
//   - Muse Spark on /responses rejects tool_choice other than "auto".

import (
	"crypto/rand"
	"encoding/json"
	"math/big"
	"sync"
	"time"
)

// zenLegacyPromptGate re-enables the pre-2026-10 compaction-prompt rewrites.
const zenLegacyPromptGate = false

const zenStubToolDescription = "Unavailable in this environment. Never call this tool."

var zenGateToolNames = []string{"bash", "read"}

var (
	zenIDMu      sync.Mutex
	zenIDLastMs  int64
	zenIDCounter int64
)

// newZenDescendingSessionID mirrors OpenCode's Identifier.descending("session").
func newZenDescendingSessionID() (string, error) {
	zenIDMu.Lock()
	now := time.Now().UnixMilli()
	if now != zenIDLastMs {
		zenIDLastMs = now
		zenIDCounter = 0
	}
	zenIDCounter++
	n := uint64(now)*0x1000 + uint64(zenIDCounter)
	zenIDMu.Unlock()
	n = ^n & 0xFFFFFFFFFFFF

	const hexdigits = "0123456789abcdef"
	buf := make([]byte, 0, 4+12+14)
	buf = append(buf, "ses_"...)
	for shift := 44; shift >= 0; shift -= 4 {
		buf = append(buf, hexdigits[(n>>uint(shift))&0xF])
	}
	for i := 0; i < 14; i++ {
		r, err := rand.Int(rand.Reader, big.NewInt(int64(len(base62))))
		if err != nil {
			return "", err
		}
		buf = append(buf, base62[r.Int64()])
	}
	return string(buf), nil
}

// ensureGateTools appends stub "bash"/"read" tools when the caller didn't send
// tools with those names. responsesShape selects the flat Responses-API tool
// format instead of the chat/completions {"type":"function","function":{...}}.
func ensureGateTools(root map[string]json.RawMessage, responsesShape bool) {
	var tools []map[string]any
	if raw, ok := root["tools"]; ok {
		if err := json.Unmarshal(raw, &tools); err != nil {
			return // unknown shape: leave untouched
		}
	}
	have := map[string]bool{}
	for _, t := range tools {
		if n, ok := t["name"].(string); ok {
			have[n] = true
		}
		if fn, ok := t["function"].(map[string]any); ok {
			if n, ok := fn["name"].(string); ok {
				have[n] = true
			}
		}
	}
	params := map[string]any{"type": "object", "properties": map[string]any{}}
	added := false
	for _, name := range zenGateToolNames {
		if have[name] {
			continue
		}
		if responsesShape {
			tools = append(tools, map[string]any{"type": "function", "name": name, "description": zenStubToolDescription, "parameters": params})
		} else {
			tools = append(tools, map[string]any{"type": "function", "function": map[string]any{"name": name, "description": zenStubToolDescription, "parameters": params}})
		}
		added = true
	}
	if !added {
		return
	}
	if b, err := json.Marshal(tools); err == nil {
		root["tools"] = b
	}
}
