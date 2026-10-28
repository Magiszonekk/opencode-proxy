package main

// systemone.go: passthrough for OpenCode Zen's decision ("System One") models,
// e.g. jev-1.13-free. They are not chat models: the request is
// {model, state, questions} and the answer is typed probabilities.
//
// Zen serves them on https://opencode.ai/inference/systemone/v1/systemone,
// NOT under /zen/v1 (there the same body gets 422 "Endpoint is unavailable").
// The free id needs no key and no gate rewrite (measured 2026-10-28: plain
// curl gets 200), so the body is forwarded untouched. What the router adds is
// the egress failover: a 429 parks that egress for the systemone pool only and
// the request moves on to the next IP.
//
// Pools: chat and systemone are separate Zen services and may well have
// separate per-IP quotas, so a 429 in one pool must not bench an egress for the
// other. backend.limitedUntil is the chat pool; backend.soLimitedUntil the
// systemone pool.

import (
	"log"
	"net/url"
	"strings"
	"time"
)

const (
	poolChat      = "chat"
	poolSystemOne = "systemone"
)

// systemOnePath is the upstream path on the upstream host (-systemone-path).
var systemOnePath = "/inference/systemone/v1/systemone"

// systemOneUA replaces the caller's User-Agent upstream. Zen's Cloudflare
// answers "403 error code: 1010" to some client UAs (Python-urllib, none at
// all) while curl/node/opencode/browser UAs pass (measured 2026-10-28), so a
// caller's library must not decide whether the request gets through.
const systemOneUA = "opencode-egress-router (systemone)"

// isSystemOneRequest matches /systemone and /v1/systemone (any prefix).
func isSystemOneRequest(path string) bool {
	return strings.HasSuffix(strings.TrimRight(path, "/"), "/systemone")
}

// systemOneTarget is the upstream URL for a systemone request: same scheme and
// host as -upstream, fixed path.
func systemOneTarget(upstream *url.URL, rawQuery string) url.URL {
	t := url.URL{Scheme: upstream.Scheme, Host: upstream.Host, Path: systemOnePath, RawQuery: rawQuery}
	return t
}

func (b *backend) availableIn(pool string, now time.Time) bool {
	if pool != poolSystemOne {
		return b.available(now)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return now.After(b.soLimitedUntil)
}

func (b *backend) markLimitedIn(pool string, cooldown time.Duration) {
	if pool != poolSystemOne {
		b.markLimited(cooldown)
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.soLimitedUntil = time.Now().Add(cooldown)
	log.Printf("[%s] systemone marked rate-limited, cooling down until %s", b.name, b.soLimitedUntil.Format(time.RFC3339))
}
