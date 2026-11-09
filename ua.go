package main

// ua.go: User-Agent sent upstream on the free-tier path, revision 2026-11-09.
//
// Gate history (same IP, body and uTLS transport, fresh session id per probe):
//
//	2026-10-27  zen-direct-v2 reported version gating (opencode/latest/2.0.29/cli -> 429)
//	2026-11-09  bare "opencode/1.18.32"                                   -> 429 FreeUsageLimitError (fake)
//	            "opencode/1.18.32 ai-sdk/provider-utils/4.0.23 runtime/bun/1.3.14" -> 200 (real CLI UA)
//	            "opencode/1.19.5 <same suffix>", "opencode/latest/2.2.6/cli" -> 200
//	            "opencode/1.0.0 <same suffix>" -> 426 UpgradeRequired (min 1.18.0)
//
// Note: a session id that once got a 200 stays trusted, so bisect with NEW ids.
//
// The UA is "opencode/<version> " + uaSuffix (shape of the CLI's fetch UA):
//  1. -zen-ua (whole string) or -zen-ua-version (just the version), if set;
//  2. otherwise uaDefaultVersion, raised in the background to the npm
//     "latest" of opencode-ai (same major only, never downgraded), so the
//     minimum-version check never catches us with a stale constant.

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const (
	uaDefaultVersion = "1.18.32"
	uaSuffix         = "ai-sdk/provider-utils/4.0.23 runtime/bun/1.3.14"
	uaRefreshURL     = "https://registry.npmjs.org/opencode-ai/latest"
	uaRefreshEvery   = 6 * time.Hour
	uaRefreshTimeout = 10 * time.Second
)

var (
	zenUAVersion  atomic.Value // string
	zenUAOverride string       // full UA from -zen-ua
)

func init() { zenUAVersion.Store(uaDefaultVersion) }

// zenUserAgent renders the upstream UA in the shape of the official CLI.
func zenUserAgent() string {
	if zenUAOverride != "" {
		return zenUAOverride
	}
	v, _ := zenUAVersion.Load().(string)
	if v == "" {
		v = uaDefaultVersion
	}
	return "opencode/" + v + " " + uaSuffix
}

// configureUA applies the flags and, unless pinned, starts the npm refresher.
func configureUA(fullUA, pinnedVersion string, refresh bool) {
	if fullUA = strings.TrimSpace(fullUA); fullUA != "" {
		zenUAOverride = fullUA
		log.Printf("ua: pinned to %q", fullUA)
		return
	}
	if pinnedVersion = strings.TrimSpace(pinnedVersion); pinnedVersion != "" {
		zenUAVersion.Store(strings.TrimPrefix(pinnedVersion, "v"))
		log.Printf("ua: version pinned to %s", pinnedVersion)
		return
	}
	if !refresh {
		return
	}
	go func() {
		for {
			refreshUAVersion()
			time.Sleep(uaRefreshEvery)
		}
	}()
}

func refreshUAVersion() {
	client := &http.Client{Timeout: uaRefreshTimeout}
	resp, err := client.Get(uaRefreshURL)
	if err != nil {
		log.Printf("ua: npm refresh failed: %v (keeping %s)", err, zenUAVersion.Load())
		return
	}
	defer resp.Body.Close()
	var body struct {
		Version string `json:"version"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&body) != nil {
		log.Printf("ua: npm refresh: bad response %d (keeping %s)", resp.StatusCode, zenUAVersion.Load())
		return
	}
	cur, _ := zenUAVersion.Load().(string)
	if newerSameMajor(cur, body.Version) {
		zenUAVersion.Store(body.Version)
		log.Printf("ua: client version %s -> %s (npm latest)", cur, body.Version)
	}
}

func parseSemver(s string) ([3]int, bool) {
	var out [3]int
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

// newerSameMajor: candidate is a strictly newer release within cur's major.
// Pre-releases are ignored (the gate presumably tracks shipped versions).
func newerSameMajor(cur, cand string) bool {
	if strings.ContainsAny(strings.TrimPrefix(cand, "v"), "-+") {
		return false
	}
	a, ok1 := parseSemver(cur)
	b, ok2 := parseSemver(cand)
	if !ok1 || !ok2 || a[0] != b[0] {
		return false
	}
	for i := 1; i < 3; i++ {
		if b[i] != a[i] {
			return b[i] > a[i]
		}
	}
	return false
}
