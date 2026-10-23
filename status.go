package main

// status.go: per-egress bookkeeping exposed at GET /__router/status (the router
// only listens on loopback). Shown on models.cikowice.pl so the owner can see how
// many egress IPs exist, which one serves traffic now and which hit Zen's daily
// free-tier quota (429 + Retry-After of several hours). Optionally persisted to
// -state-file so a restart does not forget a quota that lasts until tomorrow.

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

type egressStat struct {
	Name          string               `json:"name"`
	Family        string               `json:"family"` // ipv4 | ipv6 | tor
	LastOK        time.Time            `json:"last_ok,omitempty"`
	LastOKModel   string               `json:"last_ok_model,omitempty"`
	Last429       time.Time            `json:"last_429,omitempty"`
	Last429Model  string               `json:"last_429_model,omitempty"`
	QuotaUntil    map[string]time.Time `json:"quota_until,omitempty"` // model -> now + Retry-After
	CooldownUntil time.Time            `json:"cooldown_until,omitempty"`
	Day           string               `json:"day"`
	OKToday       int                  `json:"ok_today"`
	R429Today     int                  `json:"r429_today"`
}

type statusBook struct {
	mu       sync.Mutex
	stats    map[string]*egressStat
	order    []string
	lastUsed string
	lastAt   time.Time
	file     string
}

func familyOf(b *backend) string {
	switch {
	case b.name == "via-tor":
		return "tor"
	case b.ipv4 || b.name == "via-oracle2":
		return "ipv4"
	default:
		return "ipv6"
	}
}

func newStatusBook(bs []*backend, file string) *statusBook {
	sb := &statusBook{stats: map[string]*egressStat{}, file: file}
	for _, b := range bs {
		sb.order = append(sb.order, b.name)
		sb.stats[b.name] = &egressStat{Name: b.name, Family: familyOf(b), QuotaUntil: map[string]time.Time{}}
	}
	if file != "" {
		if raw, err := os.ReadFile(file); err == nil {
			var saved struct {
				Backends []egressStat `json:"backends"`
				LastUsed string       `json:"last_used"`
				LastAt   time.Time    `json:"last_used_at"`
			}
			if json.Unmarshal(raw, &saved) == nil {
				for _, s := range saved.Backends {
					if cur, ok := sb.stats[s.Name]; ok {
						fam := cur.Family
						*cur = s
						cur.Family = fam
						if cur.QuotaUntil == nil {
							cur.QuotaUntil = map[string]time.Time{}
						}
					}
				}
				sb.lastUsed, sb.lastAt = saved.LastUsed, saved.LastAt
			}
		}
	}
	return sb
}

func retryAfterSeconds(h http.Header) int {
	n, err := strconv.Atoi(h.Get("Retry-After"))
	if err != nil || n < 0 {
		return 0
	}
	return n
}

func (sb *statusBook) record(name string, code int, model string, retryAfter int, cooldownUntil time.Time) {
	if sb == nil {
		return
	}
	sb.mu.Lock()
	defer sb.mu.Unlock()
	s, ok := sb.stats[name]
	if !ok {
		return
	}
	now := time.Now()
	if day := now.Format("2006-01-02"); s.Day != day {
		s.Day, s.OKToday, s.R429Today = day, 0, 0
	}
	switch {
	case code >= 200 && code < 300:
		s.LastOK, s.LastOKModel = now, model
		s.OKToday++
		delete(s.QuotaUntil, model) // it answered, so this model's quota is back
		sb.lastUsed, sb.lastAt = name, now
	case code == http.StatusTooManyRequests:
		s.Last429, s.Last429Model = now, model
		s.R429Today++
		if retryAfter > 0 {
			s.QuotaUntil[model] = now.Add(time.Duration(retryAfter) * time.Second)
		}
		if !cooldownUntil.IsZero() {
			s.CooldownUntil = cooldownUntil
		}
	default:
		return
	}
	for m, t := range s.QuotaUntil {
		if now.After(t) {
			delete(s.QuotaUntil, m)
		}
	}
	sb.saveLocked()
}

func (sb *statusBook) snapshotLocked() map[string]any {
	list := make([]egressStat, 0, len(sb.order))
	for _, n := range sb.order {
		list = append(list, *sb.stats[n])
	}
	return map[string]any{"backends": list, "last_used": sb.lastUsed, "last_used_at": sb.lastAt}
}

func (sb *statusBook) saveLocked() {
	if sb.file == "" {
		return
	}
	raw, err := json.Marshal(sb.snapshotLocked())
	if err != nil {
		return
	}
	tmp := sb.file + ".tmp"
	if err := os.MkdirAll(filepath.Dir(sb.file), 0o700); err != nil {
		return
	}
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		log.Printf("status: write %s: %v", tmp, err)
		return
	}
	_ = os.Rename(tmp, sb.file)
}

// serveStatus answers GET /__router/status. "next" is the egress the next
// request would try first (first backend not in its short 429 cooldown).
func (rt *router) serveStatus(w http.ResponseWriter) {
	now := time.Now()
	next := ""
	for _, b := range rt.orderedBackends(now) {
		next = b.name
		break
	}
	sb := rt.status
	sb.mu.Lock()
	snap := sb.snapshotLocked()
	sb.mu.Unlock()
	snap["now"] = now
	snap["next"] = next
	snap["order"] = sb.order
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(snap)
}
