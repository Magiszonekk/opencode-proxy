package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// capturing records each request it sees and answers with canned codes.
type capturing struct {
	mu    sync.Mutex
	codes []int
	reqs  []*http.Request
	body  [][]byte
}

func (c *capturing) RoundTrip(r *http.Request) (*http.Response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	b, _ := io.ReadAll(r.Body)
	c.reqs = append(c.reqs, r)
	c.body = append(c.body, b)
	code := c.codes[min(len(c.reqs)-1, len(c.codes)-1)]
	return &http.Response{StatusCode: code, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"answers":{}}`))}, nil
}

func capBackend(name string, codes ...int) (*backend, *capturing) {
	c := &capturing{codes: codes}
	return &backend{name: name, client: &http.Client{Transport: c}}, c
}

func zenRouter(bs ...*backend) *router {
	u, _ := url.Parse("https://opencode.ai/zen/v1")
	return &router{upstream: u, backends: bs, status: newStatusBook(bs, ""), soStatus: newStatusBook(bs, "")}
}

const soBody = `{"model":"jev-1.13-free","state":"<env>x</env> hi","questions":{"q":{"type":"noul","instructions":"ok?"}}}`

func postSO(rt *router, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", path, strings.NewReader(soBody))
	req.Header.Set("Content-Type", "application/json")
	rt.ServeHTTP(rec, req)
	return rec
}

// /v1/systemone goes to /inference/systemone/v1/systemone on the upstream host,
// body untouched (no zenfix: no tools, no forced stream, no <env> injection).
func TestSystemOneRoutesOutsideZenPathBodyUntouched(t *testing.T) {
	d, c := capBackend("direct", 200)
	rt := zenRouter(d)
	if got := postSO(rt, "/v1/systemone").Code; got != 200 {
		t.Fatalf("want 200, got %d", got)
	}
	if len(c.reqs) != 1 {
		t.Fatalf("want 1 upstream call, got %d", len(c.reqs))
	}
	u := c.reqs[0].URL
	if u.Host != "opencode.ai" || u.Path != "/inference/systemone/v1/systemone" {
		t.Fatalf("wrong upstream url %s", u)
	}
	if !bytes.Equal(c.body[0], []byte(soBody)) {
		t.Fatalf("body was modified:\n%s", c.body[0])
	}
	if ua := c.reqs[0].Header.Get("User-Agent"); ua != systemOneUA {
		t.Fatalf("systemone must send the fixed UA (Cloudflare 1010 on some client UAs), got %q", ua)
	}
	// both spellings route the same way
	if got := postSO(rt, "/systemone").Code; got != 200 || c.reqs[1].URL.Path != "/inference/systemone/v1/systemone" {
		t.Fatalf("/systemone: code %d path %s", got, c.reqs[1].URL.Path)
	}
}

// A systemone 429 fails over to the next egress and benches the first one for
// the systemone pool only; chat traffic still uses it.
func TestSystemOne429HasOwnPool(t *testing.T) {
	cooldown = time.Minute
	d, dc := capBackend("direct", 429, 200)
	o, oc := capBackend("via-ovh", 200)
	rt := zenRouter(d, o)
	if got := postSO(rt, "/v1/systemone").Code; got != 200 {
		t.Fatalf("want failover 200, got %d", got)
	}
	if len(dc.reqs) != 1 || len(oc.reqs) != 1 {
		t.Fatalf("calls direct=%d ovh=%d", len(dc.reqs), len(oc.reqs))
	}
	if d.availableIn(poolSystemOne, time.Now()) {
		t.Fatal("direct should be benched for systemone")
	}
	if !d.availableIn(poolChat, time.Now()) {
		t.Fatal("a systemone 429 must not bench direct for chat")
	}
	// next systemone request skips direct
	postSO(rt, "/v1/systemone")
	if len(dc.reqs) != 1 || len(oc.reqs) != 2 {
		t.Fatalf("second request: calls direct=%d ovh=%d", len(dc.reqs), len(oc.reqs))
	}
	// chat (non-free model) still starts on direct
	rec := httptest.NewRecorder()
	rt.ServeHTTP(rec, httptest.NewRequest("GET", "/models", nil))
	if len(dc.reqs) != 2 {
		t.Fatalf("chat should still use direct, calls=%d", len(dc.reqs))
	}
	if rec.Code != 200 {
		t.Fatalf("chat code %d", rec.Code)
	}
}

// A chat 429 does not bench the egress for systemone.
func TestChat429DoesNotBenchSystemOne(t *testing.T) {
	cooldown = time.Minute
	d, dc := capBackend("direct", 429, 200)
	o, _ := capBackend("via-ovh", 200)
	rt := zenRouter(d, o)
	rec := httptest.NewRecorder()
	rt.ServeHTTP(rec, httptest.NewRequest("GET", "/models", nil))
	if d.available(time.Now()) {
		t.Fatal("chat 429 should bench direct for chat")
	}
	if got := postSO(rt, "/v1/systemone").Code; got != 200 || len(dc.reqs) != 2 {
		t.Fatalf("systemone should still try direct first: code=%d direct calls=%d", got, len(dc.reqs))
	}
}

// Upstream 4xx (bad question) is forwarded, not retried on another egress.
func TestSystemOne4xxForwardedNotRetried(t *testing.T) {
	d, _ := capBackend("direct", 400)
	o, oc := capBackend("via-ovh", 200)
	if got := postSO(zenRouter(d, o), "/v1/systemone").Code; got != 400 || len(oc.reqs) != 0 {
		t.Fatalf("want 400 without failover, got %d (ovh calls %d)", got, len(oc.reqs))
	}
}

// /__router/status carries a separate "systemone" block.
func TestStatusHasSystemOneBlock(t *testing.T) {
	d, _ := capBackend("direct", 200)
	rt := zenRouter(d)
	postSO(rt, "/v1/systemone")
	rec := httptest.NewRecorder()
	rt.ServeHTTP(rec, httptest.NewRequest("GET", "/__router/status", nil))
	var snap struct {
		Backends  []egressStat `json:"backends"`
		SystemOne struct {
			Backends []egressStat `json:"backends"`
			LastUsed string       `json:"last_used"`
			Next     string       `json:"next"`
		} `json:"systemone"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &snap); err != nil {
		t.Fatal(err)
	}
	if snap.SystemOne.LastUsed != "direct" || snap.SystemOne.Backends[0].OKToday != 1 || snap.SystemOne.Next != "direct" {
		t.Fatalf("systemone status wrong: %+v", snap.SystemOne)
	}
	if snap.Backends[0].OKToday != 0 {
		t.Fatalf("systemone traffic must not count in the chat book: %+v", snap.Backends[0])
	}
}
