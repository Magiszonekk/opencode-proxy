package main

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// scripted returns canned status codes in order and records how often it was used.
type scripted struct {
	mu     sync.Mutex
	codes  []int
	called int
}

func (s *scripted) RoundTrip(*http.Request) (*http.Response, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	code := s.codes[min(s.called, len(s.codes)-1)]
	s.called++
	return &http.Response{StatusCode: code, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("x"))}, nil
}

func mk(name string, attempts int, codes ...int) (*backend, *scripted) {
	s := &scripted{codes: codes}
	return &backend{name: name, client: &http.Client{Transport: s}, attempts: attempts}, s
}

func serve(rt *router) int {
	rec := httptest.NewRecorder()
	rt.ServeHTTP(rec, httptest.NewRequest("GET", "/models", nil))
	return rec.Code
}

func newRouter(bs ...*backend) *router {
	u, _ := url.Parse("https://upstream.invalid/v1")
	return &router{upstream: u, backends: bs}
}

// Every normal IP is rate limited, so the request must end on Tor.
func TestTorIsLastResortWhenAllIPsAre429(t *testing.T) {
	cooldown = time.Minute
	d, sd := mk("direct", 0, 429)
	o, so := mk("via-ovh", 0, 429)
	r, sr := mk("via-oracle", 0, 429)
	tor, st := mk("via-tor", 3, 200)
	if got := serve(newRouter(d, o, r, tor)); got != 200 {
		t.Fatalf("want 200 via tor, got %d", got)
	}
	if sd.called != 1 || so.called != 1 || sr.called != 1 || st.called != 1 {
		t.Fatalf("calls direct=%d ovh=%d oracle=%d tor=%d", sd.called, so.called, sr.called, st.called)
	}
	// The rate-limited IPs are benched, so the next request goes straight to Tor.
	if got := serve(newRouter(d, o, r, tor)); got != 200 {
		t.Fatalf("second request: want 200, got %d", got)
	}
}

// Tor is never touched while a normal IP still works.
func TestTorUnusedWhileDirectWorks(t *testing.T) {
	cooldown = time.Minute
	d, _ := mk("direct", 0, 200)
	tor, st := mk("via-tor", 3, 200)
	if got := serve(newRouter(d, tor)); got != 200 || st.called != 0 {
		t.Fatalf("got %d, tor calls %d", got, st.called)
	}
}

// A blocked exit (403) or a 429 on Tor is retried on new circuits, up to attempts.
func TestTorRetriesNewCircuits(t *testing.T) {
	tor, st := mk("via-tor", 3, 403, 429, 200)
	if got := serve(newRouter(tor)); got != 200 || st.called != 3 {
		t.Fatalf("got %d after %d tor calls", got, st.called)
	}
	tor2, st2 := mk("via-tor", 3, 403, 403, 403, 403)
	if got := serve(newRouter(tor2)); got != 403 || st2.called != 3 {
		t.Fatalf("exhausted: got %d after %d calls, want 403 after 3", got, st2.called)
	}
}

// A 403 on a normal backend is a real answer (e.g. auth), not a reason to fail over.
func TestDirect403IsReturnedNotRetried(t *testing.T) {
	d, _ := mk("direct", 0, 403)
	tor, st := mk("via-tor", 3, 200)
	if got := serve(newRouter(d, tor)); got != 403 || st.called != 0 {
		t.Fatalf("got %d, tor calls %d", got, st.called)
	}
}

// bodyRT answers with a fixed status, headers and body.
type bodyRT struct {
	code int
	hdr  http.Header
	body string
}

func (b bodyRT) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: b.code, Header: b.hdr.Clone(), Body: io.NopCloser(strings.NewReader(b.body))}, nil
}

// 429 reasons are logged with model, rate-limit headers and body; the final
// error body is still forwarded to the caller intact.
func TestErrorReasonsAreLoggedAndForwarded(t *testing.T) {
	cooldown = time.Minute
	var logBuf bytes.Buffer
	log.SetOutput(&logBuf)
	defer log.SetOutput(os.Stderr)

	d := &backend{name: "direct", client: &http.Client{Transport: bodyRT{429, http.Header{"Retry-After": {"30"}}, `{"error":{"message":"Endpoint is unavailable."}}`}}}
	o := &backend{name: "via-ovh", client: &http.Client{Transport: bodyRT{400, http.Header{"Content-Type": {"application/json"}}, `{"error":"bad model"}`}}}
	rec := httptest.NewRecorder()
	newRouter(d, o).ServeHTTP(rec, httptest.NewRequest("POST", "/models", strings.NewReader(`{"model":"paid-x"}`)))

	if rec.Code != 400 || rec.Body.String() != `{"error":"bad model"}` {
		t.Fatalf("forwarded %d %q", rec.Code, rec.Body.String())
	}
	out := logBuf.String()
	for _, want := range []string{"[direct] 429 model=paid-x retry-after=30", "Endpoint is unavailable.", "[via-ovh] POST /models -> 400 model=paid-x", "bad model"} {
		if !strings.Contains(out, want) {
			t.Fatalf("log missing %q:\n%s", want, out)
		}
	}
}

// The second Oracle IP is one more stop before Tor, used only when the first three 429.
func TestOracle2BeforeTor(t *testing.T) {
	cooldown = time.Minute
	d, _ := mk("direct", 0, 429)
	o, _ := mk("via-ovh", 0, 429)
	r, _ := mk("via-oracle", 0, 429)
	r2, sr2 := mk("via-oracle2", 0, 200)
	tor, st := mk("via-tor", 3, 200)
	if got := serve(newRouter(d, o, r, r2, tor)); got != 200 {
		t.Fatalf("want 200 via oracle2, got %d", got)
	}
	if sr2.called != 1 || st.called != 0 {
		t.Fatalf("calls oracle2=%d tor=%d", sr2.called, st.called)
	}
}

// A socks5:// URL is accepted for proxied backends; the proxy hop lives in the
// uTLS dialer (Transport.Proxy must stay nil or Go would do plain TLS itself).
func TestProxiedBackendAcceptsSocks5(t *testing.T) {
	b := newProxiedBackend("via-oracle2", "socks5://127.0.0.1:1")
	tr := b.client.Transport.(*http.Transport)
	if tr.Proxy != nil || tr.DialTLSContext == nil {
		t.Fatalf("want uTLS dialer and no Transport.Proxy")
	}
}

// IPv4 twins: the request URL host becomes the A record, Host/SNI stay the name.
type hostRecorder struct {
	urlHost, host string
}

func (h *hostRecorder) RoundTrip(r *http.Request) (*http.Response, error) {
	h.urlHost, h.host = r.URL.Host, r.Host
	return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("x"))}, nil
}

func TestIPv4TwinUsesARecordAndKeepsHost(t *testing.T) {
	cooldown = time.Minute
	old := lookupIPv4
	lookupIPv4 = func(string) (string, error) { return "203.0.113.7", nil }
	defer func() { lookupIPv4 = old; v4Addr = "" }()
	v4Addr = ""
	d, _ := mk("direct", 0, 429)
	rec := &hostRecorder{}
	v4 := &backend{name: "direct-v4", client: &http.Client{Transport: rec}, ipv4: true}
	if got := serve(newRouter(d, v4)); got != 200 {
		t.Fatalf("want 200 via direct-v4, got %d", got)
	}
	if rec.urlHost != "203.0.113.7:443" || rec.host != "upstream.invalid" {
		t.Fatalf("url host=%q host=%q", rec.urlHost, rec.host)
	}
}

func TestIPv4TwinBackendConfig(t *testing.T) {
	b := newIPv4Backend("via-ovh-v4", "http://127.0.0.1:1", "opencode.ai")
	tr := b.client.Transport.(*http.Transport)
	if !b.ipv4 || tr.Proxy != nil || tr.DialTLSContext == nil || tr.ForceAttemptHTTP2 {
		t.Fatalf("bad twin config")
	}
	d := newIPv4Backend("direct-v4", "", "opencode.ai")
	if d.client.Transport.(*http.Transport).DialTLSContext == nil {
		t.Fatal("direct-v4 must use the uTLS dialer")
	}
}

func TestIPv4FirstOrder(t *testing.T) {
	n := func(name string, v4 bool) *backend { return &backend{name: name, ipv4: v4} }
	in := []*backend{n("direct", false), n("direct-v4", true), n("via-ovh", false), n("via-ovh-v4", true),
		n("via-oracle", false), n("via-oracle-v4", true), n("via-oracle2", false), n("via-tor", false)}
	var got []string
	for _, b := range ipv4FirstOrder(in) {
		got = append(got, b.name)
	}
	want := "direct-v4 via-ovh-v4 via-oracle-v4 via-oracle2 direct via-ovh via-oracle via-tor"
	if strings.Join(got, " ") != want {
		t.Fatalf("order %v", got)
	}
}

func TestStatusRecordsQuotaAndLastUsed(t *testing.T) {
	cooldown = time.Minute
	d := &backend{name: "direct", client: &http.Client{Transport: &scripted{codes: []int{429}}}}
	v4 := &backend{name: "direct-v4", ipv4: true, client: &http.Client{Transport: &scripted{codes: []int{200}}}}
	rt := newRouter(d, v4)
	rt.status = newStatusBook(rt.backends, "")
	d.markLimited(time.Minute) // as after a real 429
	rt.status.record("direct", 429, "m", 3600, time.Now().Add(time.Minute))
	rt.status.record("direct-v4", 200, "m", 0, time.Time{})
	rec := httptest.NewRecorder()
	rt.ServeHTTP(rec, httptest.NewRequest("GET", "/__router/status", nil))
	body := rec.Body.String()
	for _, want := range []string{`"last_used":"direct-v4"`, `"family":"ipv4"`, `"family":"ipv6"`, `"quota_until":{"m":`, `"next":"direct-v4"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("status missing %s: %s", want, body)
		}
	}
}

func TestStatusPersistsAcrossRestart(t *testing.T) {
	f := t.TempDir() + "/st.json"
	bs := []*backend{{name: "direct"}, {name: "direct-v4", ipv4: true}}
	a := newStatusBook(bs, f)
	a.record("direct", 429, "m", 7200, time.Time{})
	b := newStatusBook(bs, f)
	if _, ok := b.stats["direct"].QuotaUntil["m"]; !ok || b.stats["direct"].R429Today != 1 {
		t.Fatalf("not restored: %+v", b.stats["direct"])
	}
}

func TestStatusOKClearsWholeQuota(t *testing.T) {
	sb := newStatusBook([]*backend{{name: "direct-v4", ipv4: true}}, "")
	sb.record("direct-v4", 429, "a", 3600, time.Now().Add(time.Minute))
	sb.record("direct-v4", 429, "b", 3600, time.Time{})
	sb.record("direct-v4", 200, "a", 0, time.Time{})
	if n := len(sb.stats["direct-v4"].QuotaUntil); n != 0 {
		t.Fatalf("quota left for %d models", n)
	}
}

func TestNewerSameMajor(t *testing.T) {
	cases := []struct {
		cur, cand string
		want      bool
	}{
		{"1.18.32", "1.19.5", true}, {"2.1.1", "2.2.0", true}, {"2.1.1", "2.1.2", true}, {"2.1.1", "2.1.0", false},
		{"2.1.1", "2.1.1", false}, {"2.1.1", "3.0.0", false}, {"2.1.1", "2.3.0-beta.1", false},
		{"2.1.1", "garbage", false}, {"2.9.0", "2.10.0", true},
	}
	for _, c := range cases {
		if got := newerSameMajor(c.cur, c.cand); got != c.want {
			t.Errorf("newerSameMajor(%q,%q)=%v want %v", c.cur, c.cand, got, c.want)
		}
	}
}

// Gate 2026-11-09: a bare "opencode/<ver>" UA is rejected with a fake 429;
// the full CLI fetch UA (with ai-sdk + bun runtime suffix) passes.
func TestZenUserAgentShape(t *testing.T) {
	got := zenUserAgent()
	want := "opencode/" + uaDefaultVersion + " " + uaSuffix
	if got != want || !strings.Contains(got, " runtime/bun/") {
		t.Fatalf("unexpected UA %q, want %q", got, want)
	}
}
