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

// A socks5:// URL is accepted for proxied backends.
func TestProxiedBackendAcceptsSocks5(t *testing.T) {
	b := newProxiedBackend("via-oracle2", "socks5://127.0.0.1:1")
	req, _ := http.NewRequest("GET", "https://example.invalid/", nil)
	u, err := b.client.Transport.(*http.Transport).Proxy(req)
	if err != nil || u.Scheme != "socks5" {
		t.Fatalf("proxy=%v err=%v", u, err)
	}
}
