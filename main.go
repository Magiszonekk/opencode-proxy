// opencode-egress-router: sits between CLIProxyAPI and OpenCode Zen.
// Forwards requests to the real upstream through one of several egress
// backends. On HTTP 429 from the current backend, marks it rate-limited
// for a cooldown window and retries the same request via the next backend.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

type backend struct {
	name         string
	client       *http.Client
	mu           sync.Mutex
	limitedUntil time.Time
	// attempts > 1 retries a 429 on the same backend; only useful when every
	// attempt leaves from a different IP (Tor, one fresh circuit per request).
	attempts int
	// ipv4 forces the upstream connection over IPv4: the request goes to an A
	// record of the upstream host (TLS SNI and Host stay the hostname). Zen is
	// dual-stack, so a dual-stack egress (home, OVH, Oracle) otherwise always
	// leaves via IPv6 and its IPv4 address - with its own per-IP free quota -
	// is never used. Zen counts the quota per IPv6 /64, so rotating addresses
	// inside one /64 does not help; the IPv4 address does.
	ipv4 bool
}

func (b *backend) available(now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return now.After(b.limitedUntil)
}

func (b *backend) markLimited(cooldown time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.limitedUntil = time.Now().Add(cooldown)
	log.Printf("[%s] marked rate-limited, cooling down until %s", b.name, b.limitedUntil.Format(time.RFC3339))
}

func newDirectBackend() *backend {
	return &backend{
		name:   "direct",
		client: &http.Client{Transport: &http.Transport{}},
	}
}

// newIPv4Backend is the IPv4 twin of a direct (proxyURL == "") or proxied
// backend. The URL host is rewritten to an IPv4 literal per request (see
// upstreamIPv4), so an HTTP proxy CONNECTs to that address and cannot pick
// AAAA; the direct dialer additionally only dials tcp4.
func newIPv4Backend(name, proxyURL, serverName string) *backend {
	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{ServerName: serverName},
		ForceAttemptHTTP2: true,
	}
	if proxyURL == "" {
		d := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
		tr.DialContext = func(ctx context.Context, _, addr string) (net.Conn, error) {
			return d.DialContext(ctx, "tcp4", addr)
		}
	} else {
		u, err := url.Parse(proxyURL)
		if err != nil {
			log.Fatalf("invalid proxy url for backend %s: %v", name, err)
		}
		tr.Proxy = http.ProxyURL(u)
	}
	return &backend{name: name, client: &http.Client{Transport: tr}, ipv4: true}
}

var (
	v4Mu    sync.Mutex
	v4Addr  string
	v4At    time.Time
	v4Cache = 5 * time.Minute
	// lookupIPv4 is swapped in tests.
	lookupIPv4 = func(host string) (string, error) {
		ips, err := net.DefaultResolver.LookupIP(context.Background(), "ip4", host)
		if err != nil {
			return "", err
		}
		if len(ips) == 0 {
			return "", &net.DNSError{Err: "no A record", Name: host}
		}
		return ips[0].String(), nil
	}
)

// upstreamIPv4 returns an A record of host, cached for a few minutes.
func upstreamIPv4(host string) (string, error) {
	v4Mu.Lock()
	defer v4Mu.Unlock()
	if v4Addr != "" && time.Since(v4At) < v4Cache {
		return v4Addr, nil
	}
	ip, err := lookupIPv4(host)
	if err != nil {
		if v4Addr != "" {
			return v4Addr, nil // stale beats nothing
		}
		return "", err
	}
	v4Addr, v4At = ip, time.Now()
	return ip, nil
}

func newProxiedBackend(name, proxyURL string) *backend {
	u, err := url.Parse(proxyURL)
	if err != nil {
		log.Fatalf("invalid proxy url for backend %s: %v", name, err)
	}
	return &backend{
		name:   name,
		client: &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(u)}},
	}
}

// newTorBackend sends every request through Tor with random SOCKS credentials.
// Tor isolates streams by SOCKS auth (IsolateSOCKSAuth, on by default), so each
// request gets its own circuit and usually a different exit IP. Keep-alives are
// off so a pooled connection never pins two requests to one circuit.
func newTorBackend(socksAddr string, attempts int) *backend {
	proxy := func(*http.Request) (*url.URL, error) {
		buf := make([]byte, 8)
		if _, err := rand.Read(buf); err != nil {
			return nil, err
		}
		return &url.URL{Scheme: "socks5", Host: socksAddr, User: url.UserPassword(hex.EncodeToString(buf), "x")}, nil
	}
	return &backend{
		name:     "via-tor",
		client:   &http.Client{Transport: &http.Transport{Proxy: proxy, DisableKeepAlives: true}},
		attempts: attempts,
	}
}

type router struct {
	upstream *url.URL
	backends []*backend // priority order; first available wins
}

func (rt *router) orderedBackends(now time.Time) []*backend {
	ordered := make([]*backend, 0, len(rt.backends))
	skipped := make([]*backend, 0, len(rt.backends))
	for _, b := range rt.backends {
		if b.available(now) {
			ordered = append(ordered, b)
		} else {
			skipped = append(skipped, b)
		}
	}
	// If every backend is currently in cooldown, still try them in priority
	// order — better to hit the upstream and surface its real error than to
	// fail closed locally.
	return append(ordered, skipped...)
}

func (rt *router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var bodyBytes []byte
	if r.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(r.Body)
		r.Body.Close()
		if err != nil {
			http.Error(w, "failed to read request body", http.StatusBadGateway)
			return
		}
	}

	// Satisfy Zen's anonymous free-tier gate. Only free-tier models are
	// touched; paid traffic (real sk- key) passes through unchanged.
	var (
		zenApplied         bool
		clientWantedStream bool
		museSparkApplied   bool
	)
	if strings.HasSuffix(r.URL.Path, "/chat/completions") {
		rewritten, wantedStream, applied := rewriteZenBody(bodyBytes)
		if applied {
			bodyBytes = rewritten
			zenApplied = true
			clientWantedStream = wantedStream
		}
	} else if strings.HasSuffix(r.URL.Path, "/responses") {
		rewritten, wantedStream, applied := rewriteMuseSparkBody(bodyBytes)
		if applied {
			bodyBytes = rewritten
			zenApplied = true
			clientWantedStream = wantedStream
			museSparkApplied = true
		}
	}

	target := *rt.upstream
	target.Path = strings.TrimRight(rt.upstream.Path, "/") + r.URL.Path
	target.RawQuery = r.URL.RawQuery

	now := time.Now()
	backends := rt.orderedBackends(now)

	// Flatten backends into attempts: a backend with attempts=N (Tor) is tried
	// up to N times, each time on a fresh circuit.
	type try struct {
		b *backend
		n int
	}
	var tries []try
	for _, b := range backends {
		for n := 1; n <= max(1, b.attempts); n++ {
			tries = append(tries, try{b, n})
		}
	}

	var lastErr error
	for i, t := range tries {
		b := t.b
		reqURL := target
		if b.ipv4 {
			ip, errIP := upstreamIPv4(rt.upstream.Hostname())
			if errIP != nil {
				log.Printf("[%s] no IPv4 for upstream: %v", b.name, errIP)
				lastErr = errIP
				continue
			}
			port := rt.upstream.Port()
			if port == "" {
				port = "443"
				if rt.upstream.Scheme == "http" {
					port = "80"
				}
			}
			reqURL.Host = net.JoinHostPort(ip, port)
		}
		req, err := http.NewRequest(r.Method, reqURL.String(), bytes.NewReader(bodyBytes))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		req.Header = r.Header.Clone()
		req.Host = rt.upstream.Host

		if zenApplied {
			sessionID, errSession := newZenDescendingSessionID()
			if errSession != nil {
				http.Error(w, "failed to generate session id", http.StatusInternalServerError)
				return
			}
			req.Header.Set("x-opencode-session", sessionID)
			req.Header.Set("User-Agent", zenUserAgent)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "text/event-stream")
			req.ContentLength = int64(len(bodyBytes))
		}

		resp, err := b.client.Do(req)
		if err != nil {
			log.Printf("[%s] request error: %v", b.name, err)
			lastErr = err
			continue
		}

		// Rotating backend (Tor): a blocked exit node shows up as 403/429/5xx from the
		// upstream or its CDN. Try again on a fresh circuit while attempts remain.
		if b.attempts > 1 && t.n < b.attempts && (resp.StatusCode == http.StatusForbidden ||
			resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500) {
			snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 160))
			resp.Body.Close()
			log.Printf("[%s] %d on attempt %d/%d, retrying on a new circuit: model=%s body=%q", b.name, resp.StatusCode, t.n, b.attempts, modelOf(bodyBytes), snippet)
			continue
		}

		if resp.StatusCode == http.StatusTooManyRequests && i < len(tries)-1 {
			snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 160))
			resp.Body.Close()
			// Log WHY: the body tells an IP rate limit apart from provider
			// overload ("Upstream request failed: Endpoint is unavailable"),
			// which no amount of egress rotation can fix.
			log.Printf("[%s] 429 model=%s%s body=%q", b.name, modelOf(bodyBytes), limitHeaders(resp.Header), snippet)
			b.markLimited(cooldown)
			continue
		}

		// Error bodies are small: buffer them so the reason is logged and
		// still forwarded to the caller unchanged.
		if resp.StatusCode >= 400 {
			errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
			resp.Body.Close()
			log.Printf("[%s] %s %s -> %d%s model=%s%s body=%q", b.name, r.Method, r.URL.Path, resp.StatusCode,
				zenTag(zenApplied), modelOf(bodyBytes), limitHeaders(resp.Header), truncate(errBody, 160))
			for k, vv := range resp.Header {
				if strings.EqualFold(k, "Content-Length") {
					continue
				}
				for _, v := range vv {
					w.Header().Add(k, v)
				}
			}
			w.WriteHeader(resp.StatusCode)
			w.Write(errBody)
			return
		}

		log.Printf("[%s] %s %s -> %d%s", b.name, r.Method, r.URL.Path, resp.StatusCode, zenTag(zenApplied))

		// The gate forced stream:true upstream. If the caller wanted a plain
		// JSON body, fold the SSE events back into one object.
		if zenApplied && !clientWantedStream && resp.StatusCode >= 200 && resp.StatusCode < 300 {
			var (
				collapsed   []byte
				errCollapse error
			)
			if museSparkApplied {
				collapsed, errCollapse = collapseResponsesSSE(resp.Body)
			} else {
				collapsed, errCollapse = collapseSSEToCompletion(resp.Body)
			}
			resp.Body.Close()
			if errCollapse != nil {
				log.Printf("[%s] SSE collapse failed: %v", b.name, errCollapse)
				http.Error(w, "failed to reassemble upstream stream", http.StatusBadGateway)
				return
			}
			for k, vv := range resp.Header {
				if strings.EqualFold(k, "Content-Type") || strings.EqualFold(k, "Content-Length") {
					continue
				}
				for _, v := range vv {
					w.Header().Add(k, v)
				}
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(resp.StatusCode)
			w.Write(collapsed)
			return
		}

		for k, vv := range resp.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		copyStream(w, resp.Body)
		resp.Body.Close()
		return
	}

	http.Error(w, "all backends failed: "+errString(lastErr), http.StatusBadGateway)
}

// modelOf extracts the "model" field from a JSON request body ("?" if absent).
func modelOf(body []byte) string {
	var v struct {
		Model string `json:"model"`
	}
	if json.Unmarshal(body, &v) != nil || v.Model == "" {
		return "?"
	}
	return v.Model
}

// limitHeaders renders Retry-After and any *ratelimit* response headers, so a
// per-IP / per-key limit is distinguishable from upstream overload in the log.
func limitHeaders(h http.Header) string {
	var parts []string
	for k, vv := range h {
		lk := strings.ToLower(k)
		if lk == "retry-after" || strings.Contains(lk, "ratelimit") {
			parts = append(parts, lk+"="+strings.Join(vv, ","))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	sort.Strings(parts)
	return " " + strings.Join(parts, " ")
}

func truncate(b []byte, n int) []byte {
	if len(b) > n {
		return b[:n]
	}
	return b
}

func zenTag(applied bool) string {
	if applied {
		return " (zenfix)"
	}
	return ""
}

// copyStream forwards the upstream body chunk by chunk, flushing after each
// write so SSE-style streaming completions arrive incrementally instead of
// being buffered until the response finishes.
func copyStream(w http.ResponseWriter, body io.Reader) {
	flusher, _ := w.(http.Flusher)
	buf := make([]byte, 4096)
	for {
		n, err := body.Read(buf)
		if n > 0 {
			w.Write(buf[:n])
			if flusher != nil {
				flusher.Flush()
			}
		}
		if err != nil {
			return
		}
	}
}

func errString(err error) string {
	if err == nil {
		return "no backends configured or all rate-limited"
	}
	return err.Error()
}

var cooldown time.Duration

func main() {
	listenAddr := flag.String("listen", "127.0.0.1:8318", "local listen address")
	upstreamURL := flag.String("upstream", "https://opencode.ai/zen/v1", "real upstream base URL")
	ovhProxyURL := flag.String("ovh-proxy", "http://10.8.0.1:8888", "HTTP proxy on OVH box for the fallback egress path")
	oracleProxyURL := flag.String("oracle-proxy", "", "optional third egress backend (HTTP proxy, e.g. on Oracle VPS); skipped if empty")
	oracle2ProxyURL := flag.String("oracle2-proxy", "", "optional egress backend tried after -oracle-proxy, e.g. the Oracle VPS's second public IP (http:// or socks5:// URL); skipped if empty")
	cooldownFlag := flag.Duration("cooldown", 60*time.Second, "how long to avoid a backend after it returns 429")
	torSocks := flag.String("tor-socks", "", "Tor SOCKS5 address (e.g. 127.0.0.1:9050) used as the LAST egress backend, new circuit per request; skipped if empty")
	torAttempts := flag.Int("tor-attempts", 3, "how many fresh Tor circuits to try before giving up")
	ipv4Twins := flag.Bool("ipv4-twins", false, "after each of direct / -ovh-proxy / -oracle-proxy, also try the same egress forced to IPv4 (direct-v4, via-ovh-v4, via-oracle-v4): a dual-stack egress otherwise only ever uses its IPv6 address")
	testOnly := flag.String("test-only-backend", "", "debug: route everything through this one backend (direct|direct-v4|via-ovh|via-ovh-v4|via-oracle|via-oracle-v4|via-oracle2|via-tor)")
	flag.Parse()

	cooldown = *cooldownFlag

	upstream, err := url.Parse(*upstreamURL)
	if err != nil {
		log.Fatalf("invalid upstream url: %v", err)
	}

	rt := &router{upstream: upstream}
	sni := upstream.Hostname()
	rt.backends = append(rt.backends, newDirectBackend())
	if *ipv4Twins {
		rt.backends = append(rt.backends, newIPv4Backend("direct-v4", "", sni))
	}
	rt.backends = append(rt.backends, newProxiedBackend("via-ovh", *ovhProxyURL))
	if *ipv4Twins {
		rt.backends = append(rt.backends, newIPv4Backend("via-ovh-v4", *ovhProxyURL, sni))
	}
	if *oracleProxyURL != "" {
		rt.backends = append(rt.backends, newProxiedBackend("via-oracle", *oracleProxyURL))
		if *ipv4Twins {
			rt.backends = append(rt.backends, newIPv4Backend("via-oracle-v4", *oracleProxyURL, sni))
		}
	}
	if *oracle2ProxyURL != "" {
		rt.backends = append(rt.backends, newProxiedBackend("via-oracle2", *oracle2ProxyURL))
	}
	if *torSocks != "" {
		rt.backends = append(rt.backends, newTorBackend(*torSocks, *torAttempts))
	}
	if *testOnly != "" {
		var keep []*backend
		for _, b := range rt.backends {
			if b.name == *testOnly {
				keep = append(keep, b)
			}
		}
		if len(keep) == 0 {
			log.Fatalf("test-only-backend %q not configured", *testOnly)
		}
		rt.backends = keep
	}

	names := make([]string, 0, len(rt.backends))
	for _, b := range rt.backends {
		names = append(names, b.name)
	}
	log.Printf("opencode-egress-router listening on %s, upstream=%s, backends=%s, tor-attempts=%d, cooldown=%s",
		*listenAddr, *upstreamURL, strings.Join(names, " -> "), *torAttempts, cooldown)
	log.Fatal(http.ListenAndServe(*listenAddr, rt))
}
