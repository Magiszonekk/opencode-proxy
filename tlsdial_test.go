package main

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TLS server -> HTTP CONNECT proxy -> uTLS(Bun) client: the full proxied path.
func TestBunTransportThroughHTTPConnect(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "pong:"+r.Proto) }))
	defer srv.Close()
	pl, _ := net.Listen("tcp", "127.0.0.1:0")
	defer pl.Close()
	gotAuth := make(chan string, 1)
	go func() {
		c, err := pl.Accept()
		if err != nil {
			return
		}
		br := bufio.NewReader(c)
		req, _ := http.ReadRequest(br)
		gotAuth <- req.Header.Get("Proxy-Authorization")
		up, _ := net.Dial("tcp", req.Host)
		io.WriteString(c, "HTTP/1.1 200 OK\r\n\r\n")
		go io.Copy(up, c)
		io.Copy(c, up)
	}()
	pu, _ := url.Parse("http://u:p@" + pl.Addr().String())
	d := &egressDialer{proxy: func() (*url.URL, error) { return pu, nil }, insecure: true, serverName: "example.com"}
	cl := &http.Client{Transport: newBunTransport(d, true), Timeout: 10 * time.Second}
	resp, err := cl.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	if string(b) != "pong:HTTP/1.1" {
		t.Fatalf("body %q", b)
	}
	if a := <-gotAuth; a != "Basic dTpw" {
		t.Fatalf("proxy auth %q", a)
	}
}

// Minimal SOCKS5 server with user/pass: checks the handshake bytes.
func TestSocks5ConnectWithAuth(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	defer l.Close()
	got := make(chan string, 1)
	go func() {
		c, _ := l.Accept()
		defer c.Close()
		h := make([]byte, 3)
		io.ReadFull(c, h) // 5,1,2
		c.Write([]byte{5, 2})
		v := make([]byte, 2)
		io.ReadFull(c, v)
		user := make([]byte, v[1])
		io.ReadFull(c, user)
		pl := make([]byte, 1)
		io.ReadFull(c, pl)
		pw := make([]byte, pl[0])
		io.ReadFull(c, pw)
		c.Write([]byte{1, 0})
		r := make([]byte, 5)
		io.ReadFull(c, r) // 5,1,0,3,len
		host := make([]byte, r[4])
		io.ReadFull(c, host)
		port := make([]byte, 2)
		io.ReadFull(c, port)
		got <- string(user) + ":" + string(pw) + "@" + string(host)
		c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	}()
	c, _ := net.Dial("tcp", l.Addr().String())
	defer c.Close()
	pu, _ := url.Parse("socks5://abc:x@" + l.Addr().String())
	if err := socks5Connect(c, pu, "opencode.ai:443"); err != nil {
		t.Fatal(err)
	}
	if g := <-got; g != "abc:x@opencode.ai" {
		t.Fatalf("got %q", g)
	}
}

func TestDialerDirectFailsFast(t *testing.T) {
	d := &egressDialer{timeout: time.Second}
	if _, err := d.DialTLSContext(context.Background(), "tcp", "127.0.0.1:1"); err == nil {
		t.Fatal("want error")
	}
}

func TestEnvBlockAppendedToSystem(t *testing.T) {
	now := time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)
	root := map[string]json.RawMessage{"messages": json.RawMessage(`[{"role":"system","content":"Be brief."},{"role":"user","content":"hi"}]`)}
	if !ensureEnvBlock(root, now) {
		t.Fatal("not changed")
	}
	var m []map[string]any
	json.Unmarshal(root["messages"], &m)
	sys := m[0]["content"].(string)
	if !strings.HasPrefix(sys, "Be brief.\n\n") || !strings.Contains(sys, "<env>") || !strings.Contains(sys, "Mon Oct 26 2026") || len(m) != 2 {
		t.Fatalf("bad: %q", sys)
	}
	if ensureEnvBlock(root, now) {
		t.Fatal("must not add twice")
	}
}

func TestEnvBlockInsertedWhenNoSystem(t *testing.T) {
	root := map[string]json.RawMessage{"messages": json.RawMessage(`[{"role":"user","content":"hi"}]`)}
	ensureEnvBlock(root, time.Now())
	var m []map[string]any
	json.Unmarshal(root["messages"], &m)
	if len(m) != 2 || m[0]["role"] != "system" || !strings.Contains(m[0]["content"].(string), "</env>") {
		t.Fatalf("bad: %v", m)
	}
}

func TestEnvBlockArrayContent(t *testing.T) {
	root := map[string]json.RawMessage{"messages": json.RawMessage(`[{"role":"system","content":[{"type":"text","text":"x"}]},{"role":"user","content":"hi"}]`)}
	ensureEnvBlock(root, time.Now())
	if !strings.Contains(string(root["messages"]), `<env>`) || !strings.Contains(string(root["messages"]), `"text":"x"`) {
		t.Fatalf("bad: %s", root["messages"])
	}
}

func TestRewriteZenBodyAddsEnvOnlyForFree(t *testing.T) {
	out, _, applied := rewriteZenBody([]byte(`{"model":"deepseek-v4.1-flash-free","messages":[{"role":"user","content":"hi"}]}`))
	if !applied || !strings.Contains(string(out), "<env>") {
		t.Fatalf("free: %s", out)
	}
	out, _, applied = rewriteZenBody([]byte(`{"model":"gpt-5","messages":[{"role":"user","content":"hi"}]}`))
	if applied || strings.Contains(string(out), "<env>") {
		t.Fatalf("paid touched: %s", out)
	}
}
