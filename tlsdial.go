package main

// tlsdial.go: every upstream connection is a uTLS handshake with Bun's
// ClientHello. Zen gate revision 2026-10-26 answers any other TLS fingerprint
// (curl, Go crypto/tls h1 and h2) with a fake "429 FreeUsageLimitError" on
// every IP, while the same request from Bun (opencode's runtime) gets 200.
//
// Go's http.Transport does the target TLS itself when a Proxy is set and never
// calls DialTLSContext, so the proxy hop (HTTP CONNECT or SOCKS5) is done here
// by hand and the transport gets Proxy == nil.

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	utls "github.com/refraction-networking/utls"
)

// bunClientHello mirrors Bun 1.3.14 (ja3 d871d02cecbde59abbf8f4806134addf,
// ALPN http/1.1 only), measured via tls.peet.ws from the bundled opencode Bun.
func bunClientHello() *utls.ClientHelloSpec {
	return &utls.ClientHelloSpec{
		TLSVersMin:         utls.VersionTLS12,
		TLSVersMax:         utls.VersionTLS13,
		CipherSuites:       []uint16{4865, 4866, 4867, 49195, 49199, 49196, 49200, 52393, 52392, 49161, 49171, 49162, 49172, 156, 157, 47, 53},
		CompressionMethods: []byte{0},
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{},
			&utls.ExtendedMasterSecretExtension{},
			&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{utls.X25519, utls.CurveP256, utls.CurveP384}},
			&utls.SupportedPointsExtension{SupportedPoints: []byte{0}},
			&utls.SessionTicketExtension{},
			&utls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}},
			&utls.StatusRequestExtension{},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201}},
			&utls.SCTExtension{},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{{Group: utls.X25519}}},
			&utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}},
			&utls.SupportedVersionsExtension{Versions: []uint16{utls.VersionTLS13, utls.VersionTLS12}},
			&utls.UtlsPaddingExtension{GetPaddingLen: utls.BoringPaddingStyle},
		},
	}
}

// egressDialer opens a TCP path (direct or via one proxy) and runs the Bun TLS
// handshake on it.
type egressDialer struct {
	proxy      func() (*url.URL, error) // nil = direct
	tcp4       bool                     // direct only: dial IPv4
	serverName string                   // "" = host part of the dialed addr
	insecure   bool                     // tests only
	timeout    time.Duration
}

func (d *egressDialer) dialTCP(ctx context.Context, addr string) (net.Conn, error) {
	nd := &net.Dialer{Timeout: d.timeout, KeepAlive: 30 * time.Second}
	if d.proxy == nil {
		network := "tcp"
		if d.tcp4 {
			network = "tcp4"
		}
		return nd.DialContext(ctx, network, addr)
	}
	pu, err := d.proxy()
	if err != nil {
		return nil, err
	}
	pc, err := nd.DialContext(ctx, "tcp", pu.Host)
	if err != nil {
		return nil, fmt.Errorf("proxy %s: %w", pu.Host, err)
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = pc.SetDeadline(dl)
	} else {
		_ = pc.SetDeadline(time.Now().Add(d.timeout))
	}
	switch pu.Scheme {
	case "http":
		err = httpConnect(pc, pu, addr)
	case "socks5", "socks5h":
		err = socks5Connect(pc, pu, addr)
	default:
		err = fmt.Errorf("unsupported proxy scheme %q", pu.Scheme)
	}
	if err != nil {
		pc.Close()
		return nil, err
	}
	_ = pc.SetDeadline(time.Time{})
	return pc, nil
}

func (d *egressDialer) DialTLSContext(ctx context.Context, _, addr string) (net.Conn, error) {
	raw, err := d.dialTCP(ctx, addr)
	if err != nil {
		return nil, err
	}
	sni := d.serverName
	if sni == "" {
		sni, _, _ = net.SplitHostPort(addr)
	}
	uc := utls.UClient(raw, &utls.Config{ServerName: sni, InsecureSkipVerify: d.insecure}, utls.HelloCustom)
	if err := uc.ApplyPreset(bunClientHello()); err != nil {
		raw.Close()
		return nil, err
	}
	if err := uc.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, fmt.Errorf("utls handshake: %w", err)
	}
	return uc, nil
}

// newBunTransport: HTTP/1.1 only (Bun offers no h2), all TLS through uTLS.
func newBunTransport(d *egressDialer, disableKeepAlives bool) *http.Transport {
	if d.timeout == 0 {
		d.timeout = 30 * time.Second
	}
	return &http.Transport{
		DialTLSContext:      d.DialTLSContext,
		ForceAttemptHTTP2:   false,
		DisableKeepAlives:   disableKeepAlives,
		MaxIdleConnsPerHost: 8,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 30 * time.Second,
	}
}

func httpConnect(c net.Conn, pu *url.URL, addr string) error {
	req := "CONNECT " + addr + " HTTP/1.1\r\nHost: " + addr + "\r\n"
	if pu.User != nil {
		pw, _ := pu.User.Password()
		req += "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(pu.User.Username()+":"+pw)) + "\r\n"
	}
	if _, err := io.WriteString(c, req+"\r\n"); err != nil {
		return err
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
	if err != nil {
		return fmt.Errorf("proxy CONNECT: %w", err)
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("proxy CONNECT %s: %s", addr, resp.Status)
	}
	if br.Buffered() > 0 {
		return errors.New("proxy CONNECT: unexpected data after 200")
	}
	return nil
}

// socks5Connect: RFC 1928 CONNECT with the hostname (remote DNS), optional
// RFC 1929 user/pass (Tor isolates circuits per credential).
func socks5Connect(c net.Conn, pu *url.URL, addr string) error {
	host, portS, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(portS)
	if err != nil {
		return err
	}
	methods := []byte{0x00}
	if pu.User != nil {
		methods = []byte{0x02}
	}
	if _, err := c.Write(append([]byte{5, byte(len(methods))}, methods...)); err != nil {
		return err
	}
	rep := make([]byte, 2)
	if _, err := io.ReadFull(c, rep); err != nil {
		return err
	}
	if rep[0] != 5 || rep[1] == 0xff {
		return errors.New("socks5: no acceptable auth method")
	}
	if rep[1] == 0x02 {
		user := pu.User.Username()
		pw, _ := pu.User.Password()
		msg := append([]byte{1, byte(len(user))}, user...)
		msg = append(append(msg, byte(len(pw))), pw...)
		if _, err := c.Write(msg); err != nil {
			return err
		}
		if _, err := io.ReadFull(c, rep); err != nil {
			return err
		}
		if rep[1] != 0 {
			return errors.New("socks5: auth rejected")
		}
	}
	req := []byte{5, 1, 0}
	if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
		req = append(append(req, 1), ip.To4()...)
	} else if ip != nil {
		req = append(append(req, 4), ip.To16()...)
	} else {
		req = append(append(req, 3, byte(len(host))), host...)
	}
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err := c.Write(req); err != nil {
		return err
	}
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return err
	}
	if hdr[1] != 0 {
		return fmt.Errorf("socks5: connect failed, code %d", hdr[1])
	}
	var skip int
	switch hdr[3] {
	case 1:
		skip = 4
	case 4:
		skip = 16
	case 3:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return err
		}
		skip = int(l[0])
	default:
		return errors.New("socks5: bad address type in reply")
	}
	_, err = io.ReadFull(c, make([]byte, skip+2))
	return err
}
