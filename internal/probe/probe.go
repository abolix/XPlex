// Package probe measures end-to-end SOCKS5 path liveness and latency.
//
// The probe opens TCP to the local SOCKS5 port, negotiates SOCKS5 CONNECT
// to 1.1.1.1:443, then performs a TLS handshake over that tunnel and
// stops the clock when the handshake completes.
//
// Why TLS and not just CONNECT: xray's SOCKS5 inbound returns the CONNECT
// success reply as soon as local negotiation finishes — it does not wait
// for the upstream tunnel to be built. Without exchanging any real bytes
// through the tunnel, the probe ends up timing only loopback and reads
// ~0ms. Forcing a TLS handshake guarantees one real round-trip through
// xray → remote server → 1.1.1.1 and back.
//
// Why 1.1.1.1:443: it's a literal IP (no DNS), Cloudflare anycast (close
// from anywhere), always accepts TLS, and supports TLS 1.3 so the
// handshake is 1-RTT.
package probe

import (
	"crypto/tls"
	"fmt"
	"time"

	"xrayrunner/internal/socks5"
)

const (
	targetHost    = "1.1.1.1"
	targetPort    = 443
	tlsServerName = "one.one.one.one"
)

// Result holds the outcome of a single probe.
type Result struct {
	Port    int
	OK      bool
	Latency time.Duration
	Err     string // empty when OK
}

// Run performs SOCKS5 CONNECT + TLS handshake and returns the total
// latency from dial-start to handshake completion.
func Run(socksPort int, timeout time.Duration) Result {
	r := Result{Port: socksPort}
	socksAddr := fmt.Sprintf("127.0.0.1:%d", socksPort)
	deadline := time.Now().Add(timeout)

	start := time.Now()

	conn, err := socks5.Dial(socksAddr, targetHost, targetPort, timeout)
	if err != nil {
		r.Latency = time.Since(start)
		r.Err = err.Error()
		return r
	}
	defer conn.Close()

	if err := conn.SetDeadline(deadline); err != nil {
		r.Latency = time.Since(start)
		r.Err = err.Error()
		return r
	}

	// We only care about timing the round-trip — cert validation is
	// irrelevant for this purpose.
	tlsCfg := &tls.Config{
		ServerName:         tlsServerName,
		InsecureSkipVerify: true, //nolint:gosec // probe-only, no data exchanged
		MinVersion:         tls.VersionTLS12,
	}
	tlsConn := tls.Client(conn, tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		r.Latency = time.Since(start)
		r.Err = "tls: " + err.Error()
		return r
	}

	r.Latency = time.Since(start)
	r.OK = true
	_ = tlsConn.Close()
	return r
}
