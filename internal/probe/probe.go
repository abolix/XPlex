// Package probe measures end-to-end SOCKS5 path liveness and latency.
//
// The probe opens TCP to the local SOCKS5 port, negotiates SOCKS5 CONNECT
// to 1.1.1.1:80, sends a minimal HTTP request, and measures the time
// until a response arrives. This proves the full tunnel path works
// (data flows end-to-end) without requiring TLS, which some links don't
// support for outbound port 443.
//
// Why HTTP to 1.1.1.1:80: it's a literal IP (no DNS), Cloudflare anycast
// (low latency from anywhere), always responds to HTTP, and works through
// links that only support plain TCP or non-443 ports.
package probe

import (
	"fmt"
	"time"

	"xplex/internal/socks5"
)

const (
	targetHost = "1.1.1.1"
	targetPort = 80
	// Minimal HTTP request that Cloudflare will respond to.
	httpReq = "HEAD / HTTP/1.1\r\nHost: 1.1.1.1\r\nConnection: close\r\n\r\n"
)

// Result holds the outcome of a single probe.
type Result struct {
	Port    int
	OK      bool
	Latency time.Duration
	Err     string // empty when OK
}

// Run performs SOCKS5 CONNECT + HTTP round-trip and returns the total
// latency from dial-start to first response byte.
func Run(socksPort int, timeout time.Duration) Result {
	r := Result{Port: socksPort}
	socksAddr := fmt.Sprintf("127.0.0.1:%d", socksPort)

	start := time.Now()

	conn, err := socks5.Dial(socksAddr, targetHost, targetPort, timeout)
	if err != nil {
		r.Latency = time.Since(start)
		r.Err = err.Error()
		return r
	}
	defer conn.Close()

	deadline := time.Now().Add(timeout - time.Since(start))
	if err := conn.SetDeadline(deadline); err != nil {
		r.Latency = time.Since(start)
		r.Err = err.Error()
		return r
	}

	// Send HTTP request.
	if _, err := conn.Write([]byte(httpReq)); err != nil {
		r.Latency = time.Since(start)
		r.Err = "write: " + err.Error()
		return r
	}

	// Read at least 1 byte of response — proves full round-trip.
	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		r.Latency = time.Since(start)
		if err != nil {
			r.Err = "read: " + err.Error()
		} else {
			r.Err = "read: 0 bytes"
		}
		return r
	}

	r.Latency = time.Since(start)
	r.OK = true
	return r
}

