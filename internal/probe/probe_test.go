package probe_test

import (
	"crypto/tls"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"xrayrunner/internal/probe"
	"xrayrunner/internal/testutil"
)

func portFromAddr(t *testing.T, addr string) int {
	t.Helper()
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split host/port: %v", err)
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		t.Fatalf("port not int: %v", err)
	}
	return n
}

// tlsTerminator returns a SOCKS5 handler that wraps the tunnel in TLS so
// the probe's TLS handshake actually completes.
func tlsTerminator(t *testing.T, observe func(target string, port uint16)) func(string, uint16, net.Conn) {
	cfg := testutil.SelfSignedTLSConfig(t)
	return func(target string, port uint16, conn net.Conn) {
		if observe != nil {
			observe(target, port)
		}
		tc := tls.Server(conn, cfg)
		// We don't care about the result beyond completing the handshake;
		// the probe closes its end immediately after.
		_ = tc.Handshake()
		_ = tc.Close()
	}
}

func TestRun_Success(t *testing.T) {
	var sawHost string
	var sawPort uint16
	srv := &testutil.FakeSocks5{
		Handler: tlsTerminator(t, func(h string, p uint16) {
			sawHost, sawPort = h, p
		}),
	}
	addr, err := srv.Start()
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer srv.Close()

	port := portFromAddr(t, addr)
	r := probe.Run(port, 5*time.Second)
	if !r.OK {
		t.Fatalf("expected OK, got err=%q", r.Err)
	}
	if r.Latency <= 0 {
		t.Errorf("latency should be > 0, got %v", r.Latency)
	}
	if r.Port != port {
		t.Errorf("Result.Port mismatch: got %d, want %d", r.Port, port)
	}
	// The probe must drive a CONNECT to 1.1.1.1:443 through the tunnel.
	if sawHost != "1.1.1.1" || sawPort != 443 {
		t.Errorf("server saw (%q, %d), want (1.1.1.1, 443)", sawHost, sawPort)
	}
}

func TestRun_DialFails(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := portFromAddr(t, ln.Addr().String())
	ln.Close()

	r := probe.Run(port, 200*time.Millisecond)
	if r.OK {
		t.Fatal("expected not OK when nothing is listening")
	}
	if r.Err == "" {
		t.Error("expected error message on dial failure")
	}
}

func TestRun_AuthRefused(t *testing.T) {
	srv := &testutil.FakeSocks5{RefuseAuth: true}
	addr, _ := srv.Start()
	defer srv.Close()

	r := probe.Run(portFromAddr(t, addr), 2*time.Second)
	if r.OK {
		t.Fatal("expected not OK when auth is refused")
	}
}

func TestRun_ConnectRejected(t *testing.T) {
	srv := &testutil.FakeSocks5{FailConnectReply: 0x05}
	addr, _ := srv.Start()
	defer srv.Close()

	r := probe.Run(portFromAddr(t, addr), 2*time.Second)
	if r.OK {
		t.Fatal("expected not OK when CONNECT is rejected")
	}
}

func TestRun_TLSFails(t *testing.T) {
	// Tunnel succeeds but the upstream isn't TLS — closes the conn after
	// SOCKS5 negotiation, so the probe's TLS handshake will fail. This
	// proves the probe really is exercising the tunnel, not just timing
	// the SOCKS5 reply.
	srv := &testutil.FakeSocks5{
		Handler: func(_ string, _ uint16, conn net.Conn) {
			_ = conn.Close()
		},
	}
	addr, _ := srv.Start()
	defer srv.Close()

	r := probe.Run(portFromAddr(t, addr), 2*time.Second)
	if r.OK {
		t.Fatal("expected not OK when TLS handshake cannot complete")
	}
	if !strings.HasPrefix(r.Err, "tls:") {
		t.Errorf("expected tls error, got %q", r.Err)
	}
}

func TestRun_LatencyReflectsUpstreamDelay(t *testing.T) {
	srv := &testutil.FakeSocks5{
		GreetDelay: 200 * time.Millisecond,
		Handler:    tlsTerminator(t, nil),
	}
	addr, _ := srv.Start()
	defer srv.Close()

	r := probe.Run(portFromAddr(t, addr), 5*time.Second)
	if !r.OK {
		t.Fatalf("expected OK, got err=%q", r.Err)
	}
	if r.Latency < 200*time.Millisecond {
		t.Errorf("latency %v should be >= 200ms (upstream delay)", r.Latency)
	}
}
