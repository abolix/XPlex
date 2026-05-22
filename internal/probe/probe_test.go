package probe_test

import (
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"xplex/internal/probe"
	"xplex/internal/testutil"
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

// httpResponder returns a SOCKS5 handler that accepts the connection and
// sends back a minimal HTTP response (simulating 1.1.1.1:80).
func httpResponder(observe func(target string, port uint16)) func(string, uint16, net.Conn) {
	return func(target string, port uint16, conn net.Conn) {
		if observe != nil {
			observe(target, port)
		}
		// Read the request (we don't care about content).
		buf := make([]byte, 512)
		_, _ = conn.Read(buf)
		// Send a minimal HTTP response.
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
		_ = conn.Close()
	}
}

func TestRun_Success(t *testing.T) {
	var sawHost string
	var sawPort uint16
	srv := &testutil.FakeSocks5{
		Handler: httpResponder(func(h string, p uint16) {
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
	// The probe must drive a CONNECT to 1.1.1.1:80 through the tunnel.
	if sawHost != "1.1.1.1" || sawPort != 80 {
		t.Errorf("server saw (%q, %d), want (1.1.1.1, 80)", sawHost, sawPort)
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

func TestRun_RemoteCloses(t *testing.T) {
	// Tunnel succeeds but the upstream closes immediately — no HTTP
	// response arrives. Probe should detect this as a failure.
	srv := &testutil.FakeSocks5{
		Handler: func(_ string, _ uint16, conn net.Conn) {
			_ = conn.Close()
		},
	}
	addr, _ := srv.Start()
	defer srv.Close()

	r := probe.Run(portFromAddr(t, addr), 2*time.Second)
	if r.OK {
		t.Fatal("expected not OK when remote closes immediately")
	}
	if !strings.Contains(r.Err, "read:") && !strings.Contains(r.Err, "write:") {
		t.Errorf("expected read/write error, got %q", r.Err)
	}
}

func TestRun_LatencyReflectsUpstreamDelay(t *testing.T) {
	srv := &testutil.FakeSocks5{
		GreetDelay: 200 * time.Millisecond,
		Handler:    httpResponder(nil),
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

