package socks5_test

import (
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"xplex/internal/socks5"
	"xplex/internal/testutil"
)

func TestDial_Echo(t *testing.T) {
	var seenHost string
	var seenPort uint16
	srv := &testutil.FakeSocks5{
		Handler: func(target string, port uint16, conn net.Conn) {
			seenHost, seenPort = target, port
			// Echo whatever the client sends.
			_, _ = io.Copy(conn, conn)
		},
	}
	addr, err := srv.Start()
	if err != nil {
		t.Fatalf("start fake: %v", err)
	}
	defer srv.Close()

	conn, err := socks5.Dial(addr, "example.com", 80, 2*time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 5)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != "hello" {
		t.Errorf("echo mismatch: %q", string(buf))
	}
	if seenHost != "example.com" || seenPort != 80 {
		t.Errorf("server saw (%q, %d), want (example.com, 80)", seenHost, seenPort)
	}
}

func TestDial_IPv4Target(t *testing.T) {
	var seenHost string
	srv := &testutil.FakeSocks5{
		Handler: func(target string, _ uint16, conn net.Conn) {
			seenHost = target
			_ = conn.Close()
		},
	}
	addr, _ := srv.Start()
	defer srv.Close()

	conn, err := socks5.Dial(addr, "1.2.3.4", 443, 2*time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	conn.Close()

	// Give the handler a moment to record before we close the server.
	time.Sleep(50 * time.Millisecond)
	if seenHost != "1.2.3.4" {
		t.Errorf("server saw %q, want 1.2.3.4", seenHost)
	}
}

func TestDial_IPv6Target(t *testing.T) {
	var seenHost string
	srv := &testutil.FakeSocks5{
		Handler: func(target string, _ uint16, conn net.Conn) {
			seenHost = target
			_ = conn.Close()
		},
	}
	addr, _ := srv.Start()
	defer srv.Close()

	conn, err := socks5.Dial(addr, "::1", 443, 2*time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	conn.Close()
	time.Sleep(50 * time.Millisecond)
	if seenHost != "::1" {
		t.Errorf("server saw %q, want ::1", seenHost)
	}
}

func TestDial_AuthRefused(t *testing.T) {
	srv := &testutil.FakeSocks5{RefuseAuth: true}
	addr, _ := srv.Start()
	defer srv.Close()

	_, err := socks5.Dial(addr, "example.com", 80, 2*time.Second)
	if err == nil {
		t.Fatal("expected auth-refused error")
	}
	if !strings.Contains(err.Error(), "auth refused") {
		t.Errorf("error should mention auth refused, got %v", err)
	}
}

func TestDial_ConnectFailure(t *testing.T) {
	// 0x05 = connection refused (per SOCKS5).
	srv := &testutil.FakeSocks5{FailConnectReply: 0x05}
	addr, _ := srv.Start()
	defer srv.Close()

	_, err := socks5.Dial(addr, "example.com", 80, 2*time.Second)
	if err == nil {
		t.Fatal("expected connect error")
	}
	if !strings.Contains(err.Error(), "rep=5") {
		t.Errorf("error should include rep code, got %v", err)
	}
}

func TestDial_DialTimeout(t *testing.T) {
	// 203.0.113.0/24 is reserved for documentation. Most networks black-hole it
	// so a connect attempt actually times out instead of returning ECONNREFUSED.
	// We can't guarantee that, so we instead use a listener that never accepts:
	// open a listener, immediately close it, then dial that now-dead port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	_, err = socks5.Dial(addr, "example.com", 80, 100*time.Millisecond)
	if err == nil {
		t.Fatal("expected dial error against a closed port")
	}
}

func TestDial_HandshakeTimeout(t *testing.T) {
	// Server delays its greeting longer than our timeout.
	srv := &testutil.FakeSocks5{GreetDelay: 500 * time.Millisecond}
	addr, _ := srv.Start()
	defer srv.Close()

	_, err := socks5.Dial(addr, "example.com", 80, 100*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout during handshake")
	}
}

func TestDial_LongHostnameRejected(t *testing.T) {
	srv := &testutil.FakeSocks5{Handler: func(string, uint16, net.Conn) {}}
	addr, _ := srv.Start()
	defer srv.Close()

	long := strings.Repeat("a", 256)
	_, err := socks5.Dial(addr, long, 443, 2*time.Second)
	if err == nil {
		t.Fatal("expected error for >255 char hostname")
	}
}

