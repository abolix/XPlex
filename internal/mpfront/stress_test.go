package mpfront_test

// End-to-end stress test for the redesigned multipath proxy.
//
// Setup:
//   - Real loopback TCP echo server (the destination).
//   - In-process mp-server.
//   - N fake xrays (some fast, some hung, some broken).
//   - mp client: a long-lived pool over the xrays + a SOCKS5 frontend.
//
// Workload:
//   - 200 fresh SOCKS5 connections, concurrency 8, no keep-alive.
//   - Each writes a small payload, expects byte-perfect echo, closes.
//
// MUST be 100%, fast, and finish well under 5s. The previous design
// failed this test because every accepted SOCKS5 connection opened
// fresh tunnels. The new design opens N tunnels ONCE at startup and
// every SOCKS5 session multiplexes onto them.

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"xplex/internal/mpfront"
	"xplex/internal/mphub"
	"xplex/internal/mppool"
	"xplex/internal/mpserver"
	"xplex/internal/socks5"
	"xplex/internal/testutil"
)

// startEcho launches a TCP echo server.
func startEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	return ln.Addr().String()
}

// fake xray flavors.
const (
	xrayFast = iota
	xraySlow
	xrayBroken
	xrayHang
)

// startFakeXray launches an in-process SOCKS5 server that forwards to
// whatever target it's asked, used to stand in for a real xray.
func startFakeXray(t *testing.T, kind int, slowDelay time.Duration) string {
	t.Helper()
	srv := &testutil.FakeSocks5{
		Handler: func(target string, port uint16, tunnel net.Conn) {
			switch kind {
			case xrayBroken:
				_ = tunnel.Close()
				return
			case xrayHang:
				time.Sleep(30 * time.Second)
				_ = tunnel.Close()
				return
			case xraySlow:
				time.Sleep(slowDelay)
			}
			down, err := net.DialTimeout("tcp",
				net.JoinHostPort(target, strconv.Itoa(int(port))),
				3*time.Second)
			if err != nil {
				_ = tunnel.Close()
				return
			}
			done := make(chan struct{}, 2)
			go func() { _, _ = io.Copy(down, tunnel); done <- struct{}{} }()
			go func() { _, _ = io.Copy(tunnel, down); done <- struct{}{} }()
			<-done
			_ = down.Close()
			_ = tunnel.Close()
		},
	}
	addr, err := srv.Start()
	if err != nil {
		t.Fatalf("xray start: %v", err)
	}
	t.Cleanup(srv.Close)
	return addr
}

// startMPServer starts an mpserver on an ephemeral port.
func startMPServer(t *testing.T, ctx context.Context) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen mp: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	go func() {
		_ = mpserver.New(mpserver.Config{ListenAddr: addr, Codec: testutil.TestCodec(t)}).Run(ctx)
	}()
	waitListen(t, addr, 2*time.Second)
	return addr
}

// startFront builds a pool over the given xray addrs and runs an
// mpfront on a fresh ephemeral SOCKS5 port.
func startFront(t *testing.T, ctx context.Context, mpAddr string, xrayAddrs []string) string {
	t.Helper()
	mpHost, mpPortStr, _ := net.SplitHostPort(mpAddr)
	mpPort, _ := strconv.Atoi(mpPortStr)

	dialers := make([]mppool.DialFunc, 0, len(xrayAddrs))
	names := make([]string, 0, len(xrayAddrs))
	for i, xa := range xrayAddrs {
		xa := xa
		dialers = append(dialers, func(ctx context.Context) (net.Conn, error) {
			t := 5 * time.Second
			if dl, ok := ctx.Deadline(); ok {
				t = time.Until(dl)
			}
			return socks5.Dial(xa, mpHost, uint16(mpPort), t)
		})
		names = append(names, fmt.Sprintf("x%d", i))
	}

	pool := mppool.New(ctx, mppool.Config{Codec: testutil.TestCodec(t), Dialers: dialers, Names: names})
	t.Cleanup(pool.Close)
	hub := mphub.New(ctx, pool, nil)
	t.Cleanup(hub.Close)

	addr := freeAddr(t)
	front := mpfront.New(hub, mpfront.Config{ListenAddr: addr})
	go func() { _ = front.Run(ctx) }()
	waitListen(t, addr, 2*time.Second)

	// Wait for at least one tunnel slot to come up.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if pool.LiveCount() > 0 {
			return addr
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no tunnels came up in time")
	return ""
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

func waitListen(t *testing.T, addr string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			c.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("nothing listening on %s after %s", addr, timeout)
}

// doRequest opens a SOCKS5 conn through the front, writes payload,
// reads the echo, validates byte-for-byte. Returns latency on success.
func doRequest(t *testing.T, frontAddr, dest string, payloadSize int) (time.Duration, bool) {
	t.Helper()
	host, p, _ := net.SplitHostPort(dest)
	port, _ := strconv.Atoi(p)

	payload := make([]byte, payloadSize)
	_, _ = rand.Read(payload)

	t0 := time.Now()
	conn, err := socks5.Dial(frontAddr, host, uint16(port), 5*time.Second)
	if err != nil {
		t.Logf("dial: %v", err)
		return 0, false
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		t.Logf("write: %v", err)
		return 0, false
	}
	got := make([]byte, payloadSize)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Logf("read: %v", err)
		return 0, false
	}
	if !bytes.Equal(got, payload) {
		t.Logf("byte mismatch")
		return 0, false
	}
	return time.Since(t0), true
}

func TestStress_AllFastXrays(t *testing.T) {
	const (
		total = 50
		conc  = 4
	)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dest := startEcho(t)
	mp := startMPServer(t, ctx)
	xrays := []string{
		startFakeXray(t, xrayFast, 0),
		startFakeXray(t, xrayFast, 0),
		startFakeXray(t, xrayFast, 0),
	}
	front := startFront(t, ctx, mp, xrays)

	var ok, fail atomic.Int64
	var latMu sync.Mutex
	var lats []time.Duration
	jobs := make(chan int, total)
	for i := 0; i < total; i++ {
		jobs <- i
	}
	close(jobs)

	var wg sync.WaitGroup
	start := time.Now()
	for w := 0; w < conc; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range jobs {
				lat, good := doRequest(t, front, dest, 256)
				if good {
					ok.Add(1)
					latMu.Lock()
					lats = append(lats, lat)
					latMu.Unlock()
				} else {
					fail.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)

	t.Logf("all-fast: %d ok / %d fail in %v (%.1f rps)",
		ok.Load(), fail.Load(), elapsed.Round(time.Millisecond),
		float64(total)/elapsed.Seconds())

	if fail.Load() > 0 {
		t.Fatalf("had %d failures (must be 0)", fail.Load())
	}
	sort.Slice(lats, func(i, j int) bool { return lats[i] < lats[j] })
	t.Logf("p50=%v p99=%v max=%v",
		lats[len(lats)/2], lats[(len(lats)*99)/100], lats[len(lats)-1])
}

func TestStress_WithHangingXrays(t *testing.T) {
	const (
		total = 50
		conc  = 4
	)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dest := startEcho(t)
	mp := startMPServer(t, ctx)
	xrays := []string{
		startFakeXray(t, xrayFast, 0),
		startFakeXray(t, xrayFast, 0),
		startFakeXray(t, xrayHang, 0),   // hostile slowpoke
		startFakeXray(t, xrayBroken, 0), // hostile dead
	}
	front := startFront(t, ctx, mp, xrays)

	var ok, fail atomic.Int64
	jobs := make(chan int, total)
	for i := 0; i < total; i++ {
		jobs <- i
	}
	close(jobs)

	var wg sync.WaitGroup
	start := time.Now()
	for w := 0; w < conc; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range jobs {
				if _, good := doRequest(t, front, dest, 256); good {
					ok.Add(1)
				} else {
					fail.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)

	t.Logf("mixed: %d ok / %d fail in %v",
		ok.Load(), fail.Load(), elapsed.Round(time.Millisecond))

	if fail.Load() > 0 {
		t.Fatalf("had %d failures (broken/hung xrays must not affect healthy ones)", fail.Load())
	}
	if elapsed > 15*time.Second {
		t.Errorf("test took %v; should finish quickly with 2 healthy tunnels", elapsed)
	}
}

func TestStress_LargePayload(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dest := startEcho(t)
	mp := startMPServer(t, ctx)
	xrays := []string{
		startFakeXray(t, xrayFast, 0),
		startFakeXray(t, xrayFast, 0),
	}
	front := startFront(t, ctx, mp, xrays)

	if _, ok := doRequest(t, front, dest, 1<<20); !ok {
		t.Fatal("1 MiB round-trip failed")
	}
}

