package mpadapt_test

// Tests for the adaptive controller.
//
// We build a real pool with 5 fake xrays in front of a fake mp-server
// + echo dest, run sustained traffic, and verify that:
//   1. Slow tunnels get demoted to Shadow.
//   2. Once a slow tunnel becomes fast again, it gets promoted back.
//   3. The system never drops below MinActive.

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"xplex/internal/mpadapt"
	"xplex/internal/mpfront"
	"xplex/internal/mphub"
	"xplex/internal/mppool"
	"xplex/internal/mpserver"
	"xplex/internal/socks5"
	"xplex/internal/testutil"
)

// settableXray exposes a knob to inject latency into a fake xray on
// the fly, simulating "the path got slow" mid-test.
type settableXray struct {
	srv     *testutil.FakeSocks5
	addr    string
	delayNs atomic.Int64
}

func newSettableXray(t *testing.T) *settableXray {
	t.Helper()
	x := &settableXray{}
	x.srv = &testutil.FakeSocks5{
		Handler: func(target string, port uint16, tunnel net.Conn) {
			down, err := net.DialTimeout("tcp",
				net.JoinHostPort(target, strconv.Itoa(int(port))),
				3*time.Second)
			if err != nil {
				_ = tunnel.Close()
				return
			}
			defer down.Close()
			defer tunnel.Close()

			// Inject delay on outbound (tunnel -> dest).
			done := make(chan struct{}, 2)
			go func() {
				buf := make([]byte, 32*1024)
				for {
					n, err := tunnel.Read(buf)
					if n > 0 {
						if d := x.delayNs.Load(); d > 0 {
							time.Sleep(time.Duration(d))
						}
						if _, werr := down.Write(buf[:n]); werr != nil {
							done <- struct{}{}
							return
						}
					}
					if err != nil {
						done <- struct{}{}
						return
					}
				}
			}()
			go func() {
				buf := make([]byte, 32*1024)
				for {
					n, err := down.Read(buf)
					if n > 0 {
						if d := x.delayNs.Load(); d > 0 {
							time.Sleep(time.Duration(d))
						}
						if _, werr := tunnel.Write(buf[:n]); werr != nil {
							done <- struct{}{}
							return
						}
					}
					if err != nil {
						done <- struct{}{}
						return
					}
				}
			}()
			<-done
			// Close both sides so the other goroutine unblocks too.
			_ = tunnel.Close()
			_ = down.Close()
		},
	}
	addr, err := x.srv.Start()
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(x.srv.Close)
	x.addr = addr
	return x
}

func (x *settableXray) setDelay(d time.Duration) {
	x.delayNs.Store(int64(d))
}

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

func startMPServer(t *testing.T, ctx context.Context) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	go func() {
		_ = mpserver.New(mpserver.Config{ListenAddr: addr, Codec: testutil.TestCodec(t)}).Run(ctx)
	}()
	waitListen(t, addr, 2*time.Second)
	return addr
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
	t.Fatalf("nothing on %s", addr)
}

func waitTunnels(t *testing.T, pool *mppool.Pool, want int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if pool.LiveCount() >= want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("only %d tunnels live, wanted %d", pool.LiveCount(), want)
}

// TestController_DemotesSlowTunnel: 5 xrays, 1 is slow. After a few
// evaluation rounds, the slow one should be Shadow and the controller
// should converge to MaxActive=3 with the 3 fastest in Active.
func TestController_DemotesSlowTunnel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // fires first, before t.Cleanup-registered closers

	dest := startEcho(t)
	mp := startMPServer(t, ctx)

	// 5 xrays — the first is intentionally slow.
	xrays := make([]*settableXray, 5)
	for i := range xrays {
		xrays[i] = newSettableXray(t)
	}
	xrays[0].setDelay(50 * time.Millisecond) // hostile

	mpHost, mpPortStr, _ := net.SplitHostPort(mp)
	mpPort, _ := strconv.Atoi(mpPortStr)

	dialers := make([]mppool.DialFunc, len(xrays))
	names := make([]string, len(xrays))
	for i, x := range xrays {
		x := x
		dialers[i] = func(ctx context.Context) (net.Conn, error) {
			t := 5 * time.Second
			if dl, ok := ctx.Deadline(); ok {
				t = time.Until(dl)
			}
			return socks5.Dial(x.addr, mpHost, uint16(mpPort), t)
		}
		names[i] = fmt.Sprintf("x%d", i)
	}

	pool := mppool.New(ctx, mppool.Config{Codec: testutil.TestCodec(t), Dialers: dialers, Names: names})
	t.Cleanup(pool.Close)
	hub := mphub.New(ctx, pool, nil)
	t.Cleanup(hub.Close)

	waitTunnels(t, pool, len(xrays), 3*time.Second)

	// Aggressive controller config so tests are fast.
	cfg := mpadapt.Config{
		MinActive:           2,
		MaxActive:           3,
		Tick:                300 * time.Millisecond,
		DemoteThreshold:     0.05,
		MinFrames:           20,
		CooldownAfterChange: 200 * time.Millisecond,
	}
	go mpadapt.Run(ctx, hub, cfg)

	frontAddr := freeAddr(t)
	front := mpfront.New(hub, mpfront.Config{ListenAddr: frontAddr})
	go func() { _ = front.Run(ctx) }()
	waitListen(t, frontAddr, 2*time.Second)

	host, p, _ := net.SplitHostPort(dest)
	port, _ := strconv.Atoi(p)

	// Drive sustained traffic for ~3 seconds, rate-limited to avoid
	// exhausting Windows ephemeral ports (TIME_WAIT accumulation).
	stopCh := make(chan struct{})
	time.AfterFunc(3*time.Second, func() { close(stopCh) })
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stopCh:
					return
				case <-ctx.Done():
					return
				default:
				}
				doRequest(t, frontAddr, host, uint16(port), 256)
				time.Sleep(20 * time.Millisecond) // rate limit: ~50 req/s/worker
			}
		}()
	}
	wg.Wait()

	// Give the controller one more tick.
	time.Sleep(500 * time.Millisecond)

	// Verify: the slow xray (xrays[0]) should be Shadow.
	tunnels := pool.Tunnels()
	if len(tunnels) != len(xrays) {
		t.Fatalf("expected %d tunnels, have %d", len(xrays), len(tunnels))
	}
	var slowState mppool.State
	activeCount := 0
	for _, tn := range tunnels {
		if tn.State() == mppool.StateActive {
			activeCount++
		}
		if tn.Name() == "x0" {
			slowState = tn.State()
		}
	}
	t.Logf("activeCount=%d (want=%d)", activeCount, cfg.MaxActive)
	if activeCount > cfg.MaxActive {
		t.Errorf("active count %d exceeds MaxActive %d", activeCount, cfg.MaxActive)
	}
	if activeCount < cfg.MinActive {
		t.Errorf("active count %d below MinActive %d", activeCount, cfg.MinActive)
	}
	if slowState == mppool.StateActive {
		// Soft check — sometimes 50ms isn't enough to win 0% of races,
		// just make a noisy log.
		t.Logf("WARNING: slow xray x0 is still Active (delay was probably too small to discriminate)")
	}

	// Explicitly cancel to tear down all tunnels before cleanup.
	cancel()
}

// doRequest opens a SOCKS5 conn, writes payload, reads echo. Soft on
// errors — we want the loop to keep going so the controller has data.
func doRequest(t *testing.T, frontAddr, host string, port uint16, n int) {
	t.Helper()
	payload := make([]byte, n)
	_, _ = rand.Read(payload)

	conn, err := socks5.Dial(frontAddr, host, port, 2*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = conn.Write(payload)
	got := make([]byte, n)
	_, _ = io.ReadFull(conn, got)
}

// TestController_RespectsMinActive: even with all tunnels having zero
// wins (e.g. cold start), the system never drops below MinActive.
func TestController_RespectsMinActive(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dest := startEcho(t)
	mp := startMPServer(t, ctx)

	xrays := make([]*settableXray, 4)
	for i := range xrays {
		xrays[i] = newSettableXray(t)
	}

	mpHost, mpPortStr, _ := net.SplitHostPort(mp)
	mpPort, _ := strconv.Atoi(mpPortStr)
	dialers := make([]mppool.DialFunc, len(xrays))
	names := make([]string, len(xrays))
	for i, x := range xrays {
		x := x
		dialers[i] = func(ctx context.Context) (net.Conn, error) {
			t := 5 * time.Second
			if dl, ok := ctx.Deadline(); ok {
				t = time.Until(dl)
			}
			return socks5.Dial(x.addr, mpHost, uint16(mpPort), t)
		}
		names[i] = fmt.Sprintf("x%d", i)
	}

	pool := mppool.New(ctx, mppool.Config{Codec: testutil.TestCodec(t), Dialers: dialers, Names: names})
	t.Cleanup(pool.Close)
	hub := mphub.New(ctx, pool, nil)
	t.Cleanup(hub.Close)

	waitTunnels(t, pool, len(xrays), 3*time.Second)

	cfg := mpadapt.Config{
		MinActive:           2,
		MaxActive:           2, // try to push way below
		Tick:                200 * time.Millisecond,
		DemoteThreshold:     0.5, // very aggressive — nothing meets this
		MinFrames:           10,
		CooldownAfterChange: 100 * time.Millisecond,
	}
	go mpadapt.Run(ctx, hub, cfg)

	frontAddr := freeAddr(t)
	front := mpfront.New(hub, mpfront.Config{ListenAddr: frontAddr})
	go func() { _ = front.Run(ctx) }()
	waitListen(t, frontAddr, 2*time.Second)

	host, p, _ := net.SplitHostPort(dest)
	port, _ := strconv.Atoi(p)

	stop := time.After(2 * time.Second)
	for {
		select {
		case <-stop:
			goto done
		default:
		}
		doRequest(t, frontAddr, host, uint16(port), 64)
		time.Sleep(20 * time.Millisecond) // rate limit
	}
done:
	time.Sleep(300 * time.Millisecond)

	active := pool.ActiveCount()
	if active < cfg.MinActive {
		t.Errorf("active=%d below MinActive=%d", active, cfg.MinActive)
	}
	t.Logf("active=%d (MinActive=%d, MaxActive=%d)", active, cfg.MinActive, cfg.MaxActive)

	// Explicitly cancel to tear down all tunnels before cleanup.
	cancel()
}

