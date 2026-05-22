package mpfront_test

// Test: a long-lived TCP session (simulating Stratum mining) must survive
// while tunnels flap. This reproduces the production bug where dead xray
// links create tunnel storms that can disrupt active mining sessions.

import (
	"context"
	"fmt"
	"io"
	"net"
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

// startLongLivedServer starts a TCP server that accepts connections and
// echoes data every 5s (simulating Stratum pool sending work updates).
func startLongLivedServer(t *testing.T) string {
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
				// Send "work" every 2s, also echo anything received.
				go func() {
					ticker := time.NewTicker(2 * time.Second)
					defer ticker.Stop()
					for {
						select {
						case <-ticker.C:
							_, err := c.Write([]byte("work-update\n"))
							if err != nil {
								return
							}
						}
					}
				}()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	return ln.Addr().String()
}

func TestLongLivedSession_SurvivesTunnelFlap(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start destination (simulates Stratum pool).
	dest := startLongLivedServer(t)

	// Start mp-server.
	srvLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srvAddr := srvLn.Addr().String()
	srvLn.Close()
	go func() {
		_ = mpserver.New(mpserver.Config{ListenAddr: srvAddr, Codec: testutil.TestCodec(t)}).Run(ctx)
	}()
	waitListen(t, srvAddr, 2*time.Second)

	// Start mp-client with 3 tunnels.
	dialers := make([]mppool.DialFunc, 3)
	names := make([]string, 3)
	host, portStr, _ := net.SplitHostPort(srvAddr)
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	for i := range dialers {
		dialers[i] = func(ctx context.Context) (net.Conn, error) {
			return socks5.Dial("", host, uint16(port), 5*time.Second)
		}
		// Actually connect directly (no xray in test).
		dialers[i] = func(ctx context.Context) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", srvAddr)
		}
		names[i] = fmt.Sprintf("t%d", i)
	}

	pool := mppool.New(ctx, mppool.Config{Codec: testutil.TestCodec(t), Dialers: dialers, Names: names})
	t.Cleanup(pool.Close)
	hub := mphub.New(ctx, pool, nil)
	t.Cleanup(hub.Close)

	frontAddr := freeAddr(t)
	front := mpfront.New(hub, mpfront.Config{ListenAddr: frontAddr})
	go func() { _ = front.Run(ctx) }()
	waitListen(t, frontAddr, 2*time.Second)

	// Wait for tunnels to come up.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if pool.LiveCount() >= 3 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if pool.LiveCount() < 2 {
		t.Fatalf("only %d tunnels up", pool.LiveCount())
	}

	// Open a long-lived SOCKS5 connection to the "mining pool".
	destHost, destPortStr, _ := net.SplitHostPort(dest)
	var destPort int
	fmt.Sscanf(destPortStr, "%d", &destPort)
	conn, err := socks5.Dial(frontAddr, destHost, uint16(destPort), 5*time.Second)
	if err != nil {
		t.Fatalf("dial through proxy: %v", err)
	}
	defer conn.Close()

	// Send a "share" and read back echo + work updates.
	_, err = conn.Write([]byte("share1\n"))
	if err != nil {
		t.Fatalf("write share: %v", err)
	}

	// Read the first response (should be echo of "share1\n" or a work update).
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("first read failed: %v", err)
	}
	t.Logf("got first data: %q", string(buf[:n]))

	// Now simulate tunnel flap: kill tunnel 0, wait, it reconnects.
	tunnels := pool.Tunnels()
	if len(tunnels) > 0 {
		t.Log("killing tunnel 0 to simulate flap...")
		tunnels[0].Close()
	}

	// Wait 3s for reconnect.
	time.Sleep(3 * time.Second)

	// The long-lived session should still be alive. Send another share.
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Write([]byte("share2\n"))
	if err != nil {
		t.Fatalf("write after flap failed (session died): %v", err)
	}

	// Read response — either echo or work update.
	var received atomic.Int32
	go func() {
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			if n > 0 {
				received.Add(1)
			}
		}
	}()

	// Wait 6s, should receive multiple work updates.
	time.Sleep(6 * time.Second)
	count := received.Load()
	t.Logf("received %d messages after tunnel flap over 6s", count)
	if count < 2 {
		t.Errorf("expected at least 2 messages (work updates), got %d — session likely died", count)
	}
}

