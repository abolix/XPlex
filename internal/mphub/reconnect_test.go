package mphub_test

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"xrayrunner/internal/mpframe"
	"xrayrunner/internal/mphub"
	"xrayrunner/internal/mppool"
	"xrayrunner/internal/testutil"
)

// fakeXrayDialer returns a DialFunc that connects directly to the
// addr pointed at by mpAddr (so tests can swap the target mid-run).
func fakeXrayDialer(t *testing.T, mpAddr *string) mppool.DialFunc {
	return func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", *mpAddr)
	}
}

// TestHub_KillsSessionsWhenPoolGoesDead spins up a pool against a
// closed port (no tunnel ever succeeds), registers a session, and
// verifies the liveness loop closes the session after the grace
// period. This is the regression test for "browser hangs forever
// when mp-server dies".
func TestHub_KillsSessionsWhenPoolGoesDead(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	deadAddr := "127.0.0.1:1" // closed port
	mpAddrPtr := &deadAddr

	pool := mppool.New(ctx, mppool.Config{Codec: testutil.TestCodec(t),
		Dialers:          []mppool.DialFunc{fakeXrayDialer(t, mpAddrPtr)},
		ReconnectBackoff: 500 * time.Millisecond,
	})
	t.Cleanup(pool.Close)
	hub := mphub.New(ctx, pool, nil)
	t.Cleanup(hub.Close)

	var sid mpframe.SessionID
	sid[0] = 0xab
	sess := mphub.NewSession(hub, sid, mphub.SessionConfig{StartRx: 1})
	if !hub.Register(sess) {
		t.Fatal("register")
	}

	// killAfter is 5s; allow extra slack for slow CI.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-sess.Done():
			return
		case <-time.After(200 * time.Millisecond):
		}
	}
	t.Fatal("session was not killed by liveness loop within 10s")
}

// TestHub_PoolRecoversAfterServerRestart proves the pool reconnects
// after the upstream comes back. We swap the dialer's target mid-test
// to simulate "server restarted on a new port" (which is what happens
// during quick restart on Windows due to TIME_WAIT — and is also the
// strictest thing to verify).
func TestHub_PoolRecoversAfterServerRestart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	addr1, stop1 := startToyMPServer(t)
	mpAddr := addr1

	pool := mppool.New(ctx, mppool.Config{Codec: testutil.TestCodec(t),
		Dialers:          []mppool.DialFunc{fakeXrayDialer(t, &mpAddr)},
		ReconnectBackoff: 500 * time.Millisecond,
	})
	t.Cleanup(pool.Close)
	hub := mphub.New(ctx, pool, nil)
	t.Cleanup(hub.Close)

	waitTunnelCount(t, pool, 1, 2*time.Second)

	// Server goes down.
	stop1()
	waitTunnelCount(t, pool, 0, 5*time.Second)

	// New server comes up at a different port; swap the dialer target.
	addr2, stop2 := startToyMPServer(t)
	t.Cleanup(stop2)
	mpAddr = addr2

	waitTunnelCount(t, pool, 1, 25*time.Second)
}

func waitTunnelCount(t *testing.T, pool *mppool.Pool, want int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if pool.LiveCount() == want {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("LiveCount=%d, wanted %d after %v", pool.LiveCount(), want, timeout)
}

// startToyMPServer accepts TCP and reads frames forever, replying
// HelloAck (success) to any HELLO. Returns the addr + a stop func
// that fully closes everything (listener + in-flight conns).
func startToyMPServer(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	var (
		mu    sync.Mutex
		conns = make(map[net.Conn]struct{})
		wg    sync.WaitGroup
	)

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns[c] = struct{}{}
			mu.Unlock()

			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				defer c.Close()
				defer func() {
					mu.Lock()
					delete(conns, c)
					mu.Unlock()
				}()
				for {
					f, err := mpframe.Read(c)
					if err != nil {
						return
					}
					if f.Type == mpframe.TypeHello {
						_ = mpframe.Write(c, mpframe.Frame{
							Type:    mpframe.TypeHelloAck,
							Session: f.Session,
						})
					}
				}
			}(c)
		}
	}()

	stopper := func() {
		ln.Close()
		mu.Lock()
		for c := range conns {
			_ = c.Close()
		}
		mu.Unlock()
		wg.Wait()
	}
	return ln.Addr().String(), stopper
}
