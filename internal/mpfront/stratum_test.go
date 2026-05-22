package mpfront_test

// Realistic Stratum mining simulation tests.
//
// These simulate actual mining pool behavior to verify long-lived
// sessions survive tunnel disruptions without losing shares or
// disconnecting.
//
// Stratum V1: JSON-RPC over TCP, newline-delimited.
//   - Pool sends mining.notify every 30s (new block template)
//   - Miner sends mining.submit every ~10s (share found)
//   - Connection must stay alive for hours
//
// Stratum V2: Binary framing (6-byte header + payload).
//   - Pool sends NewMiningJob messages every 30s
//   - Miner sends ShareSubmission every ~10s
//   - Noise encryption (simulated with raw binary frames here)
//   - Connection must stay alive for hours

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
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

// --- Stratum V1 Fake Pool ---

type stratumV1Pool struct {
	ln          net.Listener
	shares      atomic.Int64
	disconnects atomic.Int64
	activeConns atomic.Int64
}

func newStratumV1Pool(t *testing.T) *stratumV1Pool {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	p := &stratumV1Pool{ln: ln}
	t.Cleanup(func() { ln.Close() })
	go p.run()
	return p
}

func (p *stratumV1Pool) Addr() string { return p.ln.Addr().String() }

func (p *stratumV1Pool) run() {
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}
		p.activeConns.Add(1)
		go p.handleConn(c)
	}
}

func (p *stratumV1Pool) handleConn(c net.Conn) {
	defer func() {
		c.Close()
		p.activeConns.Add(-1)
		p.disconnects.Add(1)
	}()

	// Send mining.notify every 2s (simulates ~30s in real life, compressed for test)
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		jobID := 0
		for {
			select {
			case <-ticker.C:
				jobID++
				notify := map[string]any{
					"id":     nil,
					"method": "mining.notify",
					"params": []any{fmt.Sprintf("job_%d", jobID), "prev_hash_abc", "coinb1", "coinb2", []string{"branch1"}, "00000002", "1d00ffff", fmt.Sprintf("%x", time.Now().Unix()), true},
				}
				data, _ := json.Marshal(notify)
				data = append(data, '\n')
				if _, err := c.Write(data); err != nil {
					return
				}
			}
		}
	}()

	// Read miner submissions (newline-delimited JSON)
	buf := make([]byte, 4096)
	var partial []byte
	for {
		_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := c.Read(buf)
		if err != nil {
			return
		}
		partial = append(partial, buf[:n]...)
		// Process complete lines
		for {
			idx := bytes.IndexByte(partial, '\n')
			if idx < 0 {
				break
			}
			line := partial[:idx]
			partial = partial[idx+1:]
			var msg map[string]any
			if json.Unmarshal(line, &msg) == nil {
				if method, ok := msg["method"].(string); ok && method == "mining.submit" {
					p.shares.Add(1)
					// Send accept response
					resp := map[string]any{"id": msg["id"], "result": true, "error": nil}
					data, _ := json.Marshal(resp)
					data = append(data, '\n')
					_, _ = c.Write(data)
				}
			}
		}
	}
}

// --- Stratum V2 Fake Pool (binary framing) ---

type stratumV2Pool struct {
	ln          net.Listener
	shares      atomic.Int64
	disconnects atomic.Int64
	activeConns atomic.Int64
}

func newStratumV2Pool(t *testing.T) *stratumV2Pool {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	p := &stratumV2Pool{ln: ln}
	t.Cleanup(func() { ln.Close() })
	go p.run()
	return p
}

func (p *stratumV2Pool) Addr() string { return p.ln.Addr().String() }

func (p *stratumV2Pool) run() {
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}
		p.activeConns.Add(1)
		go p.handleConn(c)
	}
}

// SV2 frame: [ext_type:2][msg_type:1][msg_len:3][payload...]
func sv2Write(c net.Conn, msgType byte, payload []byte) error {
	hdr := make([]byte, 6)
	binary.LittleEndian.PutUint16(hdr[0:2], 0x0000) // ext_type
	hdr[2] = msgType
	// 3-byte little-endian length
	hdr[3] = byte(len(payload))
	hdr[4] = byte(len(payload) >> 8)
	hdr[5] = byte(len(payload) >> 16)
	if _, err := c.Write(hdr); err != nil {
		return err
	}
	if _, err := c.Write(payload); err != nil {
		return err
	}
	return nil
}

func sv2Read(c net.Conn) (byte, []byte, error) {
	hdr := make([]byte, 6)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return 0, nil, err
	}
	msgType := hdr[2]
	length := int(hdr[3]) | int(hdr[4])<<8 | int(hdr[5])<<16
	if length > 1<<20 {
		return 0, nil, fmt.Errorf("frame too large: %d", length)
	}
	payload := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(c, payload); err != nil {
			return 0, nil, err
		}
	}
	return msgType, payload, nil
}

const (
	sv2MsgNewJob byte = 0x1e // NewMiningJob
	sv2MsgSubmit byte = 0x1c // SubmitSharesStandard
	sv2MsgAccept byte = 0x1d // SubmitSharesSuccess
)

func (p *stratumV2Pool) handleConn(c net.Conn) {
	defer func() {
		c.Close()
		p.activeConns.Add(-1)
		p.disconnects.Add(1)
	}()

	// Send NewMiningJob every 2s
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		jobID := uint32(0)
		for {
			select {
			case <-ticker.C:
				jobID++
				payload := make([]byte, 32) // fake job data
				binary.LittleEndian.PutUint32(payload, jobID)
				if sv2Write(c, sv2MsgNewJob, payload) != nil {
					return
				}
			}
		}
	}()

	// Read share submissions
	for {
		_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
		msgType, _, err := sv2Read(c)
		if err != nil {
			return
		}
		if msgType == sv2MsgSubmit {
			p.shares.Add(1)
			// Send accept
			_ = sv2Write(c, sv2MsgAccept, []byte{0x01})
		}
	}
}

// --- Test Infrastructure ---

func setupMPProxy(t *testing.T, ctx context.Context, tunnelCount int) (frontAddr string, pool *mppool.Pool) {
	t.Helper()
	// Start mp-server
	srvLn, _ := net.Listen("tcp", "127.0.0.1:0")
	srvAddr := srvLn.Addr().String()
	srvLn.Close()
	go func() {
		_ = mpserver.New(mpserver.Config{ListenAddr: srvAddr, Codec: testutil.TestCodec(t)}).Run(ctx)
	}()
	waitListen(t, srvAddr, 2*time.Second)

	// Build pool with direct TCP dialers
	dialers := make([]mppool.DialFunc, tunnelCount)
	names := make([]string, tunnelCount)
	for i := range dialers {
		dialers[i] = func(ctx context.Context) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", srvAddr)
		}
		names[i] = fmt.Sprintf("t%d", i)
	}

	pool = mppool.New(ctx, mppool.Config{Codec: testutil.TestCodec(t), Dialers: dialers, Names: names})
	t.Cleanup(pool.Close)
	hub := mphub.New(ctx, pool, nil)
	t.Cleanup(hub.Close)

	frontAddr = freeAddr(t)
	front := mpfront.New(hub, mpfront.Config{ListenAddr: frontAddr})
	go func() { _ = front.Run(ctx) }()
	waitListen(t, frontAddr, 2*time.Second)

	// Wait for tunnels
	dl := time.Now().Add(3 * time.Second)
	for time.Now().Before(dl) {
		if pool.LiveCount() >= tunnelCount {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	return frontAddr, pool
}

// --- THE TESTS ---

func TestStratumV1_SurvivesAggressiveTunnelFlaps(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool := newStratumV1Pool(t)
	frontAddr, tunnelPool := setupMPProxy(t, ctx, 3)

	// Connect miner to pool through our proxy.
	poolHost, poolPortStr, _ := net.SplitHostPort(pool.Addr())
	poolPort, _ := strconv.Atoi(poolPortStr)
	conn, err := socks5.Dial(frontAddr, poolHost, uint16(poolPort), 5*time.Second)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close()

	// Miner loop: send shares every 500ms for 15 seconds.
	var sharesSent atomic.Int64
	var writeErrors atomic.Int64
	minerDone := make(chan struct{})
	go func() {
		defer close(minerDone)
		shareID := 0
		for i := 0; i < 30; i++ { // 30 shares over 15s
			shareID++
			submit := map[string]any{
				"id":     shareID,
				"method": "mining.submit",
				"params": []any{"worker1", fmt.Sprintf("job_%d", shareID), "00000001", fmt.Sprintf("%x", time.Now().Unix()), "nonce123"},
			}
			data, _ := json.Marshal(submit)
			data = append(data, '\n')
			_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, err := conn.Write(data); err != nil {
				writeErrors.Add(1)
				return
			}
			sharesSent.Add(1)
			time.Sleep(500 * time.Millisecond)
		}
	}()

	// Read responses in background.
	var responsesRead atomic.Int64
	go func() {
		buf := make([]byte, 4096)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			// Count newline-delimited responses
			for _, b := range buf[:n] {
				if b == '\n' {
					responsesRead.Add(1)
				}
			}
		}
	}()

	// AGGRESSIVE TUNNEL FLAPS: kill a tunnel every 3 seconds.
	// With 3 tunnels and 2s reconnect backoff, there should always
	// be at least 1 tunnel available (realistic production scenario).
	flapDone := make(chan struct{})
	go func() {
		defer close(flapDone)
		for i := 0; i < 5; i++ { // 5 flaps over 15 seconds
			time.Sleep(3 * time.Second)
			tunnels := tunnelPool.Tunnels()
			if len(tunnels) > 1 { // only kill if more than 1 alive
				tunnels[i%len(tunnels)].Close()
			}
		}
	}()

	<-minerDone
	<-flapDone
	time.Sleep(1 * time.Second) // let final responses arrive

	t.Logf("shares sent: %d, write errors: %d", sharesSent.Load(), writeErrors.Load())
	t.Logf("pool received: %d shares", pool.shares.Load())
	t.Logf("responses read: %d (includes notify + accept)", responsesRead.Load())
	t.Logf("pool disconnects: %d", pool.disconnects.Load())

	if writeErrors.Load() > 0 {
		t.Errorf("miner had %d write errors — session died during tunnel flap", writeErrors.Load())
	}
	if pool.shares.Load() < sharesSent.Load() {
		t.Errorf("pool only received %d/%d shares — data loss!", pool.shares.Load(), sharesSent.Load())
	}
	if pool.disconnects.Load() > 1 {
		t.Errorf("pool saw %d disconnects — session was interrupted", pool.disconnects.Load())
	}
}

func TestStratumV2_SurvivesAggressiveTunnelFlaps(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool := newStratumV2Pool(t)
	frontAddr, tunnelPool := setupMPProxy(t, ctx, 3)

	// Connect miner to pool through our proxy.
	poolHost, poolPortStr, _ := net.SplitHostPort(pool.Addr())
	poolPort, _ := strconv.Atoi(poolPortStr)
	conn, err := socks5.Dial(frontAddr, poolHost, uint16(poolPort), 5*time.Second)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close()

	// Miner loop: send SV2 share submissions every 500ms for 15s.
	var sharesSent atomic.Int64
	var writeErrors atomic.Int64
	minerDone := make(chan struct{})
	go func() {
		defer close(minerDone)
		for i := 0; i < 30; i++ {
			payload := make([]byte, 16) // fake share data
			binary.LittleEndian.PutUint32(payload, uint32(i+1))
			if sv2Write(conn, sv2MsgSubmit, payload) != nil {
				writeErrors.Add(1)
				return
			}
			sharesSent.Add(1)
			time.Sleep(500 * time.Millisecond)
		}
	}()

	// Read responses (job updates + share accepts).
	var messagesRead atomic.Int64
	go func() {
		for {
			_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
			_, _, err := sv2Read(conn)
			if err != nil {
				return
			}
			messagesRead.Add(1)
		}
	}()

	// AGGRESSIVE TUNNEL FLAPS.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 5; i++ {
			time.Sleep(3 * time.Second)
			tunnels := tunnelPool.Tunnels()
			if len(tunnels) > 1 {
				tunnels[i%len(tunnels)].Close()
			}
		}
	}()

	<-minerDone
	wg.Wait()
	time.Sleep(1 * time.Second)

	t.Logf("SV2 shares sent: %d, write errors: %d", sharesSent.Load(), writeErrors.Load())
	t.Logf("SV2 pool received: %d shares", pool.shares.Load())
	t.Logf("SV2 messages read: %d (jobs + accepts)", messagesRead.Load())
	t.Logf("SV2 pool disconnects: %d", pool.disconnects.Load())

	if writeErrors.Load() > 0 {
		t.Errorf("SV2 miner had %d write errors — session died", writeErrors.Load())
	}
	if pool.shares.Load() < sharesSent.Load() {
		t.Errorf("SV2 pool only received %d/%d shares — data loss!", pool.shares.Load(), sharesSent.Load())
	}
	if pool.disconnects.Load() > 1 {
		t.Errorf("SV2 pool saw %d disconnects — session interrupted", pool.disconnects.Load())
	}
}

