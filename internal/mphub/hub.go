// Package mphub demultiplexes pool inbound frames to per-session
// inboxes. It also tracks per-tunnel "win counts" — how often each
// tunnel delivered a (session, seq) frame first — and exposes that
// data so a controller can re-classify tunnels as Active or Shadow.
package mphub

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"xplex/internal/mpdedup"
	"xplex/internal/mpframe"
	"xplex/internal/mppool"
)

// Hub demultiplexes frames from a shared pool to per-session inboxes.
type Hub struct {
	pool *mppool.Pool

	mu       sync.RWMutex
	sessions map[mpframe.SessionID]*Session

	onUnknown func(f mpframe.Frame) bool

	// Win-tracking. seenKey is a (session, seq) tuple; the map records
	// the first-arriving tunnel for each key. Stays bounded because we
	// only retain winning entries for a short window.
	winMu      sync.Mutex
	winCount   map[*mppool.Tunnel]int64 // total wins by tunnel
	frameCount int64                    // total winning frames
	seen       map[seenKey]struct{}     // (session, seq) keys we've already credited
	// We use a ring of seen-keys so the map doesn't grow unbounded.
	seenRing []seenKey
	seenIdx  int

	cancel context.CancelFunc
	done   chan struct{}
}

type seenKey struct {
	id  mpframe.SessionID
	seq uint64
}

const seenRingSize = 8192 // ~remembers last 8k keys; plenty for win tracking

// New returns a Hub that runs its dispatch loop until ctx is cancelled
// or pool.Inbound is closed.
func New(parent context.Context, pool *mppool.Pool, onUnknown func(f mpframe.Frame) bool) *Hub {
	ctx, cancel := context.WithCancel(parent)
	h := &Hub{
		pool:      pool,
		sessions:  make(map[mpframe.SessionID]*Session),
		onUnknown: onUnknown,
		winCount:  make(map[*mppool.Tunnel]int64),
		seen:      make(map[seenKey]struct{}, seenRingSize),
		seenRing:  make([]seenKey, seenRingSize),
		cancel:    cancel,
		done:      make(chan struct{}),
	}
	go h.dispatchLoop(ctx)
	go h.livenessLoop(ctx)
	return h
}

// livenessLoop watches the pool's live tunnel count. If the pool stays
// at zero live tunnels for longer than the kill grace period (the
// server is down or every xray died), every open session is closed so
// the application layer sees EOF and can reconnect.
//
// As soon as a tunnel comes back up, sessions can resume opening from
// scratch. We don't try to migrate existing sessions across server
// restarts because the server's session table is gone.
func (h *Hub) livenessLoop(ctx context.Context) {
	const (
		checkInterval = 1 * time.Second
		killAfter     = 30 * time.Second // longer grace for mining sessions to survive reconnects
	)
	t := time.NewTicker(checkInterval)
	defer t.Stop()
	deadSince := time.Time{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if h.pool.LiveCount() > 0 {
				deadSince = time.Time{}
				continue
			}
			if deadSince.IsZero() {
				deadSince = time.Now()
				continue
			}
			if time.Since(deadSince) >= killAfter {
				h.killAllSessions("no live tunnels")
				deadSince = time.Time{} // wait for tunnels to recover
			}
		}
	}
}

// killAllSessions closes every registered session. Called when the
// pool has been completely dead long enough that we've decided to
// surface the failure to applications.
func (h *Hub) killAllSessions(reason string) {
	h.mu.Lock()
	victims := make([]*Session, 0, len(h.sessions))
	for _, s := range h.sessions {
		victims = append(victims, s)
	}
	h.mu.Unlock()
	for _, s := range victims {
		fmt.Printf("session %x: killed (%s)\n", s.id[:], reason)
		s.markClosed()
	}
}

// Close stops the dispatch loop. Pool ownership is unchanged.
func (h *Hub) Close() {
	h.cancel()
	<-h.done
	h.mu.Lock()
	for _, s := range h.sessions {
		s.markClosed()
	}
	h.sessions = nil
	h.mu.Unlock()
}

// Pool returns the underlying tunnel pool.
func (h *Hub) Pool() *mppool.Pool { return h.pool }

// TestFeed injects a frame directly into the hub's dispatch path.
// Only for use in tests.
func (h *Hub) TestFeed(f mpframe.Frame) {
	h.deliver(mppool.FrameWithSrc{Frame: f, Src: nil})
}

// Register attaches s to the hub.
func (h *Hub) Register(s *Session) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, exists := h.sessions[s.id]; exists {
		return false
	}
	h.sessions[s.id] = s
	return true
}

// Unregister removes s from the hub.
func (h *Hub) Unregister(s *Session) {
	h.mu.Lock()
	if cur := h.sessions[s.id]; cur == s {
		delete(h.sessions, s.id)
	}
	h.mu.Unlock()
}

// Get fetches the session with the given ID, if any.
func (h *Hub) Get(id mpframe.SessionID) *Session {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.sessions[id]
}

// Broadcast sends f through every Active tunnel.
func (h *Hub) Broadcast(f mpframe.Frame) int { return h.pool.Broadcast(f) }

// BroadcastAlways sends f through every live tunnel ignoring state.
// Used for control frames (HELLO/ACK/CLOSE).
func (h *Hub) BroadcastAlways(f mpframe.Frame) int { return h.pool.BroadcastAlways(f) }

// WinStats reports total winning frames seen and per-tunnel wins
// since the last Reset. The returned map is a copy.
func (h *Hub) WinStats() (totalFrames int64, perTunnel map[*mppool.Tunnel]int64) {
	h.winMu.Lock()
	defer h.winMu.Unlock()
	cp := make(map[*mppool.Tunnel]int64, len(h.winCount))
	for k, v := range h.winCount {
		cp[k] = v
	}
	return h.frameCount, cp
}

// ResetWinStats clears all win counters. Called by the controller at
// the end of each evaluation window. Also purges entries for dead
// tunnels to prevent slow memory leaks (#3 fix).
func (h *Hub) ResetWinStats() {
	h.winMu.Lock()
	h.winCount = make(map[*mppool.Tunnel]int64)
	h.frameCount = 0
	for i := range h.seenRing {
		h.seenRing[i] = seenKey{}
	}
	h.seenIdx = 0
	h.seen = make(map[seenKey]struct{}, seenRingSize)
	h.winMu.Unlock()
}

func (h *Hub) dispatchLoop(ctx context.Context) {
	defer close(h.done)
	in := h.pool.InboundWithSrc()
	for {
		select {
		case <-ctx.Done():
			return
		case fs, ok := <-in:
			if !ok {
				return
			}
			h.deliver(fs)
		}
	}
}

func (h *Hub) deliver(fs mppool.FrameWithSrc) {
	// Credit the source tunnel for a "win" if this is the first time
	// we've seen this (session, seq) key. Only DATA frames count —
	// HELLO/ACK/CLOSE are control and don't reflect duplication
	// goodness.
	if fs.Frame.Type == mpframe.TypeData && fs.Src != nil {
		h.creditWin(fs.Frame.Session, fs.Frame.Seq, fs.Src)
	}

	h.mu.RLock()
	s := h.sessions[fs.Frame.Session]
	h.mu.RUnlock()
	if s != nil {
		s.feed(fs.Frame)
		return
	}
	if h.onUnknown != nil {
		_ = h.onUnknown(fs.Frame)
	}
}

func (h *Hub) creditWin(id mpframe.SessionID, seq uint64, t *mppool.Tunnel) {
	k := seenKey{id: id, seq: seq}
	h.winMu.Lock()
	defer h.winMu.Unlock()
	if _, dup := h.seen[k]; dup {
		return
	}
	// Evict the slot we're about to overwrite.
	old := h.seenRing[h.seenIdx]
	if old != (seenKey{}) {
		delete(h.seen, old)
	}
	h.seenRing[h.seenIdx] = k
	h.seenIdx = (h.seenIdx + 1) % len(h.seenRing)
	h.seen[k] = struct{}{}
	h.winCount[t]++
	h.frameCount++
}

// Session is the per-flow state.
type Session struct {
	id  mpframe.SessionID
	hub *Hub

	dedup *mpdedup.Buffer

	mu      sync.Mutex
	seqOut  uint64
	closed  bool
	inboxCh chan mpframe.Frame
	doneCh  chan struct{}

	// Pre-dedup filter: tracks which seq numbers have already been
	// enqueued into inboxCh, so duplicate copies from other tunnels
	// are dropped before they consume inbox slots.
	feedMu   sync.Mutex
	feedSeen map[uint64]struct{}

	bytesSent atomic.Int64
	bytesRecv atomic.Int64
}

// SessionConfig controls a session's resources.
type SessionConfig struct {
	StartRx         uint64
	DedupCap        int
	InboxBufferSize int
}

// NewSession creates a session bound to hub.
func NewSession(hub *Hub, id mpframe.SessionID, cfg SessionConfig) *Session {
	if cfg.StartRx == 0 {
		cfg.StartRx = 1
	}
	if cfg.DedupCap <= 0 {
		cfg.DedupCap = 4096
	}
	if cfg.InboxBufferSize <= 0 {
		cfg.InboxBufferSize = 256
	}
	return &Session{
		id:       id,
		hub:      hub,
		dedup:    mpdedup.New(cfg.StartRx, cfg.DedupCap),
		inboxCh:  make(chan mpframe.Frame, cfg.InboxBufferSize),
		doneCh:   make(chan struct{}),
		feedSeen: make(map[uint64]struct{}, 256),
	}
}

func (s *Session) ID() mpframe.SessionID       { return s.id }
func (s *Session) Done() <-chan struct{}       { return s.doneCh }
func (s *Session) Inbox() <-chan mpframe.Frame { return s.inboxCh }

// SendData broadcasts a DATA frame across Active tunnels. If no tunnel
// accepts the frame (all down), retries with backoff until at least one
// tunnel delivers it or the session is closed. This prevents data loss
// during brief tunnel flaps.
func (s *Session) SendData(payload []byte) (uint64, int) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return 0, 0
	}
	s.seqOut++
	seq := s.seqOut
	s.mu.Unlock()

	f := mpframe.Frame{
		Type:    mpframe.TypeData,
		Session: s.id,
		Seq:     seq,
		Payload: payload,
	}
	s.bytesSent.Add(int64(len(payload)))

	// Retry loop: keep trying until at least one tunnel accepts the frame.
	// Wait up to 30s to survive tunnel reconnects without losing data.
	const maxRetries = 300 // 300 * 100ms = 30s max wait
	for attempt := 0; ; attempt++ {
		sent := s.hub.Broadcast(f)
		if sent > 0 {
			return seq, sent
		}
		// No tunnels available. Wait briefly and retry.
		if attempt >= maxRetries {
			return seq, 0 // give up after 5s
		}
		select {
		case <-s.doneCh:
			return seq, 0 // session closed
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// SendControl broadcasts a control frame (HELLO/HELLO_ACK/CLOSE)
// through all tunnels, including Shadows. These signals must reach
// the peer regardless of duplication policy.
func (s *Session) SendControl(typ byte, payload []byte) int {
	f := mpframe.Frame{
		Type:    typ,
		Session: s.id,
		Seq:     0,
		Payload: payload,
	}
	return s.hub.BroadcastAlways(f)
}

// DeliverData feeds a DATA frame into the dedup buffer.
func (s *Session) DeliverData(f mpframe.Frame) ([][]byte, error) {
	out, err := s.dedup.Push(f.Seq, f.Payload)
	if err == nil {
		for _, p := range out {
			s.bytesRecv.Add(int64(len(p)))
		}
	}
	return out, err
}

// Close marks the session closed.
func (s *Session) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	close(s.doneCh)
	s.mu.Unlock()
	s.hub.Unregister(s)
}

func (s *Session) markClosed() {
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		close(s.doneCh)
	}
	s.mu.Unlock()
}

func (s *Session) feed(f mpframe.Frame) {
	// For DATA frames: deduplicate at the inbox gate. Only the first
	// copy of a given seq number enters the channel. Duplicates from
	// other tunnels are silently dropped here — never consuming inbox
	// capacity. This is the real fix for "inbox full" under multipath.
	if f.Type == mpframe.TypeData && f.Seq > 0 {
		s.feedMu.Lock()
		if _, dup := s.feedSeen[f.Seq]; dup {
			s.feedMu.Unlock()
			return // duplicate — drop it
		}
		s.feedSeen[f.Seq] = struct{}{}
		// Bound the map: remove entries far below current seq.
		// Keep a window of 512 to handle mild reordering.
		if len(s.feedSeen) > 1024 {
			cutoff := f.Seq - 512
			for k := range s.feedSeen {
				if k < cutoff {
					delete(s.feedSeen, k)
				}
			}
		}
		s.feedMu.Unlock()
	}

	// Enqueue. Control frames (HELLO_ACK, CLOSE) always go through.
	select {
	case s.inboxCh <- f:
	case <-s.doneCh:
	}
}

