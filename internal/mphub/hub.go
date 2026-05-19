// Package mphub implements the session demux that sits on top of an
// mppool.Pool.
//
// Multiple logical sessions (one per SOCKS5 client connection on the
// front, or one per upstream-target dial on the server) share the same
// long-lived tunnel pool. Each session has a 16-byte ID. When a frame
// arrives on the pool, the hub looks up the session by ID and feeds
// the frame to it. When a session wants to send, it asks the hub to
// broadcast through the pool.
package mphub

import (
	"context"
	"fmt"
	"sync"

	"xrayrunner/internal/mpdedup"
	"xrayrunner/internal/mpframe"
	"xrayrunner/internal/mppool"
)

// Hub demultiplexes frames from a shared pool to per-session inboxes.
type Hub struct {
	pool *mppool.Pool

	mu       sync.RWMutex
	sessions map[mpframe.SessionID]*Session

	// onUnknown is called when a frame arrives for a session ID not
	// in the registry. The server uses it to spawn a new session for
	// inbound HELLOs; the client returns false to drop.
	onUnknown func(f mpframe.Frame) bool

	cancel context.CancelFunc
	done   chan struct{}
}

// New returns a Hub that runs its dispatch loop until ctx is cancelled
// or pool.Inbound is closed.
//
// onUnknown handles frames whose session ID is not yet registered. On
// the server side this is where a new HELLO is detected and a new
// session goroutine is spawned. Returning false drops the frame.
func New(parent context.Context, pool *mppool.Pool, onUnknown func(f mpframe.Frame) bool) *Hub {
	ctx, cancel := context.WithCancel(parent)
	h := &Hub{
		pool:      pool,
		sessions:  make(map[mpframe.SessionID]*Session),
		onUnknown: onUnknown,
		cancel:    cancel,
		done:      make(chan struct{}),
	}
	go h.dispatchLoop(ctx)
	return h
}

// Close stops the dispatch loop. The pool is NOT closed (the caller
// owns it).
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

// Register attaches s to the hub under its ID. Returns false if the ID
// is already registered.
func (h *Hub) Register(s *Session) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, exists := h.sessions[s.id]; exists {
		return false
	}
	h.sessions[s.id] = s
	return true
}

// Unregister removes s from the hub. Late-arriving frames will be
// passed to onUnknown.
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

// Broadcast sends f through every live tunnel in the pool. Returns
// the number that accepted it.
func (h *Hub) Broadcast(f mpframe.Frame) int {
	return h.pool.Broadcast(f)
}

func (h *Hub) dispatchLoop(ctx context.Context) {
	defer close(h.done)
	in := h.pool.Inbound()
	for {
		select {
		case <-ctx.Done():
			return
		case f, ok := <-in:
			if !ok {
				return
			}
			h.deliver(f)
		}
	}
}

func (h *Hub) deliver(f mpframe.Frame) {
	h.mu.RLock()
	s := h.sessions[f.Session]
	h.mu.RUnlock()
	if s != nil {
		s.feed(f)
		return
	}
	if h.onUnknown != nil {
		if h.onUnknown(f) {
			// onUnknown handled it (registered a new session). Re-drop:
			// the frame may now route to that new session if the
			// registration completed before we returned.
			return
		}
	}
	// Otherwise drop: late frame for a closed/unknown session.
}

// Session is the per-flow state. It owns a dedup buffer for incoming
// frames and a monotonic seq counter for outgoing.
type Session struct {
	id  mpframe.SessionID
	hub *Hub

	dedup *mpdedup.Buffer

	mu      sync.Mutex
	seqOut  uint64
	closed  bool
	inboxCh chan mpframe.Frame
	doneCh  chan struct{}
}

// SessionConfig controls a session's resources.
type SessionConfig struct {
	StartRx         uint64 // first inbound seqno expected (1 for fresh sessions)
	DedupCap        int    // out-of-order backlog cap
	InboxBufferSize int    // pending-to-process frames
}

// NewSession creates a session bound to hub. The caller is responsible
// for hub.Register'ing it.
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
		id:      id,
		hub:     hub,
		dedup:   mpdedup.New(cfg.StartRx, cfg.DedupCap),
		inboxCh: make(chan mpframe.Frame, cfg.InboxBufferSize),
		doneCh:  make(chan struct{}),
	}
}

// ID returns the session ID.
func (s *Session) ID() mpframe.SessionID { return s.id }

// Done is closed when the session is shut down.
func (s *Session) Done() <-chan struct{} { return s.doneCh }

// Inbox is the channel of frames addressed to this session, in arrival
// order (NOT delivery order — the consumer must dedup using
// DeliverData).
func (s *Session) Inbox() <-chan mpframe.Frame { return s.inboxCh }

// SendData wraps payload as a DATA frame and broadcasts it through the
// hub's pool. Returns the assigned seqno.
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
	return seq, s.hub.Broadcast(f)
}

// SendControl broadcasts a non-data frame (HELLO, HELLO_ACK, CLOSE).
// These do not consume seqno space — they're tunnel-level signaling.
func (s *Session) SendControl(typ byte, payload []byte) int {
	f := mpframe.Frame{
		Type:    typ,
		Session: s.id,
		Seq:     0,
		Payload: payload,
	}
	return s.hub.Broadcast(f)
}

// DeliverData feeds a DATA frame into the dedup buffer and returns
// any newly-deliverable payloads (in order).
func (s *Session) DeliverData(f mpframe.Frame) ([][]byte, error) {
	return s.dedup.Push(f.Seq, f.Payload)
}

// Close marks the session closed and signals waiters. Idempotent.
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

// feed pushes f onto the inbox; non-blocking on a full buffer (drops
// the oldest by closing the inbox conservatively isn't quite right, so
// we just drop the new frame and rely on dedup retransmission via
// other tunnels).
func (s *Session) feed(f mpframe.Frame) {
	select {
	case s.inboxCh <- f:
	case <-s.doneCh:
	default:
		// Inbox full. Frame dropped; under multipath this is fine
		// because dedup will pick it up via another tunnel — but in
		// practice should never happen with default buffer size.
		fmt.Printf("session %x: inbox full, dropping frame\n", s.id[:])
	}
}
