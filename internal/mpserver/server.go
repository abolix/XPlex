// Package mpserver is the destination side of the multipath proxy.
//
// It accepts incoming TCP connections (each is one tunnel from a
// client) and feeds them into a shared mppool / mphub. When a HELLO
// arrives for an unknown session ID, the server dials the requested
// destination and starts a session goroutine that pumps bytes
// between the destination and the hub.
package mpserver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"xplex/internal/mpcrypto"
	"xplex/internal/mpframe"
	"xplex/internal/mphub"
	"xplex/internal/mppool"
)

// Config controls the server.
type Config struct {
	ListenAddr     string
	WriteChunkSize int
	DialTimeout    time.Duration
	// Codec encrypts/decrypts every wire frame. Required.
	Codec *mpcrypto.Codec
}

// Server runs the destination side of the multipath proxy.
type Server struct {
	cfg Config

	mu     sync.Mutex
	pool   *mppool.Pool
	hub    *mphub.Hub
	tombMu sync.Mutex
	tombs  map[mpframe.SessionID]time.Time
}

// New returns a Server.
func New(cfg Config) *Server {
	if cfg.WriteChunkSize == 0 {
		cfg.WriteChunkSize = 16 * 1024
	}
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = 10 * time.Second
	}
	return &Server{
		cfg:   cfg,
		tombs: make(map[mpframe.SessionID]time.Time),
	}
}

// Run blocks until ctx is cancelled or Listen fails.
func (s *Server) Run(ctx context.Context) error {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.cfg.ListenAddr, err)
	}
	defer ln.Close()
	go func() { <-ctx.Done(); ln.Close() }()

	pool := mppool.New(ctx, mppool.Config{Codec: s.cfg.Codec}) // server has no dialers
	hub := mphub.New(ctx, pool, func(f mpframe.Frame) bool {
		return s.handleUnknown(ctx, f)
	})

	s.mu.Lock()
	s.pool = pool
	s.hub = hub
	s.mu.Unlock()

	defer hub.Close()
	defer pool.Close()

	// #4: Periodic tomb sweep so stale entries don't accumulate.
	go s.tombSweepLoop(ctx)

	fmt.Printf("mp-server listening on %s\n", s.cfg.ListenAddr)

	tunIdx := 0
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept: %w", err)
		}
		tunIdx++
		pool.AddConn(fmt.Sprintf("acc-%d", tunIdx), c)
	}
}

// handleUnknown is invoked by the hub when a frame arrives for a
// session ID with no registered session. We expect HELLO; anything
// else is dropped.
func (s *Server) handleUnknown(ctx context.Context, f mpframe.Frame) bool {
	if f.Type != mpframe.TypeHello {
		return false
	}

	if s.isTomb(f.Session) {
		_ = s.sendAck(f.Session, "session closed")
		return false
	}

	dest, err := mpframe.DecodeDest(f.Payload)
	if err != nil || dest == "" {
		_ = s.sendAck(f.Session, "bad destination")
		return false
	}

	s.mu.Lock()
	hub := s.hub
	s.mu.Unlock()

	sess := mphub.NewSession(hub, f.Session, mphub.SessionConfig{StartRx: 1})
	if !hub.Register(sess) {
		return false
	}

	go s.runSession(ctx, sess, dest)
	return true
}

func (s *Server) runSession(ctx context.Context, sess *mphub.Session, dest string) {
	defer s.tomb(sess.ID())
	defer sess.Close()

	dialCtx, cancel := context.WithTimeout(ctx, s.cfg.DialTimeout)
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(dialCtx, "tcp", dest)
	cancel()
	if err != nil {
		fmt.Printf("session %x: dial %s failed: %v\n", func() []byte { id := sess.ID(); return id[:] }(), dest, err)
		_ = s.sendAck(sess.ID(), "dial failed")
		return
	}
	defer conn.Close()

	// TCP_NODELAY on outbound connection to destination (mining pool).
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}

	// 0-RTT: Flush any DATA frames that arrived while we were dialing.
	// The client starts sending immediately after HELLO without waiting
	// for ACK, so frames may have accumulated in the inbox.
	earlyDrained := false
drainEarly:
	for !earlyDrained {
		select {
		case fr := <-sess.Inbox():
			switch fr.Type {
			case mpframe.TypeData:
				ready, err := sess.DeliverData(fr)
				if err != nil {
					_ = s.sendAck(sess.ID(), "dedup error")
					return
				}
				for _, p := range ready {
					if _, werr := conn.Write(p); werr != nil {
						return
					}
				}
			case mpframe.TypeClose:
				return
			}
		default:
			earlyDrained = true
			break drainEarly
		}
	}

	if err := s.sendAck(sess.ID(), ""); err != nil {
		return
	}
	fmt.Printf("session %x: opened -> %s\n", func() []byte { id := sess.ID(); return id[:] }(), dest)

	// Idle timeout — must be longer than the liveness kill grace (30s)
	// so sessions survive tunnel reconnects without being reaped.
	const idleTimeout = 120 * time.Second
	activity := make(chan struct{}, 1)

	destDone := make(chan struct{})
	hubDone := make(chan struct{})
	go func() {
		s.pumpDestToHub(conn, sess, activity)
		close(destDone)
	}()
	go func() {
		s.pumpHubToDest(conn, sess, activity)
		close(hubDone)
	}()

	// Idle timeout watcher.
	idleTimer := time.NewTimer(idleTimeout)
	defer idleTimer.Stop()
	go func() {
		for {
			select {
			case <-destDone:
				return
			case <-hubDone:
				return
			case _, ok := <-activity:
				if !ok {
					return
				}
				if !idleTimer.Stop() {
					select {
					case <-idleTimer.C:
					default:
					}
				}
				idleTimer.Reset(idleTimeout)
			}
		}
	}()

	// Half-close.
	select {
	case <-destDone:
		sess.SendControl(mpframe.TypeClose, nil)
		select {
		case <-hubDone:
		case <-time.After(5 * time.Second):
		}
	case <-hubDone:
		sess.SendControl(mpframe.TypeClose, nil)
		select {
		case <-destDone:
		case <-time.After(2 * time.Second):
		}
	case <-idleTimer.C:
		fmt.Printf("session %x: idle timeout\n", func() []byte { id := sess.ID(); return id[:] }())
	}
	fmt.Printf("session %x: closed\n", func() []byte { id := sess.ID(); return id[:] }())
}

func (s *Server) pumpDestToHub(dest net.Conn, sess *mphub.Session, activity chan<- struct{}) {
	buf := make([]byte, s.cfg.WriteChunkSize)
	for {
		n, err := dest.Read(buf)
		if n > 0 {
			select {
			case activity <- struct{}{}:
			default:
			}
			payload := make([]byte, n)
			copy(payload, buf[:n])
			if _, sent := sess.SendData(payload); sent == 0 {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func (s *Server) pumpHubToDest(dest net.Conn, sess *mphub.Session, activity chan<- struct{}) {
	for {
		select {
		case <-sess.Done():
			return
		case fr, ok := <-sess.Inbox():
			if !ok {
				return
			}
			switch fr.Type {
			case mpframe.TypeData:
				select {
				case activity <- struct{}{}:
				default:
				}
				ready, err := sess.DeliverData(fr)
				if err != nil {
					return
				}
				for _, p := range ready {
					if _, werr := dest.Write(p); werr != nil {
						return
					}
				}
			case mpframe.TypeClose:
				return
			}
		}
	}
}

func (s *Server) sendAck(id mpframe.SessionID, errMsg string) error {
	s.mu.Lock()
	hub := s.hub
	s.mu.Unlock()
	if hub == nil {
		return errors.New("hub not ready")
	}
	f := mpframe.Frame{
		Type:    mpframe.TypeHelloAck,
		Session: id,
	}
	if errMsg != "" {
		f.Payload = []byte(errMsg)
	}
	if hub.BroadcastAlways(f) == 0 {
		return errors.New("no live tunnels")
	}
	return nil
}

const tombTTL = 30 * time.Second

// tombSweepLoop periodically cleans expired entries from the tomb map
// so it doesn't grow unbounded when traffic stops.
func (s *Server) tombSweepLoop(ctx context.Context) {
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.tombMu.Lock()
			for k, ts := range s.tombs {
				if time.Since(ts) > tombTTL {
					delete(s.tombs, k)
				}
			}
			s.tombMu.Unlock()
		}
	}
}

func (s *Server) tomb(id mpframe.SessionID) {
	s.tombMu.Lock()
	s.tombs[id] = time.Now()
	for k, t := range s.tombs {
		if time.Since(t) > tombTTL {
			delete(s.tombs, k)
		}
	}
	s.tombMu.Unlock()
}

func (s *Server) isTomb(id mpframe.SessionID) bool {
	s.tombMu.Lock()
	defer s.tombMu.Unlock()
	t, ok := s.tombs[id]
	if !ok {
		return false
	}
	if time.Since(t) > tombTTL {
		delete(s.tombs, id)
		return false
	}
	return true
}

