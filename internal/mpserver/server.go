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

	"xrayrunner/internal/mpcrypto"
	"xrayrunner/internal/mpframe"
	"xrayrunner/internal/mphub"
	"xrayrunner/internal/mppool"
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

	if err := s.sendAck(sess.ID(), ""); err != nil {
		return
	}
	fmt.Printf("session %x: opened -> %s\n", func() []byte { id := sess.ID(); return id[:] }(), dest)

	pumpDone := make(chan struct{}, 2)
	go func() {
		s.pumpDestToHub(conn, sess)
		pumpDone <- struct{}{}
	}()
	go func() {
		s.pumpHubToDest(conn, sess)
		pumpDone <- struct{}{}
	}()
	<-pumpDone

	sess.SendControl(mpframe.TypeClose, nil)
	select {
	case <-pumpDone:
	case <-time.After(200 * time.Millisecond):
	}
	fmt.Printf("session %x: closed\n", func() []byte { id := sess.ID(); return id[:] }())
}

func (s *Server) pumpDestToHub(dest net.Conn, sess *mphub.Session) {
	buf := make([]byte, s.cfg.WriteChunkSize)
	for {
		n, err := dest.Read(buf)
		if n > 0 {
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

func (s *Server) pumpHubToDest(dest net.Conn, sess *mphub.Session) {
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
	if hub.Broadcast(f) == 0 {
		return errors.New("no live tunnels")
	}
	return nil
}

const tombTTL = 30 * time.Second

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
