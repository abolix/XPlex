// Package mppool maintains a long-lived set of multipath tunnels.
//
// The pool fans frames in/out across all live tunnels:
//   - Outbound: Broadcast(frame) sends through every live tunnel.
//   - Inbound: Inbound() yields frames from any tunnel, in arrival
//     order across all of them.
//
// Two ways tunnels enter the pool:
//   - "slots" maintained by dialers (client side): each slot is a
//     goroutine that re-dials when its tunnel dies.
//   - AddConn(conn): the server uses this for tunnels that arrived via
//     Accept, with no re-dial behavior.
package mppool

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"xrayrunner/internal/mpframe"
)

// DialFunc opens one tunnel. It must perform whatever transport
// handshake is needed (e.g. SOCKS5 -> mp-server) and return a conn
// ready to carry mpframe Frames.
type DialFunc func(ctx context.Context) (net.Conn, error)

// Tunnel wraps one underlying conn with a writer goroutine that
// serializes outbound frames.
type Tunnel struct {
	name      string
	conn      net.Conn
	sendCh    chan mpframe.Frame
	done      chan struct{}
	closeOnce sync.Once
}

// Done is closed when the tunnel has been torn down.
func (t *Tunnel) Done() <-chan struct{} { return t.done }

// Send queues f. Returns false if the tunnel is dead. Drops f and
// closes the tunnel if its send buffer is full (i.e. wedged).
func (t *Tunnel) Send(f mpframe.Frame) bool {
	select {
	case <-t.done:
		return false
	default:
	}
	select {
	case <-t.done:
		return false
	case t.sendCh <- f:
		return true
	default:
		t.Close()
		return false
	}
}

// Close terminates the tunnel. Idempotent.
func (t *Tunnel) Close() {
	t.closeOnce.Do(func() {
		close(t.done)
		_ = t.conn.Close()
	})
}

const sendBufferDepth = 1024

// Pool fans frames in/out across multiple tunnels.
type Pool struct {
	dialFuncs        []DialFunc
	dialerNames      []string
	reconnectBackoff time.Duration

	mu         sync.RWMutex
	slotted    []*Tunnel            // by-slot for dialer-driven tunnels (client side)
	accepted   map[*Tunnel]struct{} // for tunnels added via AddConn (server)
	closed     bool
	totalAdded int

	inbound chan mpframe.Frame

	wg     sync.WaitGroup
	ctx    context.Context
	cancel context.CancelFunc

	totalSent  atomic.Int64
	totalRecvd atomic.Int64
}

// Config controls pool startup.
type Config struct {
	// Dialers may be empty (server side). When non-empty, the pool
	// keeps one tunnel per dialer alive at all times.
	Dialers []DialFunc
	// Names are cosmetic labels for log lines; len must match Dialers.
	Names []string
	// ReconnectBackoff is the wait between failed re-dials per slot.
	ReconnectBackoff time.Duration
}

// New starts the pool. For dialer-driven slots, the first round of
// dials happens in goroutines — the call returns immediately.
func New(parent context.Context, cfg Config) *Pool {
	if cfg.ReconnectBackoff == 0 {
		cfg.ReconnectBackoff = 2 * time.Second
	}
	if len(cfg.Names) == 0 {
		cfg.Names = make([]string, len(cfg.Dialers))
		for i := range cfg.Names {
			cfg.Names[i] = fmt.Sprintf("d%d", i)
		}
	}
	ctx, cancel := context.WithCancel(parent)
	p := &Pool{
		dialFuncs:        cfg.Dialers,
		dialerNames:      cfg.Names,
		reconnectBackoff: cfg.ReconnectBackoff,
		slotted:          make([]*Tunnel, len(cfg.Dialers)),
		accepted:         make(map[*Tunnel]struct{}),
		inbound:          make(chan mpframe.Frame, 4096),
		ctx:              ctx,
		cancel:           cancel,
	}
	for i := range cfg.Dialers {
		p.wg.Add(1)
		go p.maintainSlot(i)
	}
	return p
}

// Inbound returns the channel of frames arriving from any tunnel.
func (p *Pool) Inbound() <-chan mpframe.Frame { return p.inbound }

// Broadcast sends f through every live tunnel.
func (p *Pool) Broadcast(f mpframe.Frame) int {
	p.mu.RLock()
	tunnels := p.snapshotLocked()
	p.mu.RUnlock()

	sent := 0
	for _, t := range tunnels {
		if t.Send(f) {
			sent++
		}
	}
	if sent > 0 {
		p.totalSent.Add(1)
	}
	return sent
}

// LiveCount returns the number of live tunnels in the pool.
func (p *Pool) LiveCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.snapshotLocked())
}

// AddConn pushes an externally-accepted conn into the pool as a new
// tunnel. The pool reads/writes mpframe.Frames on it directly. When
// the conn dies, the tunnel is removed from the live set; nothing
// re-dials it (this is the server-side path).
func (p *Pool) AddConn(name string, conn net.Conn) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		_ = conn.Close()
		return
	}
	t := &Tunnel{
		name:   name,
		conn:   conn,
		sendCh: make(chan mpframe.Frame, sendBufferDepth),
		done:   make(chan struct{}),
	}
	p.accepted[t] = struct{}{}
	p.totalAdded++
	p.mu.Unlock()

	fmt.Printf("pool: tunnel %s up (accepted)\n", name)
	go func() {
		p.runTunnel(t, name)
		p.mu.Lock()
		delete(p.accepted, t)
		p.mu.Unlock()
		fmt.Printf("pool: tunnel %s down (accepted)\n", name)
	}()
}

// Close shuts the pool down and waits for slot maintainers.
func (p *Pool) Close() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	p.cancel()
	tunnels := p.snapshotLocked()
	p.mu.Unlock()

	for _, t := range tunnels {
		t.Close()
	}
	p.wg.Wait()
	close(p.inbound)
}

// snapshotLocked returns the live tunnel set; caller holds p.mu.
func (p *Pool) snapshotLocked() []*Tunnel {
	out := make([]*Tunnel, 0, len(p.slotted)+len(p.accepted))
	for _, t := range p.slotted {
		if t != nil {
			out = append(out, t)
		}
	}
	for t := range p.accepted {
		out = append(out, t)
	}
	return out
}

// maintainSlot keeps slot i populated with a live tunnel, re-dialing
// when one dies. Used on the client side.
func (p *Pool) maintainSlot(i int) {
	defer p.wg.Done()
	dial := p.dialFuncs[i]
	name := p.dialerNames[i]

	for {
		if p.ctx.Err() != nil {
			return
		}
		dialCtx, cancel := context.WithTimeout(p.ctx, 10*time.Second)
		conn, err := dial(dialCtx)
		cancel()
		if err != nil {
			fmt.Printf("pool slot %s: dial failed: %v (retry in %v)\n",
				name, err, p.reconnectBackoff)
			select {
			case <-p.ctx.Done():
				return
			case <-time.After(p.reconnectBackoff):
				continue
			}
		}
		t := &Tunnel{
			name:   name,
			conn:   conn,
			sendCh: make(chan mpframe.Frame, sendBufferDepth),
			done:   make(chan struct{}),
		}
		p.mu.Lock()
		p.slotted[i] = t
		p.mu.Unlock()

		fmt.Printf("pool slot %s: tunnel up\n", name)
		p.runTunnel(t, name)

		p.mu.Lock()
		if p.slotted[i] == t {
			p.slotted[i] = nil
		}
		p.mu.Unlock()
		fmt.Printf("pool slot %s: tunnel down\n", name)

		select {
		case <-p.ctx.Done():
			return
		case <-time.After(p.reconnectBackoff):
		}
	}
}

// runTunnel runs reader+writer goroutines and blocks until both exit.
func (p *Pool) runTunnel(t *Tunnel, name string) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for {
			select {
			case <-t.done:
				return
			case f := <-t.sendCh:
				if err := mpframe.Write(t.conn, f); err != nil {
					t.Close()
					return
				}
			}
		}
	}()

	go func() {
		defer wg.Done()
		for {
			f, err := mpframe.Read(t.conn)
			if err != nil {
				t.Close()
				return
			}
			p.totalRecvd.Add(1)
			select {
			case p.inbound <- f:
			case <-t.done:
				return
			case <-p.ctx.Done():
				return
			}
		}
	}()

	wg.Wait()
}
