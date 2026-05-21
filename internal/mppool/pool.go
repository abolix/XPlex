// Package mppool maintains a long-lived set of multipath tunnels.
//
// The pool fans frames in/out across all live tunnels:
//   - Outbound: Broadcast(frame) sends through every ACTIVE tunnel.
//     Shadow tunnels do not get outbound traffic but stay open as
//     hot spares.
//   - Inbound: Inbound() yields frames from any tunnel, including
//     Shadows — that's the whole point, so we can passively measure
//     who would have won if they'd been broadcasting.
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

	"xrayrunner/internal/mpcrypto"
	"xrayrunner/internal/mpframe"
)

// DialFunc opens one tunnel.
type DialFunc func(ctx context.Context) (net.Conn, error)

// State classifies a tunnel for outbound duplication.
type State int

const (
	StateActive State = iota // sends + receives
	StateShadow              // only receives (saves outbound bandwidth)
)

func (s State) String() string {
	if s == StateActive {
		return "active"
	}
	return "shadow"
}

// Tunnel wraps one underlying conn with a writer goroutine.
type Tunnel struct {
	name string
	conn net.Conn

	state atomic.Int32 // State

	sendCh    chan mpframe.Frame
	done      chan struct{}
	closeOnce sync.Once
}

// Name returns a cosmetic identifier for logs.
func (t *Tunnel) Name() string { return t.name }

// State returns the tunnel's current State.
func (t *Tunnel) State() State { return State(t.state.Load()) }

// SetState transitions the tunnel between Active and Shadow. Idempotent.
func (t *Tunnel) SetState(s State) { t.state.Store(int32(s)) }

// Done is closed when the tunnel has been torn down.
func (t *Tunnel) Done() <-chan struct{} { return t.done }

// Send queues f. Returns false if the tunnel is dead OR not Active.
func (t *Tunnel) Send(f mpframe.Frame) bool {
	if t.State() != StateActive {
		return false
	}
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

// SendAlways is like Send but ignores the Active/Shadow gate. Used for
// control frames (HELLO/HELLO_ACK/PING) that must reach the peer
// regardless of duplication policy.
func (t *Tunnel) SendAlways(f mpframe.Frame) bool {
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
	codec            *mpcrypto.Codec

	mu       sync.RWMutex
	slotted  []*Tunnel
	accepted map[*Tunnel]struct{}
	closed   bool

	inboundWithSrc chan FrameWithSrc

	wg     sync.WaitGroup
	ctx    context.Context
	cancel context.CancelFunc

	totalSent  atomic.Int64
	totalRecvd atomic.Int64
}

// FrameWithSrc pairs an inbound frame with the tunnel that delivered it.
type FrameWithSrc struct {
	Frame mpframe.Frame
	Src   *Tunnel // may be nil if the source has been removed by the time the consumer reads
}

// Config controls pool startup.
type Config struct {
	Dialers          []DialFunc
	Names            []string
	ReconnectBackoff time.Duration
	// Codec is the AEAD codec used for every frame on every tunnel.
	// REQUIRED. Both ends of the wire must use the same key.
	Codec *mpcrypto.Codec
}

// New starts the pool.
func New(parent context.Context, cfg Config) *Pool {
	if cfg.Codec == nil {
		panic("mppool.New: Codec is required (use mpcrypto.New)")
	}
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
		codec:            cfg.Codec,
		slotted:          make([]*Tunnel, len(cfg.Dialers)),
		accepted:         make(map[*Tunnel]struct{}),
		inboundWithSrc:   make(chan FrameWithSrc, 4096),
		ctx:              ctx,
		cancel:           cancel,
	}
	for i := range cfg.Dialers {
		p.wg.Add(1)
		go p.maintainSlot(i)
	}
	return p
}

// InboundWithSrc returns frames paired with their source tunnel.
func (p *Pool) InboundWithSrc() <-chan FrameWithSrc { return p.inboundWithSrc }

// Inbound returns frames only (drops the src). Convenience for
// consumers that don't care about source attribution.
func (p *Pool) Inbound() <-chan mpframe.Frame {
	out := make(chan mpframe.Frame, cap(p.inboundWithSrc))
	go func() {
		defer close(out)
		for fs := range p.inboundWithSrc {
			out <- fs.Frame
		}
	}()
	return out
}

// Broadcast sends f through every ACTIVE tunnel. Returns the number
// of tunnels that accepted f.
func (p *Pool) Broadcast(f mpframe.Frame) int {
	tunnels := p.snapshot()
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

// BroadcastAlways sends f through every live tunnel ignoring state.
// Used for control frames.
func (p *Pool) BroadcastAlways(f mpframe.Frame) int {
	tunnels := p.snapshot()
	sent := 0
	for _, t := range tunnels {
		if t.SendAlways(f) {
			sent++
		}
	}
	return sent
}

// Tunnels returns a snapshot of all live tunnels (active + shadow).
func (p *Pool) Tunnels() []*Tunnel { return p.snapshot() }

// LiveCount returns the number of live tunnels in the pool.
func (p *Pool) LiveCount() int {
	return len(p.snapshot())
}

// ActiveCount returns the number of currently-Active tunnels.
func (p *Pool) ActiveCount() int {
	tunnels := p.snapshot()
	n := 0
	for _, t := range tunnels {
		if t.State() == StateActive {
			n++
		}
	}
	return n
}

// AddConn pushes an externally-accepted conn into the pool. Server side.
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
	t.SetState(StateActive)
	p.accepted[t] = struct{}{}
	p.mu.Unlock()

	fmt.Printf("pool: tunnel %s up (accepted)\n", name)
	go func() {
		p.runTunnel(t)
		p.mu.Lock()
		delete(p.accepted, t)
		p.mu.Unlock()
		fmt.Printf("pool: tunnel %s down (accepted)\n", name)
	}()
}

// Close shuts the pool down.
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
	close(p.inboundWithSrc)
}

func (p *Pool) snapshot() []*Tunnel {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.snapshotLocked()
}

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

// maintainSlot keeps slot i populated with a live tunnel.
//
// Reconnect uses exponential backoff so a long server outage doesn't
// hammer the network with dial attempts. Backoff resets to baseline
// once a tunnel stays up for at least minStableUptime — that way a
// brief flap doesn't cascade into a long backoff.
func (p *Pool) maintainSlot(i int) {
	defer p.wg.Done()
	dial := p.dialFuncs[i]
	name := p.dialerNames[i]

	const (
		minStableUptime = 30 * time.Second
		maxBackoff      = 15 * time.Second
	)
	backoff := p.reconnectBackoff
	for {
		if p.ctx.Err() != nil {
			return
		}
		dialCtx, cancel := context.WithTimeout(p.ctx, 10*time.Second)
		conn, err := dial(dialCtx)
		cancel()
		if err != nil {
			fmt.Printf("pool slot %s: dial failed: %v (retry in %v)\n",
				name, err, backoff)
			select {
			case <-p.ctx.Done():
				return
			case <-time.After(backoff):
				// Exponential backoff up to maxBackoff.
				backoff *= 2
				if backoff > maxBackoff {
					backoff = maxBackoff
				}
				continue
			}
		}
		t := &Tunnel{
			name:   name,
			conn:   conn,
			sendCh: make(chan mpframe.Frame, sendBufferDepth),
			done:   make(chan struct{}),
		}
		t.SetState(StateActive)
		p.mu.Lock()
		p.slotted[i] = t
		p.mu.Unlock()

		fmt.Printf("pool slot %s: tunnel up\n", name)
		upStart := time.Now()
		p.runTunnel(t)
		uptime := time.Since(upStart)

		p.mu.Lock()
		if p.slotted[i] == t {
			p.slotted[i] = nil
		}
		p.mu.Unlock()
		fmt.Printf("pool slot %s: tunnel down (uptime %v)\n", name, uptime.Round(time.Millisecond))

		// Reset backoff if the tunnel was actually stable.
		if uptime >= minStableUptime {
			backoff = p.reconnectBackoff
		} else {
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}

		select {
		case <-p.ctx.Done():
			return
		case <-time.After(backoff):
		}
	}
}

// runTunnel runs reader+writer goroutines and blocks until both exit.
func (p *Pool) runTunnel(t *Tunnel) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for {
			select {
			case <-t.done:
				return
			case f := <-t.sendCh:
				blob, err := mpframe.Marshal(f)
				if err != nil {
					t.Close()
					return
				}
				if err := p.codec.WriteFrame(t.conn, blob); err != nil {
					t.Close()
					return
				}
			}
		}
	}()

	go func() {
		defer wg.Done()
		for {
			pt, err := p.codec.ReadFrame(t.conn)
			if err != nil {
				t.Close()
				return
			}
			f, err := mpframe.Unmarshal(pt)
			if err != nil {
				t.Close()
				return
			}
			p.totalRecvd.Add(1)
			select {
			case p.inboundWithSrc <- FrameWithSrc{Frame: f, Src: t}:
			case <-t.done:
				return
			case <-p.ctx.Done():
				return
			}
		}
	}()

	wg.Wait()
}
