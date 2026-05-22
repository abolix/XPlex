// Package mpdedup implements an in-memory reorder + dedup buffer for
// frames received over multiple parallel paths.
//
// Each direction of the multipath stream has its own buffer. Frames
// arrive in arbitrary order across paths and may be duplicated; this
// buffer presents them as a single in-order, dedup'd byte stream.
package mpdedup

import (
	"errors"
	"sync"
)

// ErrFull is returned by Push when the unordered backlog would exceed
// the configured capacity. The caller should treat the stream as
// broken: a path is wedged and we cannot make forward progress.
var ErrFull = errors.New("dedup buffer full")

// Buffer is safe for concurrent use.
type Buffer struct {
	mu      sync.Mutex
	next    uint64            // next seqno expected in delivery order
	pending map[uint64][]byte // out-of-order frames waiting for the gap to fill
	cap     int               // maximum number of pending frames
}

// New returns a buffer that delivers frames starting at startSeq. cap
// bounds the number of buffered out-of-order frames.
func New(startSeq uint64, cap int) *Buffer {
	if cap <= 0 {
		cap = 1024
	}
	if startSeq == 0 {
		startSeq = 1
	}
	return &Buffer{
		next:    startSeq,
		pending: make(map[uint64][]byte),
		cap:     cap,
	}
}

// Push records the frame at seq and returns any payloads that are now
// deliverable in order. It returns ErrFull if accepting the frame
// would exceed the buffer's capacity.
//
// Frames whose seqno is below the current delivery point or already
// pending are silently dropped (legitimate duplicates from another
// path).
func (b *Buffer) Push(seq uint64, payload []byte) ([][]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if seq < b.next {
		return nil, nil
	}
	if _, exists := b.pending[seq]; exists {
		return nil, nil
	}
	if len(b.pending) >= b.cap {
		return nil, ErrFull
	}

	b.pending[seq] = payload

	var ready [][]byte
	for {
		p, ok := b.pending[b.next]
		if !ok {
			break
		}
		delete(b.pending, b.next)
		ready = append(ready, p)
		b.next++
	}
	return ready, nil
}

// Next returns the next seqno awaiting delivery (for diagnostics).
func (b *Buffer) Next() uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.next
}

// Pending returns the number of out-of-order frames currently buffered.
func (b *Buffer) Pending() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.pending)
}

