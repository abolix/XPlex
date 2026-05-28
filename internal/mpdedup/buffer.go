// Package mpdedup implements an in-memory reorder + dedup buffer for
// frames received over multiple parallel paths.
//
// Each direction of the multipath stream has its own buffer. Frames
// arrive in arbitrary order across paths and may be duplicated; this
// buffer presents them as a single in-order, dedup'd byte stream.
//
// Gap timeout: if the next expected sequence number doesn't arrive
// within GapTimeout, the buffer skips ahead to the lowest buffered
// seq and delivers from there. This prevents permanent stalls when
// frames are lost due to tunnel death.
package mpdedup

import (
	"errors"
	"sync"
	"time"
)

// ErrFull is returned by Push when the unordered backlog would exceed
// the configured capacity. The caller should treat the stream as
// broken: a path is wedged and we cannot make forward progress.
var ErrFull = errors.New("dedup buffer full")

// DefaultGapTimeout is how long we wait for a missing seq before
// skipping ahead. Must be long enough to tolerate reordering across
// paths, but short enough to recover from lost frames quickly.
const DefaultGapTimeout = 3 * time.Second

// Buffer is safe for concurrent use.
type Buffer struct {
	mu      sync.Mutex
	next    uint64            // next seqno expected in delivery order
	pending map[uint64][]byte // out-of-order frames waiting for the gap to fill
	cap     int               // maximum number of pending frames

	// Gap timeout: when we first notice a gap (pending has frames but
	// next is missing), we record the time. If the gap persists longer
	// than gapTimeout, we skip ahead.
	gapTimeout time.Duration
	gapSince   time.Time // when we first saw the gap; zero means no gap
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
		next:       startSeq,
		pending:    make(map[uint64][]byte),
		cap:        cap,
		gapTimeout: DefaultGapTimeout,
	}
}

// Push records the frame at seq and returns any payloads that are now
// deliverable in order. It returns ErrFull if accepting the frame
// would exceed the buffer's capacity.
//
// Frames whose seqno is below the current delivery point or already
// pending are silently dropped (legitimate duplicates from another
// path).
//
// If a gap has persisted longer than gapTimeout, Push skips ahead to
// the lowest pending seq and delivers everything it can from there.
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
		// Before returning ErrFull, try gap-skip recovery if gap has
		// persisted long enough.
		if !b.gapSince.IsZero() && time.Since(b.gapSince) >= b.gapTimeout {
			if recovered := b.skipGapLocked(); len(recovered) > 0 {
				// Made room — now accept the new frame.
				b.pending[seq] = payload
				more := b.drainLocked()
				return append(recovered, more...), nil
			}
		}
		return nil, ErrFull
	}

	b.pending[seq] = payload

	// Try normal in-order delivery.
	ready := b.drainLocked()

	// If we still have pending frames but couldn't deliver (gap exists),
	// check the gap timeout.
	if len(b.pending) > 0 && len(ready) == 0 {
		if b.gapSince.IsZero() {
			b.gapSince = time.Now()
		} else if time.Since(b.gapSince) >= b.gapTimeout {
			// Gap has persisted too long — skip ahead.
			skipped := b.skipGapLocked()
			ready = append(ready, skipped...)
		}
	} else if len(b.pending) == 0 {
		// No gap — reset timer.
		b.gapSince = time.Time{}
	}

	return ready, nil
}

// drainLocked delivers consecutive frames starting from b.next.
func (b *Buffer) drainLocked() [][]byte {
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
	if len(ready) > 0 {
		b.gapSince = time.Time{} // delivered something, reset gap timer
	}
	return ready
}

// skipGapLocked advances b.next to the lowest pending seq, skipping
// the missing frames. Returns any payloads that become deliverable.
func (b *Buffer) skipGapLocked() [][]byte {
	if len(b.pending) == 0 {
		return nil
	}
	// Find the lowest pending seq.
	minSeq := ^uint64(0)
	for k := range b.pending {
		if k < minSeq {
			minSeq = k
		}
	}
	if minSeq <= b.next {
		return nil // shouldn't happen, but be safe
	}
	// Skip ahead.
	b.next = minSeq
	b.gapSince = time.Time{}
	return b.drainLocked()
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

// Flush forces delivery of all pending frames regardless of gaps.
// Used when the stream is ending (CLOSE received) and we want to
// deliver whatever we have rather than wait for missing frames.
func (b *Buffer) Flush() [][]byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.pending) == 0 {
		return nil
	}
	// Collect all pending seqs in order.
	var seqs []uint64
	for k := range b.pending {
		seqs = append(seqs, k)
	}
	// Sort them.
	sortUint64(seqs)
	var out [][]byte
	for _, s := range seqs {
		out = append(out, b.pending[s])
		delete(b.pending, s)
	}
	if len(seqs) > 0 {
		b.next = seqs[len(seqs)-1] + 1
	}
	b.gapSince = time.Time{}
	return out
}

func sortUint64(s []uint64) {
	// Simple insertion sort — pending is typically small.
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
