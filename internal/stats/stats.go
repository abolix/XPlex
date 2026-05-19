// Package stats keeps a rolling, in-memory history of probe results per
// upstream port and exposes derived metrics for selection decisions.
//
// All data is in-memory only — nothing is persisted to disk. State
// resets when the program exits.
package stats

import (
	"math"
	"sort"
	"sync"
	"time"
)

// MaxScore represents an "unhealthy / no data" score. Used in place of
// math.Inf so the caller can compare durations directly.
const MaxScore = time.Duration(math.MaxInt64)

// Sample is a single recorded probe outcome.
type Sample struct {
	OK      bool
	Latency time.Duration
	At      time.Time
}

// Snapshot is the derived view of an upstream's recent behavior.
type Snapshot struct {
	Total         int           // probes recorded in the window
	Successes     int           // OK probes in the window
	SuccessRate   float64       // Successes / Total (0..1), 0 when Total==0
	MedianLatency time.Duration // P50 over OK samples
	P90Latency    time.Duration // P90 over OK samples (tail latency)
	Jitter        time.Duration // P90 - P50
	Score         time.Duration // P90 / SuccessRate; MaxScore when no successes
	LastOK        bool          // outcome of the most recent sample
}

// Tracker maintains a sliding window of Samples per port. Safe for
// concurrent use.
type Tracker struct {
	mu      sync.RWMutex
	window  int
	history map[int][]Sample
}

// NewTracker returns a Tracker that keeps at most window samples per port.
func NewTracker(window int) *Tracker {
	if window <= 0 {
		window = 1
	}
	return &Tracker{window: window, history: make(map[int][]Sample)}
}

// Record appends a sample for port and evicts the oldest if the window
// is exceeded.
func (t *Tracker) Record(port int, s Sample) {
	t.mu.Lock()
	defer t.mu.Unlock()
	h := append(t.history[port], s)
	if len(h) > t.window {
		h = h[len(h)-t.window:]
	}
	t.history[port] = h
}

// Snapshot returns the derived stats for a single port. For unknown
// ports the zero value is returned with Score == MaxScore.
func (t *Tracker) Snapshot(port int) Snapshot {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return computeSnapshot(t.history[port])
}

// Snapshots returns a copy of every known port's current snapshot.
func (t *Tracker) Snapshots() map[int]Snapshot {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make(map[int]Snapshot, len(t.history))
	for p, h := range t.history {
		out[p] = computeSnapshot(h)
	}
	return out
}

func computeSnapshot(samples []Sample) Snapshot {
	s := Snapshot{Total: len(samples), Score: MaxScore}
	if s.Total == 0 {
		return s
	}
	s.LastOK = samples[len(samples)-1].OK

	// Collect OK latencies for percentile calculation.
	lat := make([]time.Duration, 0, len(samples))
	for _, x := range samples {
		if x.OK {
			s.Successes++
			lat = append(lat, x.Latency)
		}
	}
	s.SuccessRate = float64(s.Successes) / float64(s.Total)

	if s.Successes == 0 {
		// Score remains MaxScore.
		return s
	}

	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	s.MedianLatency = nearestRank(lat, 0.5)
	s.P90Latency = nearestRank(lat, 0.9)
	s.Jitter = s.P90Latency - s.MedianLatency

	// Score = P90 / success_rate. P90 captures spikes (median is too
	// forgiving), and dividing by success_rate inflates the score for
	// any backend that's flaky.
	s.Score = time.Duration(float64(s.P90Latency) / s.SuccessRate)
	return s
}

// nearestRank returns the value at percentile p (0..1) using the
// nearest-rank method on a pre-sorted slice. For empty input returns 0.
func nearestRank(sorted []time.Duration, p float64) time.Duration {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	idx := int(math.Ceil(p*float64(n))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= n {
		idx = n - 1
	}
	return sorted[idx]
}
