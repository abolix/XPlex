// Package monitor periodically probes each running xray instance and
// records the result into a stats tracker. The tracker is read by
// other components (e.g. a future duplication controller) but the
// monitor itself does not pick a "best" upstream — the multipath
// frontend broadcasts to all of them.
package monitor

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"xrayrunner/internal/probe"
	"xrayrunner/internal/runner"
	"xrayrunner/internal/stats"
)

// Run blocks until ctx is cancelled, probing every interval.
// timeout is the per-instance probe timeout.
func Run(
	ctx context.Context,
	instances []*runner.Instance,
	tracker *stats.Tracker,
	interval, timeout time.Duration,
) {
	probeAll(instances, tracker, timeout)

	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			probeAll(instances, tracker, timeout)
		}
	}
}

func probeAll(instances []*runner.Instance, tracker *stats.Tracker, timeout time.Duration) {
	results := make([]probe.Result, len(instances))
	var wg sync.WaitGroup
	for i, inst := range instances {
		wg.Add(1)
		go func(i int, inst *runner.Instance) {
			defer wg.Done()
			results[i] = probe.Run(inst.Port, timeout)
		}(i, inst)
	}
	wg.Wait()

	now := time.Now()
	for _, r := range results {
		tracker.Record(r.Port, stats.Sample{
			OK:      r.OK,
			Latency: r.Latency,
			At:      now,
		})
	}

	sort.Slice(results, func(i, j int) bool { return results[i].Port < results[j].Port })

	stamp := now.Format("15:04:05")
	fmt.Printf("\n=== health check %s ===\n", stamp)
	snaps := tracker.Snapshots()
	for _, r := range results {
		s := snaps[r.Port]
		if r.OK {
			fmt.Printf("  :%d  OK    last=%4dms  p50=%4dms  p90=%4dms  ok=%d/%d\n",
				r.Port,
				r.Latency.Milliseconds(),
				s.MedianLatency.Milliseconds(),
				s.P90Latency.Milliseconds(),
				s.Successes, s.Total,
			)
		} else {
			fmt.Printf("  :%d  FAIL  ok=%d/%d  (%s)\n",
				r.Port, s.Successes, s.Total, r.Err)
		}
	}
}
