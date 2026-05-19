package stats_test

import (
	"sync"
	"testing"
	"time"

	"xrayrunner/internal/stats"
)

func ok(latencyMs int) stats.Sample {
	return stats.Sample{OK: true, Latency: time.Duration(latencyMs) * time.Millisecond}
}
func fail() stats.Sample { return stats.Sample{OK: false} }

func TestTracker_EmptySnapshot(t *testing.T) {
	tr := stats.NewTracker(10)
	s := tr.Snapshot(1080)
	if s.Total != 0 || s.Successes != 0 {
		t.Fatalf("empty snapshot: %+v", s)
	}
	if s.Score != stats.MaxScore {
		t.Errorf("expected MaxScore for empty, got %v", s.Score)
	}
}

func TestTracker_RollingWindowEvicts(t *testing.T) {
	tr := stats.NewTracker(3)
	tr.Record(1, ok(100))
	tr.Record(1, ok(200))
	tr.Record(1, ok(300))
	tr.Record(1, ok(400)) // pushes 100 out

	s := tr.Snapshot(1)
	if s.Total != 3 {
		t.Fatalf("expected 3 retained samples, got %d", s.Total)
	}
	// Latencies in window are 200,300,400; P50 should be 300.
	if s.MedianLatency != 300*time.Millisecond {
		t.Errorf("median = %v, want 300ms", s.MedianLatency)
	}
}

func TestTracker_SuccessRate(t *testing.T) {
	tr := stats.NewTracker(10)
	tr.Record(1, ok(50))
	tr.Record(1, fail())
	tr.Record(1, ok(50))
	tr.Record(1, fail())

	s := tr.Snapshot(1)
	if s.Total != 4 || s.Successes != 2 {
		t.Fatalf("got total=%d successes=%d, want 4/2", s.Total, s.Successes)
	}
	if s.SuccessRate != 0.5 {
		t.Errorf("rate = %v, want 0.5", s.SuccessRate)
	}
}

func TestTracker_PercentileResistsSpike(t *testing.T) {
	tr := stats.NewTracker(10)
	// Nine probes around 100ms, one giant 10s spike.
	for i := 0; i < 9; i++ {
		tr.Record(1, ok(100))
	}
	tr.Record(1, ok(10000))

	s := tr.Snapshot(1)
	if s.MedianLatency != 100*time.Millisecond {
		t.Errorf("median should resist single spike: %v", s.MedianLatency)
	}
	// P90 with 10 samples sorted = 9th value. 9 of 100ms and 1 of 10000ms
	// after sorting: index 8 is 100ms, index 9 is 10000ms. ceil(0.9*10)=9 → idx 8.
	if s.P90Latency != 100*time.Millisecond {
		t.Errorf("P90 with one outlier should still be 100ms: %v", s.P90Latency)
	}
}

func TestTracker_P90PicksUpRepeatedSpikes(t *testing.T) {
	tr := stats.NewTracker(10)
	for i := 0; i < 8; i++ {
		tr.Record(1, ok(100))
	}
	tr.Record(1, ok(800))
	tr.Record(1, ok(900))

	s := tr.Snapshot(1)
	// Sorted OK latencies: 100x8, 800, 900. P90 → idx 8 → 800ms.
	if s.P90Latency != 800*time.Millisecond {
		t.Errorf("P90 with 2 spikes should be 800ms: %v", s.P90Latency)
	}
}

func TestTracker_ScoreAccountsForFailures(t *testing.T) {
	tr := stats.NewTracker(10)
	for i := 0; i < 5; i++ {
		tr.Record(1, ok(100))
	}
	for i := 0; i < 5; i++ {
		tr.Record(1, fail())
	}
	s := tr.Snapshot(1)
	// 50% success rate doubles the score.
	if s.SuccessRate != 0.5 {
		t.Fatalf("rate = %v, want 0.5", s.SuccessRate)
	}
	// All successes had identical 100ms latency, so P90 is 100ms.
	// Score = 100ms / 0.5 = 200ms.
	if s.Score != 200*time.Millisecond {
		t.Errorf("score = %v, want 200ms", s.Score)
	}
}

func TestTracker_ScoreMaxWhenAllFail(t *testing.T) {
	tr := stats.NewTracker(5)
	for i := 0; i < 5; i++ {
		tr.Record(1, fail())
	}
	s := tr.Snapshot(1)
	if s.Successes != 0 {
		t.Fatal("expected 0 successes")
	}
	if s.Score != stats.MaxScore {
		t.Errorf("expected MaxScore for all-fail, got %v", s.Score)
	}
}

func TestTracker_LastOK(t *testing.T) {
	tr := stats.NewTracker(5)
	tr.Record(1, fail())
	tr.Record(1, ok(50))
	if !tr.Snapshot(1).LastOK {
		t.Error("LastOK should be true")
	}
	tr.Record(1, fail())
	if tr.Snapshot(1).LastOK {
		t.Error("LastOK should be false after a failure")
	}
}

func TestTracker_SnapshotsCopy(t *testing.T) {
	tr := stats.NewTracker(5)
	tr.Record(1080, ok(100))
	tr.Record(1081, ok(50))
	all := tr.Snapshots()
	if len(all) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(all))
	}
	if all[1080].Successes != 1 || all[1081].Successes != 1 {
		t.Errorf("counts wrong: %+v", all)
	}
}

func TestTracker_Concurrent(t *testing.T) {
	tr := stats.NewTracker(20)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				tr.Record(id, ok(j))
			}
		}(i)
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				_ = tr.Snapshots()
			}
		}()
	}
	wg.Wait()
}

func TestTracker_WindowZeroFallsBackToOne(t *testing.T) {
	tr := stats.NewTracker(0)
	tr.Record(1, ok(50))
	tr.Record(1, ok(100))
	s := tr.Snapshot(1)
	if s.Total != 1 {
		t.Errorf("window<=0 should clamp to 1, got total=%d", s.Total)
	}
}
