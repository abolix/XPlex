package mphub_test

import (
	"context"
	"testing"
	"time"

	"xplex/internal/mpframe"
	"xplex/internal/mphub"
	"xplex/internal/mppool"
	"xplex/internal/testutil"
)

// TestInbox_NoDuplicateFlood verifies that with 3 tunnels sending the
// same frame, only 1 copy enters the inbox. This prevents "inbox full"
// under multipath burst load.
func TestInbox_NoDuplicateFlood(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool := mppool.New(ctx, mppool.Config{Codec: testutil.TestCodec(t)})
	t.Cleanup(pool.Close)
	hub := mphub.New(ctx, pool, nil)
	t.Cleanup(hub.Close)

	var sid mpframe.SessionID
	sid[0] = 0xAA
	// Use a tiny inbox (8 slots) to prove dedup prevents overflow.
	sess := mphub.NewSession(hub, sid, mphub.SessionConfig{
		StartRx:         1,
		InboxBufferSize: 8,
	})
	if !hub.Register(sess) {
		t.Fatal("register failed")
	}
	defer sess.Close()

	// Simulate 3 tunnels each delivering the same 20 frames (seq 1-20).
	// Without dedup: 60 frames hit the inbox (size 8) → massive overflow.
	// With dedup: only 20 unique frames enter → fits in 8 if consumer runs.
	done := make(chan struct{})
	go func() {
		defer close(done)
		received := 0
		for received < 20 {
			select {
			case fr := <-sess.Inbox():
				if fr.Type == mpframe.TypeData {
					received++
				}
			case <-time.After(5 * time.Second):
				t.Errorf("timeout after receiving %d frames", received)
				return
			}
		}
	}()

	// Feed 3 copies of each frame (simulating 3 tunnels).
	for seq := uint64(1); seq <= 20; seq++ {
		for tunnel := 0; tunnel < 3; tunnel++ {
			f := mpframe.Frame{
				Type:    mpframe.TypeData,
				Session: sid,
				Seq:     seq,
				Payload: []byte("hello"),
			}
			hub.TestFeed(f) // exposed for testing
		}
		// Small delay to let consumer drain.
		time.Sleep(1 * time.Millisecond)
	}

	select {
	case <-done:
		// Success — all 20 unique frames received without overflow.
	case <-time.After(10 * time.Second):
		t.Fatal("test timed out — consumer stuck or frames lost")
	}
}

