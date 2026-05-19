package mpdedup_test

import (
	"bytes"
	"errors"
	"sync"
	"testing"

	"xrayrunner/internal/mpdedup"
)

func TestPushInOrderDelivers(t *testing.T) {
	b := mpdedup.New(1, 16)
	for i := uint64(1); i <= 5; i++ {
		ready, err := b.Push(i, []byte{byte(i)})
		if err != nil {
			t.Fatalf("seq %d: %v", i, err)
		}
		if len(ready) != 1 || ready[0][0] != byte(i) {
			t.Fatalf("seq %d: ready=%v", i, ready)
		}
	}
	if b.Pending() != 0 || b.Next() != 6 {
		t.Errorf("after in-order: pending=%d next=%d", b.Pending(), b.Next())
	}
}

func TestPushOutOfOrderReorders(t *testing.T) {
	b := mpdedup.New(1, 16)

	if ready, _ := b.Push(3, []byte{3}); len(ready) != 0 {
		t.Fatalf("seq 3 should buffer, got %v", ready)
	}
	if ready, _ := b.Push(2, []byte{2}); len(ready) != 0 {
		t.Fatalf("seq 2 should still buffer (1 missing), got %v", ready)
	}
	ready, err := b.Push(1, []byte{1})
	if err != nil {
		t.Fatalf("Push 1: %v", err)
	}
	// Now we should get 1, 2, 3 in order.
	if len(ready) != 3 {
		t.Fatalf("expected 3 ready, got %d (%v)", len(ready), ready)
	}
	for i, want := range []byte{1, 2, 3} {
		if !bytes.Equal(ready[i], []byte{want}) {
			t.Errorf("ready[%d] = %v, want %v", i, ready[i], []byte{want})
		}
	}
}

func TestDuplicatesIgnored(t *testing.T) {
	b := mpdedup.New(1, 16)

	// First arrival of seq=1.
	ready, _ := b.Push(1, []byte("first"))
	if len(ready) != 1 || string(ready[0]) != "first" {
		t.Fatalf("got %v", ready)
	}
	// Duplicate of seq=1 (after delivery): below next, dropped.
	ready, _ = b.Push(1, []byte("dup"))
	if len(ready) != 0 {
		t.Errorf("delivered duplicate: %v", ready)
	}
}

func TestDuplicateWhilePendingIgnored(t *testing.T) {
	b := mpdedup.New(1, 16)
	// Out-of-order seq=2 first.
	if ready, _ := b.Push(2, []byte("a")); len(ready) != 0 {
		t.Fatalf("got %v", ready)
	}
	// Duplicate of seq=2 (still in pending): no-op.
	if ready, _ := b.Push(2, []byte("a-dup")); len(ready) != 0 {
		t.Fatalf("got %v", ready)
	}
	// Seq=1 unblocks — payload should be the original "a", not "a-dup".
	ready, _ := b.Push(1, []byte("first"))
	if len(ready) != 2 {
		t.Fatalf("got %d (%v)", len(ready), ready)
	}
	if string(ready[1]) != "a" {
		t.Errorf("dup overwrote pending: got %q, want %q", ready[1], "a")
	}
}

func TestErrFullWhenBacklogExceedsCap(t *testing.T) {
	b := mpdedup.New(1, 3)
	for i := uint64(2); i <= 4; i++ {
		if _, err := b.Push(i, []byte{byte(i)}); err != nil {
			t.Fatalf("seq %d should succeed, got %v", i, err)
		}
	}
	_, err := b.Push(5, []byte{5})
	if !errors.Is(err, mpdedup.ErrFull) {
		t.Fatalf("expected ErrFull, got %v", err)
	}
}

func TestStartSeqHonored(t *testing.T) {
	b := mpdedup.New(100, 16)
	if ready, _ := b.Push(99, []byte("old")); len(ready) != 0 {
		t.Errorf("seq below start should drop, got %v", ready)
	}
	if ready, _ := b.Push(100, []byte("first")); len(ready) != 1 {
		t.Errorf("expected delivery at start seq, got %v", ready)
	}
}

func TestConcurrentPush(t *testing.T) {
	b := mpdedup.New(1, 10000)
	var wg sync.WaitGroup
	const n = 1000
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := uint64(1); j <= n; j++ {
				_, _ = b.Push(j, []byte{byte(j)})
			}
		}()
	}
	wg.Wait()
	if b.Next() != n+1 {
		t.Errorf("after concurrent dups: next=%d, want %d", b.Next(), n+1)
	}
}
