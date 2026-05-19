package runner

import (
	"net"
	"strconv"
	"testing"
	"time"
)

func TestWaitReady_ReturnsWhenPortAccepts(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	_, p, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(p)
	inst := &Instance{Port: port}

	if err := WaitReady(inst, 1*time.Second); err != nil {
		t.Fatalf("WaitReady: %v", err)
	}
}

func TestWaitReady_TimesOutOnDeadPort(t *testing.T) {
	// Bind then immediately close so we know the port is dead.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, p, _ := net.SplitHostPort(ln.Addr().String())
	ln.Close()
	port, _ := strconv.Atoi(p)
	inst := &Instance{Port: port}

	start := time.Now()
	err = WaitReady(inst, 250*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout error on dead port")
	}
	if elapsed := time.Since(start); elapsed < 200*time.Millisecond {
		t.Errorf("returned too early: %v", elapsed)
	}
}

func TestWaitReady_PortBecomesAvailable(t *testing.T) {
	// Pick a free port, bind it after a short delay; WaitReady should
	// succeed once the listener comes up.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	_, p, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(p)
	ln.Close()

	go func() {
		time.Sleep(150 * time.Millisecond)
		l, err := net.Listen("tcp", addr)
		if err != nil {
			return
		}
		// Accept in the background until the test ends.
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				c.Close()
			}
		}()
		t.Cleanup(func() { l.Close() })
	}()

	if err := WaitReady(&Instance{Port: port}, 2*time.Second); err != nil {
		t.Fatalf("WaitReady should have succeeded: %v", err)
	}
}
