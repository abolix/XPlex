// Package testutil provides shared test fakes — kept in a separate package
// so tests across modules (socks5, probe, lbserver) can reuse them without
// import cycles.
package testutil

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// FakeSocks5 is a minimal SOCKS5 server intended only for tests.
// On a successful CONNECT it invokes Handler with the requested target
// and the in-tunnel connection. The handler can do whatever it wants
// with the conn (echo bytes, return canned HTTP, close immediately, ...).
type FakeSocks5 struct {
	// Handler is called after CONNECT succeeds. The conn is the SOCKS
	// tunnel; whatever you read from it is what the client sent through
	// the proxy, and whatever you write goes back to the client.
	Handler func(target string, port uint16, conn net.Conn)

	// Behavior knobs for fault-injection tests.
	RefuseAuth       bool          // reply with method=0xff during greeting
	FailConnectReply byte          // if non-zero, reply CONNECT with this status
	GreetDelay       time.Duration // sleep before responding to greeting

	listener net.Listener
	wg       sync.WaitGroup
	closed   atomic.Bool
}

// Start binds an ephemeral port on localhost and begins accepting.
func (f *FakeSocks5) Start() (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	f.listener = ln
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			f.wg.Add(1)
			go func() {
				defer f.wg.Done()
				f.serve(c)
			}()
		}
	}()
	return ln.Addr().String(), nil
}

// Close stops the server and waits for in-flight handlers.
func (f *FakeSocks5) Close() {
	if f.closed.Swap(true) {
		return
	}
	if f.listener != nil {
		_ = f.listener.Close()
	}
	f.wg.Wait()
}

func (f *FakeSocks5) serve(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))

	if f.GreetDelay > 0 {
		time.Sleep(f.GreetDelay)
	}

	// Greeting.
	head := make([]byte, 2)
	if _, err := io.ReadFull(c, head); err != nil {
		return
	}
	if head[0] != 0x05 {
		return
	}
	methods := make([]byte, head[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	if f.RefuseAuth {
		_, _ = c.Write([]byte{0x05, 0xff})
		return
	}
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// CONNECT request.
	target, port, err := readConnect(c)
	if err != nil {
		return
	}

	if f.FailConnectReply != 0 {
		writeReply(c, f.FailConnectReply)
		return
	}
	if err := writeReply(c, 0x00); err != nil {
		return
	}

	// Clear deadline before handing off.
	_ = c.SetDeadline(time.Time{})
	if f.Handler != nil {
		f.Handler(target, port, c)
	}
}

func readConnect(c net.Conn) (string, uint16, error) {
	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		return "", 0, err
	}
	if head[0] != 0x05 || head[1] != 0x01 {
		return "", 0, errors.New("expected CONNECT")
	}

	var host string
	switch head[3] {
	case 0x01:
		buf := make([]byte, 4)
		if _, err := io.ReadFull(c, buf); err != nil {
			return "", 0, err
		}
		host = net.IP(buf).String()
	case 0x03:
		ln := make([]byte, 1)
		if _, err := io.ReadFull(c, ln); err != nil {
			return "", 0, err
		}
		buf := make([]byte, ln[0])
		if _, err := io.ReadFull(c, buf); err != nil {
			return "", 0, err
		}
		host = string(buf)
	case 0x04:
		buf := make([]byte, 16)
		if _, err := io.ReadFull(c, buf); err != nil {
			return "", 0, err
		}
		host = net.IP(buf).String()
	default:
		return "", 0, fmt.Errorf("bad atyp %d", head[3])
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(c, portBuf); err != nil {
		return "", 0, err
	}
	return host, binary.BigEndian.Uint16(portBuf), nil
}

func writeReply(c net.Conn, status byte) error {
	_, err := c.Write([]byte{0x05, status, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	return err
}
