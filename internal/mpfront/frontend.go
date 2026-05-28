// Package mpfront is the local SOCKS5 frontend on the client side.
//
// Each accepted SOCKS5 connection becomes one session. A session
// reserves a fresh 16-byte ID, registers with the hub, broadcasts a
// HELLO carrying the requested destination, waits for HELLO_ACK on
// any tunnel, then pumps client bytes as DATA frames and returns
// dedup'd inbound bytes back to the SOCKS5 client.
//
// All tunnels are shared (long-lived in the pool); the frontend
// never opens a tunnel itself.
package mpfront

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"xplex/internal/mpframe"
	"xplex/internal/mphub"
)

// Config controls the frontend.
type Config struct {
	ListenAddr     string
	HelloTimeout   time.Duration // how long to wait for HELLO_ACK
	WriteChunkSize int           // max DATA payload per frame
}

// Frontend listens on a local SOCKS5 port and forwards each accepted
// connection over the hub.
type Frontend struct {
	cfg Config
	hub *mphub.Hub
}

// New returns a Frontend bound to hub.
func New(hub *mphub.Hub, cfg Config) *Frontend {
	if cfg.HelloTimeout == 0 {
		cfg.HelloTimeout = 5 * time.Second
	}
	if cfg.WriteChunkSize == 0 {
		cfg.WriteChunkSize = 16 * 1024
	}
	return &Frontend{cfg: cfg, hub: hub}
}

// Run blocks until ctx is cancelled or Listen fails.
func (f *Frontend) Run(ctx context.Context) error {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", f.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", f.cfg.ListenAddr, err)
	}
	defer ln.Close()
	go func() { <-ctx.Done(); ln.Close() }()

	fmt.Printf("mp-front listening on socks5://%s\n", f.cfg.ListenAddr)

	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept: %w", err)
		}
		go f.handle(ctx, c)
	}
}

func (f *Frontend) handle(ctx context.Context, client net.Conn) {
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(f.cfg.HelloTimeout))

	target, err := socksHandshake(client)
	if err != nil {
		return
	}

	// Wait briefly for at least one tunnel instead of instant-reject.
	if f.hub.Pool().LiveCount() == 0 {
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			if f.hub.Pool().LiveCount() > 0 {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if f.hub.Pool().LiveCount() == 0 {
			_ = writeConnectReply(client, 0x03)
			return
		}
	}

	var sid mpframe.SessionID
	if _, err := rand.Read(sid[:]); err != nil {
		_ = writeConnectReply(client, 0x01)
		return
	}

	sess := mphub.NewSession(f.hub, sid, mphub.SessionConfig{StartRx: 1})
	if !f.hub.Register(sess) {
		_ = writeConnectReply(client, 0x01)
		return
	}
	defer sess.Close()

	// Send HELLO.
	destPayload, err := mpframe.EncodeDest(target)
	if err != nil {
		_ = writeConnectReply(client, 0x01)
		return
	}
	if sess.SendControl(mpframe.TypeHello, destPayload) == 0 {
		_ = writeConnectReply(client, 0x03)
		return
	}

	// 0-RTT: Tell the SOCKS5 client "connected" immediately and start
	// pumping data. The server will buffer early DATA frames while it
	// dials the destination. If dial fails, we'll get HELLO_ACK with
	// an error and close the session — the client sees a broken pipe.
	if err := writeConnectReply(client, 0x00); err != nil {
		return
	}
	_ = client.SetDeadline(time.Time{})

	fmt.Printf("session %x: open -> %s\n", sid[:], target)

	// Start pumps immediately — don't wait for ACK.
	clientDone := make(chan struct{})
	hubDone := make(chan struct{})
	go func() {
		f.pumpClientToHub(client, sess)
		close(clientDone)
	}()
	go func() {
		f.pumpHubToClient(client, sess)
		close(hubDone)
	}()

	select {
	case <-clientDone:
		sess.SendControl(mpframe.TypeClose, nil)
		select {
		case <-hubDone:
		case <-time.After(5 * time.Second):
		}
	case <-hubDone:
		sess.SendControl(mpframe.TypeClose, nil)
		select {
		case <-clientDone:
		case <-time.After(2 * time.Second):
		}
	}

	fmt.Printf("session %x: closed\n", sid[:])
}

func (f *Frontend) pumpClientToHub(client net.Conn, sess *mphub.Session) {
	buf := make([]byte, f.cfg.WriteChunkSize)
	for {
		n, err := client.Read(buf)
		if n > 0 {
			payload := make([]byte, n)
			copy(payload, buf[:n])
			if _, sent := sess.SendData(payload); sent == 0 {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func (f *Frontend) pumpHubToClient(client net.Conn, sess *mphub.Session) {
	for {
		select {
		case <-sess.Done():
			return
		case fr, ok := <-sess.Inbox():
			if !ok {
				return
			}
			switch fr.Type {
			case mpframe.TypeData:
				ready, err := sess.DeliverData(fr)
				if err != nil {
					return
				}
				for _, p := range ready {
					if _, werr := client.Write(p); werr != nil {
						return
					}
				}
			case mpframe.TypeHelloAck:
				// 0-RTT: if ACK carries an error, the server couldn't
				// dial the destination. Close session — client sees RST.
				if len(fr.Payload) > 0 {
					return
				}
				// Success ACK — ignore, we're already pumping.
			case mpframe.TypeClose:
				// Flush any buffered out-of-order data before closing.
				// Frames may have been lost during tunnel death; deliver
				// what we have rather than discarding it.
				for _, p := range sess.FlushDedup() {
					if _, werr := client.Write(p); werr != nil {
						return
					}
				}
				return
			}
		}
	}
}

// ----- SOCKS5 server-side helpers -----

func socksHandshake(c net.Conn) (string, error) {
	head := make([]byte, 2)
	if _, err := io.ReadFull(c, head); err != nil {
		return "", err
	}
	if head[0] != 0x05 {
		return "", errors.New("not socks5")
	}
	methods := make([]byte, head[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return "", err
	}
	supported := false
	for _, m := range methods {
		if m == 0x00 {
			supported = true
			break
		}
	}
	if !supported {
		_, _ = c.Write([]byte{0x05, 0xff})
		return "", errors.New("no acceptable auth methods")
	}
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		return "", err
	}

	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil {
		return "", err
	}
	if req[0] != 0x05 {
		return "", errors.New("bad version")
	}
	if req[1] != 0x01 {
		_ = writeConnectReply(c, 0x07)
		return "", errors.New("only CONNECT supported")
	}
	var host string
	switch req[3] {
	case 0x01:
		buf := make([]byte, 4)
		if _, err := io.ReadFull(c, buf); err != nil {
			return "", err
		}
		host = net.IP(buf).String()
	case 0x03:
		ln := make([]byte, 1)
		if _, err := io.ReadFull(c, ln); err != nil {
			return "", err
		}
		buf := make([]byte, ln[0])
		if _, err := io.ReadFull(c, buf); err != nil {
			return "", err
		}
		host = string(buf)
	case 0x04:
		buf := make([]byte, 16)
		if _, err := io.ReadFull(c, buf); err != nil {
			return "", err
		}
		host = net.IP(buf).String()
	default:
		_ = writeConnectReply(c, 0x08)
		return "", errors.New("unknown atyp")
	}
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(c, portBuf); err != nil {
		return "", err
	}
	port := binary.BigEndian.Uint16(portBuf)
	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

func writeConnectReply(c net.Conn, status byte) error {
	_, err := c.Write([]byte{0x05, status, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	return err
}
