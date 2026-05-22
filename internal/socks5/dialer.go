// Package socks5 implements just enough of the SOCKS5 protocol for our
// local probe and load balancer to reach upstream xray instances.
package socks5

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// Dial opens a TCP connection to socksAddr, performs a no-auth SOCKS5
// handshake, and asks the proxy to CONNECT to targetHost:targetPort.
// On success the returned net.Conn is ready for application traffic.
//
// targetHost may be an IPv4 string, IPv6 string, or domain name.
func Dial(socksAddr, targetHost string, targetPort uint16, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	c, err := d.Dial("tcp", socksAddr)
	if err != nil {
		return nil, fmt.Errorf("dial socks: %w", err)
	}
	if err := c.SetDeadline(time.Now().Add(timeout)); err != nil {
		_ = c.Close()
		return nil, err
	}

	// Greeting: ver=5, nmethods=1, methods=[0x00 no-auth].
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("greet: %w", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(c, resp); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("greet read: %w", err)
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		_ = c.Close()
		return nil, fmt.Errorf("socks auth refused: %v", resp)
	}

	// CONNECT request: pick the right ATYP based on what targetHost looks like.
	req, err := buildConnectRequest(targetHost, targetPort)
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	if _, err := c.Write(req); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("connect req: %w", err)
	}

	// CONNECT reply header.
	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("connect reply: %w", err)
	}
	if head[1] != 0x00 {
		_ = c.Close()
		return nil, fmt.Errorf("socks connect failed (rep=%d)", head[1])
	}

	// Drain the bound-address (variable length per atyp) + 2-byte port.
	switch head[3] {
	case 0x01:
		_, err = io.ReadFull(c, make([]byte, 4+2))
	case 0x03:
		ln := make([]byte, 1)
		if _, err = io.ReadFull(c, ln); err == nil {
			_, err = io.ReadFull(c, make([]byte, int(ln[0])+2))
		}
	case 0x04:
		_, err = io.ReadFull(c, make([]byte, 16+2))
	default:
		err = fmt.Errorf("unknown atyp %d", head[3])
	}
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("connect reply addr: %w", err)
	}

	// Caller takes over deadline management.
	_ = c.SetDeadline(time.Time{})
	return c, nil
}

// buildConnectRequest formats a SOCKS5 CONNECT request, picking IPv4/IPv6/domain.
func buildConnectRequest(host string, port uint16) ([]byte, error) {
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, port)

	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req := append([]byte{0x05, 0x01, 0x00, 0x01}, v4...)
			return append(req, portBytes...), nil
		}
		if v6 := ip.To16(); v6 != nil {
			req := append([]byte{0x05, 0x01, 0x00, 0x04}, v6...)
			return append(req, portBytes...), nil
		}
	}

	if len(host) > 255 {
		return nil, errors.New("host too long")
	}
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, []byte(host)...)
	return append(req, portBytes...), nil
}

