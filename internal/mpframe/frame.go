// Package mpframe defines the wire format used between the multipath
// client and server.
//
// Every byte exchanged between the two sides is wrapped in a Frame.
// The header is fixed 29 bytes:
//
//	+--------+--------------------+--------------------+--------------------+
//	|  type  |  session ID (16B)  |  seqno (u64 BE)    |  payload len (u32) |
//	|  1 B   |        16 B        |       8 B          |       4 B          |
//	+--------+--------------------+--------------------+--------------------+
//	|                       payload (length B)                              |
//	+-----------------------------------------------------------------------+
//
// Sequence numbers are scoped per (session, direction). A HELLO frame
// carries a destination string in its payload. HELLO_ACK echoes the
// session ID and carries an empty payload on success or an error
// message on failure.
//
// Tunnels are long-lived and shared across many sessions; the session
// ID is what routes a frame to the right session state.
package mpframe

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Frame types. Wire-stable; do not renumber.
const (
	TypeHello    byte = 0x01 // HELLO + payload = destination string
	TypeHelloAck byte = 0x02 // HELLO_ACK; empty payload = success, non-empty = error message
	TypeData     byte = 0x03 // DATA payload for a session
	TypeClose    byte = 0x04 // session-level close (flush and end)
	TypePing     byte = 0x05 // tunnel-level keepalive (later)
	TypePong     byte = 0x06 // tunnel-level keepalive reply (later)
)

// HeaderSize is the fixed number of bytes preceding the payload.
const HeaderSize = 1 + 16 + 8 + 4

// MaxPayload caps per-frame payload to defend against malicious peers.
const MaxPayload = 1 << 20 // 1 MiB

// SessionIDLen is the length of a session ID in bytes.
const SessionIDLen = 16

// MaxDestLen caps the destination string in a HELLO payload. SOCKS5
// hostnames go up to 255 bytes; 512 is plenty even with ":port".
const MaxDestLen = 512

// SessionID is a 16-byte random token that identifies a logical session.
type SessionID [SessionIDLen]byte

// Frame is a decoded wire frame.
type Frame struct {
	Type    byte
	Session SessionID
	Seq     uint64
	Payload []byte
}

// Write serializes f and writes it as a single Write call. The caller
// is responsible for serializing concurrent writes against the same
// underlying conn (the mptun writer goroutine handles this).
func Write(w io.Writer, f Frame) error {
	if len(f.Payload) > MaxPayload {
		return fmt.Errorf("payload too large: %d > %d", len(f.Payload), MaxPayload)
	}
	buf := make([]byte, HeaderSize+len(f.Payload))
	buf[0] = f.Type
	copy(buf[1:1+SessionIDLen], f.Session[:])
	binary.BigEndian.PutUint64(buf[1+SessionIDLen:1+SessionIDLen+8], f.Seq)
	binary.BigEndian.PutUint32(buf[1+SessionIDLen+8:HeaderSize], uint32(len(f.Payload)))
	copy(buf[HeaderSize:], f.Payload)
	_, err := w.Write(buf)
	return err
}

// Read decodes a single frame from r. Returns io.EOF if the stream
// ends cleanly between frames; any other error indicates a broken
// stream and the caller should close the tunnel.
func Read(r io.Reader) (Frame, error) {
	var hdr [HeaderSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Frame{}, err
	}
	plen := binary.BigEndian.Uint32(hdr[1+SessionIDLen+8 : HeaderSize])
	if plen > MaxPayload {
		return Frame{}, fmt.Errorf("payload too large: %d > %d", plen, MaxPayload)
	}
	f := Frame{
		Type: hdr[0],
		Seq:  binary.BigEndian.Uint64(hdr[1+SessionIDLen : 1+SessionIDLen+8]),
	}
	copy(f.Session[:], hdr[1:1+SessionIDLen])
	if plen > 0 {
		f.Payload = make([]byte, plen)
		if _, err := io.ReadFull(r, f.Payload); err != nil {
			return Frame{}, err
		}
	}
	return f, nil
}

// EncodeDest puts the destination string into a HELLO payload. The
// caller fills Frame.Session separately. There is intentionally no
// session ID inside the payload — that lives in the header now.
func EncodeDest(dest string) ([]byte, error) {
	if len(dest) > MaxDestLen {
		return nil, fmt.Errorf("destination too long: %d > %d", len(dest), MaxDestLen)
	}
	return []byte(dest), nil
}

// DecodeDest extracts the destination string from a HELLO payload.
func DecodeDest(p []byte) (string, error) {
	if len(p) > MaxDestLen {
		return "", errors.New("destination too long")
	}
	return string(p), nil
}
