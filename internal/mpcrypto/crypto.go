// Package mpcrypto wraps each mpframe write with ChaCha20-Poly1305
// authenticated encryption using a pre-shared key.
//
// Threat model: a malicious xray operator sits between client and
// mp-server. They see the raw bytes, can drop them, can re-order
// them, can replay them. They cannot read or modify them undetected
// because they don't know the PSK.
//
// On the wire, every frame becomes:
//
//	+------------+------------------------------------+
//	| nonce (12) | ciphertext + Poly1305 tag (16) ... |
//	+------------+------------------------------------+
//	| 4 byte u32 length prefix in front of all of it  |
//	+-------------------------------------------------+
//
// So the framing is: [u32 frame_len][12 byte nonce][ciphertext+tag].
// Length prefix is necessary because we no longer have a fixed-size
// header to anchor framing on the receive side.
package mpcrypto

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

// KeySize is the PSK length in bytes.
const KeySize = chacha20poly1305.KeySize // 32

// NonceSize is the per-frame nonce length.
const NonceSize = chacha20poly1305.NonceSize // 12

// Overhead is the AEAD tag length added to every frame.
const Overhead = chacha20poly1305.Overhead // 16

// MaxCipherFrame caps a single ciphertext frame so a malicious peer
// cannot ask us to allocate gigabytes.
const MaxCipherFrame = 1 << 24 // 16 MiB

// readBufPool recycles read buffers to reduce GC pressure (#7).
var readBufPool = sync.Pool{
	New: func() any {
		// Start with a 32KB buffer; will grow if needed.
		b := make([]byte, 32*1024)
		return &b
	},
}

// Codec is a per-direction AEAD that encrypts whole-frame mpframe blobs.
// Safe for use by one writer goroutine and one reader goroutine.
type Codec struct {
	aead cipher.AEAD
}

// New returns a Codec using the given 32-byte key.
func New(key []byte) (*Codec, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("psk must be %d bytes, got %d", KeySize, len(key))
	}
	a, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return &Codec{aead: a}, nil
}

// WriteFrame seals plaintext and writes one length-prefixed frame to w.
//
// #6: Single write call — header (4 byte len + 12 byte nonce) and
// ciphertext are combined into one buffer to avoid TCP small-segment
// issues and reduce syscalls.
func (c *Codec) WriteFrame(w io.Writer, plaintext []byte) error {
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	ct := c.aead.Seal(nil, nonce, plaintext, nil)
	total := len(nonce) + len(ct)
	if total > MaxCipherFrame {
		return fmt.Errorf("frame too large: %d > %d", total, MaxCipherFrame)
	}
	// Single combined write: [u32 len][nonce][ciphertext+tag]
	buf := make([]byte, 4+total)
	binary.BigEndian.PutUint32(buf[:4], uint32(total))
	copy(buf[4:4+NonceSize], nonce)
	copy(buf[4+NonceSize:], ct)
	_, err := w.Write(buf)
	return err
}

// ReadFrame reads one length-prefixed encrypted frame from r and
// returns the decrypted plaintext.
//
// #7: Uses a buffer pool to reduce per-frame allocations.
// Returns io.EOF if the stream ends cleanly between frames.
func (c *Codec) ReadFrame(r io.Reader) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	total := int(binary.BigEndian.Uint32(lenBuf[:]))
	if total < NonceSize+Overhead {
		return nil, fmt.Errorf("frame too small: %d", total)
	}
	if total > MaxCipherFrame {
		return nil, fmt.Errorf("frame too large: %d > %d", total, MaxCipherFrame)
	}

	// Get a buffer from the pool; grow if needed.
	bp := readBufPool.Get().(*[]byte)
	body := *bp
	if cap(body) < total {
		body = make([]byte, total)
	} else {
		body = body[:total]
	}

	if _, err := io.ReadFull(r, body); err != nil {
		*bp = body
		readBufPool.Put(bp)
		return nil, err
	}
	nonce := body[:NonceSize]
	ct := body[NonceSize:]
	pt, err := c.aead.Open(nil, nonce, ct, nil)

	// Return the buffer to the pool.
	*bp = body
	readBufPool.Put(bp)

	if err != nil {
		return nil, errors.New("authentication failed (psk mismatch or tamper)")
	}
	return pt, nil
}

