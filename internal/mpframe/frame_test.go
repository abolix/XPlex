package mpframe_test

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"xrayrunner/internal/mpframe"
)

func id(b byte) mpframe.SessionID {
	var s mpframe.SessionID
	for i := range s {
		s[i] = b
	}
	return s
}

func TestRoundTripData(t *testing.T) {
	in := mpframe.Frame{
		Type:    mpframe.TypeData,
		Session: id(0xab),
		Seq:     42,
		Payload: []byte("hello world"),
	}
	var buf bytes.Buffer
	if err := mpframe.Write(&buf, in); err != nil {
		t.Fatalf("Write: %v", err)
	}
	out, err := mpframe.Read(&buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if out.Type != in.Type || out.Seq != in.Seq || out.Session != in.Session ||
		!bytes.Equal(out.Payload, in.Payload) {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", out, in)
	}
}

func TestRoundTripEmptyPayload(t *testing.T) {
	in := mpframe.Frame{Type: mpframe.TypeClose, Session: id(0x01), Seq: 7}
	var buf bytes.Buffer
	if err := mpframe.Write(&buf, in); err != nil {
		t.Fatalf("Write: %v", err)
	}
	out, err := mpframe.Read(&buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(out.Payload) != 0 || out.Seq != 7 || out.Type != mpframe.TypeClose ||
		out.Session != in.Session {
		t.Fatalf("got %+v", out)
	}
}

func TestMultipleFramesBackToBack(t *testing.T) {
	var buf bytes.Buffer
	frames := []mpframe.Frame{
		{Type: mpframe.TypeData, Session: id(1), Seq: 1, Payload: []byte("a")},
		{Type: mpframe.TypeData, Session: id(2), Seq: 1, Payload: []byte("bb")},
		{Type: mpframe.TypeData, Session: id(1), Seq: 2, Payload: []byte("ccc")},
	}
	for _, f := range frames {
		if err := mpframe.Write(&buf, f); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	for i, want := range frames {
		got, err := mpframe.Read(&buf)
		if err != nil {
			t.Fatalf("frame %d: Read: %v", i, err)
		}
		if got.Seq != want.Seq || got.Session != want.Session ||
			!bytes.Equal(got.Payload, want.Payload) {
			t.Errorf("frame %d: got %+v, want %+v", i, got, want)
		}
	}
}

func TestPayloadTooLargeOnWrite(t *testing.T) {
	big := make([]byte, mpframe.MaxPayload+1)
	err := mpframe.Write(&bytes.Buffer{}, mpframe.Frame{
		Type:    mpframe.TypeData,
		Payload: big,
	})
	if err == nil {
		t.Fatal("expected error for oversized payload")
	}
}

func TestReadRejectsHugeLengthHeader(t *testing.T) {
	hdr := make([]byte, mpframe.HeaderSize)
	hdr[0] = mpframe.TypeData
	// length field starts at 1 + SessionIDLen + 8 = 25
	hdr[25] = 0x80 // 0x80000000 — way over MaxPayload
	_, err := mpframe.Read(bytes.NewReader(hdr))
	if err == nil {
		t.Fatal("expected error for outsized declared length")
	}
}

func TestReadEOFOnEmptyStream(t *testing.T) {
	_, err := mpframe.Read(bytes.NewReader(nil))
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected io.EOF, got %v", err)
	}
}

func TestReadShortPayload(t *testing.T) {
	var buf bytes.Buffer
	if err := mpframe.Write(&buf, mpframe.Frame{
		Type:    mpframe.TypeData,
		Session: id(7),
		Seq:     1,
		Payload: []byte("0123456789"),
	}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	truncated := buf.Bytes()[:mpframe.HeaderSize+3]
	_, err := mpframe.Read(bytes.NewReader(truncated))
	if err == nil {
		t.Fatal("expected error on truncated payload")
	}
}

func TestEncodeDecodeDest(t *testing.T) {
	dest := "stratum.example.com:3333"
	p, err := mpframe.EncodeDest(dest)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	got, err := mpframe.DecodeDest(p)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got != dest {
		t.Errorf("got %q, want %q", got, dest)
	}
}

func TestEncodeDestTooLong(t *testing.T) {
	long := strings.Repeat("a", mpframe.MaxDestLen+1)
	if _, err := mpframe.EncodeDest(long); err == nil {
		t.Fatal("expected error for oversized dest")
	}
}
