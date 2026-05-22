package testutil

import (
	"testing"

	"xplex/internal/mpcrypto"
)

// TestCodec returns a Codec built from a fixed all-zeros PSK. Tests
// that need to share a key between client and server should both call
// this; production code uses real random keys.
func TestCodec(t *testing.T) *mpcrypto.Codec {
	t.Helper()
	key := make([]byte, mpcrypto.KeySize)
	c, err := mpcrypto.New(key)
	if err != nil {
		t.Fatalf("test codec: %v", err)
	}
	return c
}

