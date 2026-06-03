package abi

import "testing"

// Regression test for the out-of-bounds slice in qeAuthDataToProto. A QE AuthData
// buffer whose declared ParsedDataSize exceeds the bytes actually present must return
// an error rather than panic. Before the fix, data[authDataStart:authDataEnd] sliced
// past the end of the buffer and panicked the parser (and, through QuoteToProto /
// verify.RawTdxQuote, the whole verifier) instead of rejecting the malformed quote.
func TestQeAuthDataParsedDataSizeOutOfBounds(t *testing.T) {
	// First two bytes = ParsedDataSize (little-endian) = 0xFFFF, with no payload bytes
	// after it: authDataEnd = 0x02 + 0xFFFF = 0x10001, far past len(data) = 2.
	if _, _, err := qeAuthDataToProto([]byte{0xFF, 0xFF}); err == nil {
		t.Fatal("expected error for out-of-bounds ParsedDataSize, got nil (slice would panic before the fix)")
	}
}

// A buffer that cannot even hold the 2-byte ParsedDataSize field must also return an
// error rather than panic on the size-field read.
func TestQeAuthDataBufferTooShort(t *testing.T) {
	if _, _, err := qeAuthDataToProto([]byte{0x00}); err == nil {
		t.Fatal("expected error for too-short QE AuthData buffer, got nil")
	}
}
