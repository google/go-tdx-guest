// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package rtmr

import (
	"crypto"
	"strings"
	"testing"

	"github.com/google/go-configfs-tsm/configfs/fakertmr"

	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	// Import for the side-effect of registering the SHA384 hash algorithm.
	_ "golang.org/x/crypto/sha3"
)

func TestExtendEventLogOk(t *testing.T) {
	client := fakertmr.CreateRtmrSubsystem(t.TempDir())
	err := ExtendEventLogClient(client, 2, crypto.SHA384, []byte("event log"))
	if err != nil {
		t.Errorf("ExtendEventlog failed: %v", err)
	}
}

func TestExtendDigestOk(t *testing.T) {
	client := fakertmr.CreateRtmrSubsystem(t.TempDir())
	var sha384Hash [48]byte
	err := ExtendDigestClient(client, 2, sha384Hash[:])
	if err != nil {
		t.Errorf("ExtendDigest failed: %v", err)
	}
}

func TestExtendEventLogErr(t *testing.T) {
	tcs := []struct {
		rtmr     int
		crypto   crypto.Hash
		eventlog []byte
		wantErr  string
	}{
		{rtmr: 2, crypto: crypto.SHA256, eventlog: []byte("event log"), wantErr: "unsupported hash algorithm SHA-256"},
		{rtmr: 4, crypto: crypto.SHA384, eventlog: []byte("event log"), wantErr: "index can only be 0-3"},
		{rtmr: 3, crypto: crypto.SHA384, eventlog: []byte(""), wantErr: "input event log is empty"},
	}
	client := fakertmr.CreateRtmrSubsystem(t.TempDir())
	for _, tc := range tcs {
		err := ExtendEventLogClient(client, tc.rtmr, tc.crypto, tc.eventlog)
		if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Fatalf("ExtendEventLog(%d, %v, %q) failed: %v, want %q", tc.rtmr, tc.crypto, tc.eventlog, err, tc.wantErr)
		}
	}
}

func TestExtendDigestErr(t *testing.T) {
	var sha384Hash [48]byte
	var sha512Hash [64]byte
	tcs := []struct {
		rtmr    int
		digest  []byte
		wantErr string
	}{
		{rtmr: 4, digest: sha384Hash[:], wantErr: "index can only be 0-3"},
		{rtmr: 3, digest: sha512Hash[:], wantErr: "sha384 digest should be 48 bytes"},
	}
	client := fakertmr.CreateRtmrSubsystem(t.TempDir())
	for _, tc := range tcs {
		err := ExtendDigestClient(client, tc.rtmr, tc.digest)
		if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Fatalf("ExtendDigest(%d, %v) failed: %v, want %q", tc.rtmr, tc.digest, err, tc.wantErr)
		}
	}
}

// TestRtmrExtendVerification performs multiple rounds of extending an RTMR and verifies the result.
// It reads the initial state, calls ExtendDigestSysfs to perform the hardware extension,
// and compares the new hardware state against a software-simulated extension.
func TestRtmrExtendVerification(t *testing.T) {
	testCases := []struct {
		name      string
		rtmrIndex int
		hashAlgo  crypto.Hash
	}{
		{"RTMR0_SHA384", 0, crypto.SHA384},
		{"RTMR1_SHA384", 1, crypto.SHA384},
		{"RTMR2_SHA384", 2, crypto.SHA384},
		{"RTMR3_SHA384", 3, crypto.SHA384},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			filePath := fmt.Sprintf("/sys/class/misc/tdx_guest/measurements/rtmr%d:sha384", tc.rtmrIndex)
			digestSize := tc.hashAlgo.Size()

			if _, err := os.Stat(filePath); os.IsNotExist(err) {
				t.Skipf("skipping test: RTMR sysfs file not found at %s", filePath)
			}

			for i := 0; i < 10; i++ {
				initialData, err := os.ReadFile(filePath)
				if err != nil {
					t.Fatalf("Round %d: failed to read original digest from %s: %v", i+1, filePath, err)
				}

				hasher := tc.hashAlgo.New()
				// Check the size of the initial data before using it.
				// For a SHA384-based RTMR, the existing data should be a valid SHA384 digest.
				if len(initialData) != crypto.SHA384.Size() {
					t.Fatalf("Round %d: initial data from %s has incorrect size: got %d bytes, want %d bytes",
						i+1, filePath, len(initialData), crypto.SHA384.Size())
				}
				hasher.Write(initialData)

				eventDigest := make([]byte, digestSize)
				if _, err := rand.Read(eventDigest); err != nil {
					t.Fatalf("Round %d: error generating random data: %v", i+1, err)
				}

				hasher.Write(eventDigest)
				wantDigest := hasher.Sum(nil)

				if err := ExtendDigestSysfs(tc.rtmrIndex, eventDigest); err != nil {
					t.Fatalf("Round %d: error extending RTMR via sysfs: %v", i+1, err)
				}

				gotDigest, err := os.ReadFile(filePath)
				if err != nil {
					t.Fatalf("Round %d: failed to read back from %s for verification: %v", i+1, filePath, err)
				}

				if !bytes.Equal(wantDigest, gotDigest) {
					t.Errorf("Round %d: VERIFICATION FAILED:\n  Expected: %s\n  Got:      %s",
						i+1, hex.EncodeToString(wantDigest), hex.EncodeToString(gotDigest))
				}
			}
		})
	}
}
