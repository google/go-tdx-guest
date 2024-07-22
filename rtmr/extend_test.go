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
