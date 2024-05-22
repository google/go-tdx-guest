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

package extend

import (
	"crypto"
	"fmt"
	"path"
	"strconv"
	"testing"

	"github.com/google/go-configfs-tsm/configfs/configfsi"
)

type RtmtFakeSubsystem struct {
	RtmrIndex int
}

func (r *RtmtFakeSubsystem) RemoveAll(name string) error {
	p, err := configfsi.ParseTsmPath(name)
	if err != nil {
		return fmt.Errorf("RemoveAll: Error %v", err)
	}
	if p.Attribute != "" || p.Entry == "" || p.Subsystem != RtmrSubsystem {
		return fmt.Errorf("RemoveAll: expected RTMR subsystem. Subsystem: %q Entry %q Attribute %q", p.Subsystem, p.Entry, p.Attribute)
	}
	return nil
}

func (r *RtmtFakeSubsystem) MkdirTemp(dir, pattern string) (string, error) {
	_, err := configfsi.ParseTsmPath(dir)
	if err != nil {
		return "", fmt.Errorf("MkdirTemp: Error %v", err)
	}
	return path.Join(dir, pattern), nil
}

func (r *RtmtFakeSubsystem) ReadFile(name string) ([]byte, error) {
	p, err := configfsi.ParseTsmPath(name)
	if err != nil {
		return nil, fmt.Errorf("ReadFile: Error %v", err)
	}
	if p.Attribute != TsmPathTcgMap {
		return nil, fmt.Errorf("ReadFile expected rtmr attribute %q", p.Attribute)
	}
	var rtmrPcrMaps = map[int]string{
		0: "1,7\n",
		1: "2-6\n",
		2: "8-15\n",
		3: "\n",
	}
	return []byte(rtmrPcrMaps[r.RtmrIndex]), nil
}

func (c *RtmtFakeSubsystem) WriteFile(name string, content []byte) error {
	p, err := configfsi.ParseTsmPath(name)
	if err != nil {
		return fmt.Errorf("WriteFile: %v", err)
	}
	if p.Entry == "" || p.Subsystem != RtmrSubsystem {
		return fmt.Errorf("WriteFile(%q) expected RTMR subsystem entry path", name)
	}
	if p.Attribute == TsmRtmrDigest {
		if c.RtmrIndex < 0 || c.RtmrIndex > 3 {
			return fmt.Errorf("WriteFile(%q) invalid RTMR index %d. Index can only be 0-3", name, c.RtmrIndex)
		}
		if len(content) != int(crypto.SHA384.Size()) {
			return fmt.Errorf("WriteFile(%q) expected %d bytes, got %d", name, crypto.SHA384.Size(), len(content))
		}
		return nil
	} else if p.Attribute == TsmPathIndex {
		num, err := strconv.Atoi(string(content))
		if err == nil {
			c.RtmrIndex = num
			return nil
		}
	}
	return fmt.Errorf("WriteFile(%q) expected RTMR attribute entry path", p.Attribute)
}

func makeFakeRTMRClient() configfsi.Client {
	return &RtmtFakeSubsystem{}
}

func TestExtendtoRtmr(t *testing.T) {
	client := makeFakeRTMRClient()
	err := ExtendtoRtmrClient(client, 2, crypto.SHA384, []byte("hash"))
	if err != nil {
		t.Errorf("ExtendtoRtmrClient failed: %v", err)
	}
	if client.(*RtmtFakeSubsystem).RtmrIndex != 2 {
		t.Errorf("ExtendtoRtmrClient failed: expected index 2, got %d", client.(*RtmtFakeSubsystem).RtmrIndex)
	}
}

func TestExtendtoRtmrErr(t *testing.T) {
	tcs := []struct {
		rtmr     int
		crypto   crypto.Hash
		eventlog []byte
		wantErr  string
	}{
		{rtmr: 5, crypto: crypto.SHA384, eventlog: []byte("event log"), wantErr: "invalid RTMR index 5. Index can only be 0-3"},
		{rtmr: 2, crypto: crypto.SHA256, eventlog: []byte("event log"), wantErr: "unsupported hash algorithm SHA-256"},
		{rtmr: 1, crypto: crypto.SHA384, eventlog: []byte("event log"), wantErr: "invalid  index 1, userspace can only extend to rtmr2 or rtmr3"},
		{rtmr: 3, crypto: crypto.SHA384, eventlog: []byte(""), wantErr: "input event log is empty"},
	}
	client := makeFakeRTMRClient()
	for _, tc := range tcs {
		err := ExtendtoRtmrClient(client, tc.rtmr, tc.crypto, tc.eventlog)
		if err == nil || err.Error() != tc.wantErr {
			t.Fatalf("ExtendtoRtmrClient(%d, %v, %q) failed: %v, want %q", tc.rtmr, tc.crypto, tc.eventlog, err, tc.wantErr)
		}
	}
}
