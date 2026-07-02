// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gce

import (
	"bytes"
	"crypto/sha512"
	"strings"
	"testing"

	pb "github.com/google/go-tdx-guest/proto/tdx"
)

func TestPZIDPayload(t *testing.T) {
	info := &InstanceInfo{
		Zone:          "us-central1-a",
		ProjectNumber: 123456789012,
		InstanceID:    112233445566778899,
	}
	got, err := PZIDPayload(info)
	if err != nil {
		t.Fatalf("PZIDPayload() failed: %v", err)
	}
	want := `{"instanceId":112233445566778899,"numericalProjectId":123456789012,"zone":"us-central1-a"}`
	if got != want {
		t.Errorf("PZIDPayload() = %q, want %q", got, want)
	}
}

func TestPZIDPayloadRejectsInvalidZone(t *testing.T) {
	testCases := []struct {
		name string
		zone string
	}{
		{
			name: "Empty zone",
		},
		{
			name: "Invalid zone characters",
			zone: `us-central1-a"`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := PZIDPayload(&InstanceInfo{Zone: tc.zone}); err == nil {
				t.Error("PZIDPayload() succeeded, want error")
			}
		})
	}
}

func TestVerifyPZID(t *testing.T) {
	info := &InstanceInfo{
		Zone:          "us-central1-a",
		ProjectNumber: 123456789012,
		InstanceID:    112233445566778899,
	}
	payload, err := PZIDPayload(info)
	if err != nil {
		t.Fatalf("PZIDPayload() failed: %v", err)
	}
	digest := sha512.Sum384([]byte(payload))
	quote := &pb.QuoteV4{TdQuoteBody: &pb.TDQuoteBody{MrOwner: digest[:]}}

	got, err := VerifyPZID(quote, info)
	if err != nil {
		t.Fatalf("VerifyPZID() failed: %v", err)
	}
	if got.Payload != payload {
		t.Errorf("VerifyPZID().Payload = %q, want %q", got.Payload, payload)
	}
	if !bytes.Equal(got.ExpectedMROwner, digest[:]) {
		t.Errorf("VerifyPZID().ExpectedMROwner = %x, want %x", got.ExpectedMROwner, digest)
	}
}

func TestVerifyPZIDRejectsMismatch(t *testing.T) {
	info := &InstanceInfo{
		Zone:          "us-central1-a",
		ProjectNumber: 123456789012,
		InstanceID:    112233445566778899,
	}
	quote := &pb.QuoteV4{TdQuoteBody: &pb.TDQuoteBody{MrOwner: make([]byte, sha512.Size384)}}
	if _, err := VerifyPZID(quote, info); err == nil {
		t.Fatal("VerifyPZID() succeeded, want mismatch error")
	}
}

func TestMROwnerFromQuoteRejectsQuoteV5(t *testing.T) {
	if _, err := MROwnerFromQuote(&pb.QuoteV5{}); err == nil {
		t.Fatal("MROwnerFromQuote() succeeded, want error")
	} else if !strings.Contains(err.Error(), "supports QuoteV4 only") {
		t.Fatalf("MROwnerFromQuote() error = %q, want QuoteV4-only error", err.Error())
	}
}
