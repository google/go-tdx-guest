// Copyright 2026 Google LLC
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

package abi

import (
	"bytes"
	"fmt"
	"testing"

	pb "github.com/google/go-tdx-guest/proto/tdx"
	test "github.com/google/go-tdx-guest/testing/testdata"
	"google.golang.org/protobuf/proto"
)

func TestDiceQuoteToProtoAndAbiBytes(t *testing.T) {
	tcs := []struct {
		name     string
		rawQuote []byte
	}{
		{
			name:     "integration sample dice quote",
			rawQuote: test.RawQuoteDICE,
		},
		{
			name:     "specification example dice quote",
			rawQuote: test.RawQuoteDICESpec,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			anyQuote, err := QuoteToProto(tc.rawQuote)
			if err != nil {
				t.Fatalf("QuoteToProto() failed: %v", err)
			}
			q, ok := anyQuote.(*pb.DiceQuote)
			if !ok {
				t.Fatalf("QuoteToProto() returned %T, want *pb.DiceQuote", anyQuote)
			}
			if err := CheckQuote(q); err != nil {
				t.Errorf("CheckQuote(DiceQuote) returned unexpected error: %v", err)
			}

			// Verify round-trip via RawQuote.
			abiBytes, err := QuoteToAbiBytes(q)
			if err != nil {
				t.Fatalf("QuoteToAbiBytes(DiceQuote) failed: %v", err)
			}
			if !bytes.Equal(tc.rawQuote, abiBytes) {
				t.Errorf("QuoteToAbiBytes(DiceQuote) did not match original raw quote bytes")
			}

			// Verify re-encoding when RawQuote is cleared produces valid CBOR that parses back identically.
			cloned := proto.Clone(q).(*pb.DiceQuote)
			cloned.RawQuote = nil
			reencodedBytes, err := QuoteToAbiBytes(cloned)
			if err != nil {
				t.Fatalf("QuoteToAbiBytes(DiceQuote without RawQuote) failed: %v", err)
			}
			reparsedAny, err := QuoteToProto(reencodedBytes)
			if err != nil {
				t.Fatalf("QuoteToProto(reencodedBytes) failed: %v", err)
			}
			reparsed := reparsedAny.(*pb.DiceQuote)
			reparsed.RawQuote = nil
			if !proto.Equal(cloned, reparsed) {
				t.Errorf("reparsed DiceQuote does not match original")
			}

			// Verify parsing bare COSE_Sign1 (Tag 18 without outer Tag 61) works identically.
			bareCOSE := tc.rawQuote[2:] // Strip outer 0xd8 0x3d (Tag 61)
			if _, err := QuoteToProto(bareCOSE); err != nil {
				t.Errorf("QuoteToProto(bare COSE_Sign1 without Tag 61) failed: %v", err)
			}
		})
	}
}

func TestInvalidDiceQuoteConversionsToAbiBytes(t *testing.T) {
	anyQuote, err := QuoteToProto(test.RawQuoteDICE)
	if err != nil {
		t.Fatalf("QuoteToProto(RawQuoteDICE) failed: %v", err)
	}
	validBody := anyQuote.(*pb.DiceQuote).GetTdQuoteBody()

	tcs := []struct {
		name    string
		quote   *pb.DiceQuote
		wantErr string
	}{
		{
			name:    "DiceQuoteNil",
			quote:   nil,
			wantErr: "DiceQuote invalid: DiceQuote is nil",
		},
		{
			name:    "DiceQuoteEmpty",
			quote:   &pb.DiceQuote{},
			wantErr: "DiceQuote invalid: DiceQuote protectedHeader is empty",
		},
		{
			name: "DiceQuoteUnsupportedAlgorithm",
			quote: &pb.DiceQuote{
				ProtectedHeader: []byte{0xa1, 0x01, 0x26},
				Algorithm:       -7,
			},
			wantErr: fmt.Sprintf("DiceQuote invalid: DiceQuote algorithm -7 not supported, expected %d", coseAlgES384),
		},
		{
			name: "DiceQuoteCertChainEmpty",
			quote: &pb.DiceQuote{
				ProtectedHeader: []byte{0xa1, 0x01, 0x38, 0x22},
				Algorithm:       coseAlgES384,
			},
			wantErr: "DiceQuote invalid: DiceQuote certChain is empty",
		},
		{
			name: "DiceQuoteCertChainElementEmpty",
			quote: &pb.DiceQuote{
				ProtectedHeader: []byte{0xa1, 0x01, 0x38, 0x22},
				Algorithm:       coseAlgES384,
				CertChain:       [][]byte{{}},
			},
			wantErr: "DiceQuote invalid: DiceQuote certChain[0] is empty",
		},
		{
			name: "DiceQuoteRawPayloadEmpty",
			quote: &pb.DiceQuote{
				ProtectedHeader: []byte{0xa1, 0x01, 0x38, 0x22},
				Algorithm:       coseAlgES384,
				CertChain:       [][]byte{{0x01}},
			},
			wantErr: "DiceQuote invalid: DiceQuote rawPayload is empty",
		},
		{
			name: "DiceQuoteTDQuoteBodyNil",
			quote: &pb.DiceQuote{
				ProtectedHeader: []byte{0xa1, 0x01, 0x38, 0x22},
				Algorithm:       coseAlgES384,
				CertChain:       [][]byte{{0x01}},
				RawPayload:      []byte{0xa0},
			},
			wantErr: "DiceQuote invalid: DiceQuote TD Quote Body error: TD quote body is nil",
		},
		{
			name: "DiceQuoteSignatureInvalidSize",
			quote: &pb.DiceQuote{
				ProtectedHeader: []byte{0xa1, 0x01, 0x38, 0x22},
				Algorithm:       coseAlgES384,
				CertChain:       [][]byte{{0x01}},
				RawPayload:      []byte{0xa0},
				TdQuoteBody:     validBody,
				Signature:       []byte{0x01, 0x02},
			},
			wantErr: fmt.Sprintf("DiceQuote invalid: DiceQuote signature size is 2 bytes. Expected %d bytes", DiceSignatureSize),
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := QuoteToAbiBytes(tc.quote); err == nil || err.Error() != tc.wantErr {
				t.Errorf("QuoteToAbiBytes() error = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestDiceQuoteNegativeCases(t *testing.T) {
	validProtected := encodeCBORBytes([]byte{0xa1, 0x01, 0x38, 0x22}) // << {1: -35} >>
	validUnprotected := []byte{0xa1, 0x18, 0x20, 0x81, 0x41, 0x01}    // {32: [h'01']}
	validSig := encodeCBORBytes(make([]byte, 96))

	wrapCWT := func(inner []byte) []byte {
		return append([]byte{0xd8, 0x3d}, inner...)
	}
	wrapCOSE := func(elems ...[]byte) []byte {
		out := append([]byte{0xd2}, encodeCBORHead(cborMajorArray, uint64(len(elems)))...)
		for _, e := range elems {
			out = append(out, e...)
		}
		return wrapCWT(out)
	}

	tcs := []struct {
		name    string
		raw     []byte
		wantErr string
	}{
		{
			name:    "truncated dice quote",
			raw:     test.RawQuoteDICE[:100],
			wantErr: "parsing DICE quote CBOR failed: unexpected EOF reading CBOR byte string of length 923",
		},
		{
			name:    "trailing bytes after CBOR root",
			raw:     append(append([]byte{}, test.RawQuoteDICESpec...), 0x00),
			wantErr: "parsing DICE quote CBOR failed: trailing bytes after CBOR data item: 1 bytes",
		},
		{
			name: "exceed max CBOR nesting depth",
			raw: func() []byte {
				b := []byte{0xd8, 0x3d}
				for i := 0; i < 35; i++ {
					b = append(b, 0xd2)
				}
				return append(b, 0x00)
			}(),
			wantErr: "parsing DICE quote CBOR failed: CBOR maximum nesting depth 32 exceeded",
		},
		{
			name:    "wrong inner tag (not Tag 18 COSE_Sign1)",
			raw:     wrapCWT([]byte{0xd8, 0x63, 0x84, 0x40, 0xa0, 0x40, 0x40}),
			wantErr: "expected CBOR Tag 18 (COSE_Sign1), got majorType=6 tag=99",
		},
		{
			name:    "COSE_Sign1 array wrong element count",
			raw:     wrapCOSE(validProtected, validUnprotected, validSig),
			wantErr: "COSE_Sign1 must be a 4-element CBOR array, got 3 elements",
		},
		{
			name:    "protected header not bstr",
			raw:     wrapCOSE([]byte{0xa0}, validUnprotected, encodeCBORBytes([]byte{0xa0}), validSig),
			wantErr: "COSE_Sign1 protected header must be a byte string",
		},
		{
			name:    "protected header empty",
			raw:     wrapCOSE([]byte{0x40}, validUnprotected, encodeCBORBytes([]byte{0xa0}), validSig),
			wantErr: "parsing COSE_Sign1 protected header failed: protected header is empty",
		},
		{
			name:    "protected header missing alg",
			raw:     wrapCOSE(encodeCBORBytes([]byte{0xa1, 0x02, 0x01}), validUnprotected, encodeCBORBytes([]byte{0xa0}), validSig),
			wantErr: "parsing COSE_Sign1 protected header failed: missing algorithm (key 1) in protected header",
		},
		{
			name:    "unprotected header not map",
			raw:     wrapCOSE(validProtected, []byte{0x40}, encodeCBORBytes([]byte{0xa0}), validSig),
			wantErr: "COSE_Sign1 unprotected header must be a CBOR map",
		},
		{
			name:    "unprotected header missing cert chain",
			raw:     wrapCOSE(validProtected, []byte{0xa1, 0x03, 0x61, 0x61}, encodeCBORBytes([]byte{0xa0}), validSig),
			wantErr: "parsing COSE_Sign1 unprotected header failed: missing certificate chain (key 32 or 33) in unprotected header",
		},
		{
			name:    "payload missing report_data",
			raw:     wrapCOSE(validProtected, validUnprotected, encodeCBORBytes([]byte{0xa1, 0x01, 0x61, 0x61}), validSig),
			wantErr: "parsing DICE CWT payload failed: missing or invalid report_data (claim -212) in CWT payload",
		},
		{
			name: "payload missing submods (-11)",
			raw: wrapCOSE(
				validProtected,
				validUnprotected,
				encodeCBORBytes(append([]byte{0xa1, 0x38, 0xd3}, encodeCBORBytes(make([]byte, 64))...)),
				validSig,
			),
			wantErr: "parsing DICE CWT payload failed: missing or invalid submods map (claim -11) in CWT payload",
		},
		{
			name: "payload missing Platform TCB submodule",
			raw: wrapCOSE(
				validProtected,
				validUnprotected,
				encodeCBORBytes(append(append([]byte{0xa2, 0x38, 0xd3}, encodeCBORBytes(make([]byte, 64))...), 0x2a, 0xa0)),
				validSig,
			),
			wantErr: fmt.Sprintf("parsing DICE CWT payload failed: missing Platform TCB submodule (%s) in CWT payload", diceSubmodPlatformTCBOID1),
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := QuoteToProto(tc.raw); err == nil || err.Error() != tc.wantErr {
				t.Errorf("QuoteToProto() error = %v, want %q", err, tc.wantErr)
			}
		})
	}
}
