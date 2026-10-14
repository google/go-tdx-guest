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
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	pb "github.com/google/go-tdx-guest/proto/tdx"
	test "github.com/google/go-tdx-guest/testing/testdata"
	"github.com/veraison/go-cose"
	"google.golang.org/protobuf/proto"
)

// DER-encoded OID bytes (without tag/length) for "2.16.840.1.113741.1.16.1".
var testEatProfileDEROID = []byte{0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x4d, 0x01, 0x10, 0x01}

func buildTestDiceQuoteCBOR(t *testing.T, protected map[any]any, unprotected map[any]any, payload any, sig []byte, wrapTag61 bool) []byte {
	t.Helper()
	protectedBytes := []byte{}
	if len(protected) > 0 {
		var err error
		protectedBytes, err = diceCBOREncMode.Marshal(protected)
		if err != nil {
			t.Fatalf("failed to marshal protected header map: %v", err)
		}
	}
	rawProtected, err := diceCBOREncMode.Marshal(protectedBytes)
	if err != nil {
		t.Fatalf("failed to marshal protected header bstr: %v", err)
	}
	rawUnprotected, err := diceCBOREncMode.Marshal(unprotected)
	if err != nil {
		t.Fatalf("failed to marshal unprotected header map: %v", err)
	}
	var payloadBytes []byte
	if b, ok := payload.([]byte); ok {
		payloadBytes = b
	} else {
		payloadBytes, err = diceCBOREncMode.Marshal(payload)
		if err != nil {
			t.Fatalf("failed to marshal payload: %v", err)
		}
	}
	coseArray := []any{
		cbor.RawMessage(rawProtected),
		cbor.RawMessage(rawUnprotected),
		payloadBytes,
		sig,
	}
	coseArrayBytes, err := diceCBOREncMode.Marshal(coseArray)
	if err != nil {
		t.Fatalf("failed to marshal COSE_Sign1 array: %v", err)
	}
	coseTagged, err := cbor.RawTag{
		Number:  cose.CBORTagSign1Message,
		Content: coseArrayBytes,
	}.MarshalCBOR()
	if err != nil {
		t.Fatalf("failed to marshal Tag 18: %v", err)
	}
	if !wrapTag61 {
		return coseTagged
	}
	out, err := cbor.RawTag{
		Number:  cborTagCWT,
		Content: coseTagged,
	}.MarshalCBOR()
	if err != nil {
		t.Fatalf("failed to marshal Tag 61: %v", err)
	}
	return out
}

func TestIsDiceQuoteBytes(t *testing.T) {
	if !isDiceQuoteBytes(test.RawQuoteDICE) {
		t.Errorf("isDiceQuoteBytes(RawQuoteDICE) = false, want true")
	}
	if !isDiceQuoteBytes(test.RawQuoteDICE[2:]) {
		t.Errorf("isDiceQuoteBytes(bare COSE_Sign1) = false, want true")
	}
	if isDiceQuoteBytes(test.RawQuote) {
		t.Errorf("isDiceQuoteBytes(RawQuote V4) = true, want false")
	}
	if isDiceQuoteBytes([]byte{0xd8}) {
		t.Errorf("isDiceQuoteBytes(1 byte) = true, want false")
	}
}

func TestParseAndEncodeDiceQuoteEnvelope(t *testing.T) {
	validReportData := bytes.Repeat([]byte{0xab}, ReportDataSize)
	validSig := bytes.Repeat([]byte{0xcd}, diceSignatureSize)

	specStyleQuote := buildTestDiceQuoteCBOR(
		t,
		map[any]any{
			cose.HeaderLabelAlgorithm: cose.AlgorithmES384,
			cose.HeaderLabelCritical:  []any{cose.HeaderLabelAlgorithm},
		},
		map[any]any{
			cose.HeaderLabelContentType: diceContentType,
			cose.HeaderLabelKeyID:       []byte{0x01, 0x02, 0x03, 0x04},
			cose.HeaderLabelX5Chain:     []byte{0x30, 0x82, 0x01, 0x00},
		},
		map[any]any{
			cwtClaimIss:        "DICE Intel TDX TD Attestation",
			cwtClaimSub:        "TEE Quote / Attestation Evidence",
			cwtClaimEatProfile: testEatProfileDEROID,
			cwtClaimReportData: validReportData,
		},
		validSig,
		true,
	)

	tcs := []struct {
		name     string
		rawQuote []byte
	}{
		{
			name:     "sample dice quote",
			rawQuote: test.RawQuoteDICE,
		},
		{
			name:     "specification example dice quote",
			rawQuote: test.RawQuoteDICESpec,
		},
		{
			name:     "bare COSE_Sign1 without outer Tag 61",
			rawQuote: test.RawQuoteDICE[2:],
		},
		{
			name:     "spec style quote with DER OID eat_profile, crit, and single-cert x5chain",
			rawQuote: specStyleQuote,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			quote, claims, err := parseDiceQuoteEnvelope(tc.rawQuote)
			if err != nil {
				t.Fatalf("parseDiceQuoteEnvelope() failed: %v", err)
			}
			if len(claims) == 0 {
				t.Fatalf("parseDiceQuoteEnvelope() returned empty claims map")
			}
			if err := checkDiceQuoteEnvelope(quote); err != nil {
				t.Fatalf("checkDiceQuoteEnvelope() failed: %v", err)
			}
			if quote.GetEatProfile() != diceEatProfileOID {
				t.Errorf("quote.GetEatProfile() = %q, want %q", quote.GetEatProfile(), diceEatProfileOID)
			}

			encoded, err := encodeDiceQuoteCBOR(quote)
			if err != nil {
				t.Fatalf("encodeDiceQuoteCBOR() failed: %v", err)
			}
			reparsed, _, err := parseDiceQuoteEnvelope(encoded)
			if err != nil {
				t.Fatalf("parseDiceQuoteEnvelope(encoded) failed: %v", err)
			}
			if !proto.Equal(quote, reparsed) {
				t.Errorf("reparsed DiceQuote does not match original")
			}
		})
	}
}

func TestCheckAndEncodeDiceQuoteEnvelopeNegative(t *testing.T) {
	baseQuote, _, err := parseDiceQuoteEnvelope(test.RawQuoteDICE)
	if err != nil {
		t.Fatalf("parseDiceQuoteEnvelope(RawQuoteDICE) failed: %v", err)
	}

	mutate := func(fn func(*pb.DiceQuote)) *pb.DiceQuote {
		q := proto.Clone(baseQuote).(*pb.DiceQuote)
		fn(q)
		return q
	}

	tcs := []struct {
		name    string
		quote   *pb.DiceQuote
		wantErr string
	}{
		{
			name:    "nil quote",
			quote:   nil,
			wantErr: "DiceQuote is nil",
		},
		{
			name:    "empty protected header",
			quote:   mutate(func(q *pb.DiceQuote) { q.ProtectedHeader = nil }),
			wantErr: "DiceQuote protectedHeader is empty",
		},
		{
			name:    "unsupported algorithm",
			quote:   mutate(func(q *pb.DiceQuote) { q.Algorithm = int64(cose.AlgorithmES256) }),
			wantErr: "DiceQuote algorithm -7 not supported, expected -35",
		},
		{
			name:    "unsupported content type",
			quote:   mutate(func(q *pb.DiceQuote) { q.ContentType = "application/json" }),
			wantErr: `DiceQuote contentType "application/json" not supported`,
		},
		{
			name:    "empty cert chain",
			quote:   mutate(func(q *pb.DiceQuote) { q.CertChain = nil }),
			wantErr: "DiceQuote certChain is empty",
		},
		{
			name:    "empty cert element",
			quote:   mutate(func(q *pb.DiceQuote) { q.CertChain = [][]byte{{}} }),
			wantErr: "DiceQuote certChain[0] is empty",
		},
		{
			name:    "empty raw payload",
			quote:   mutate(func(q *pb.DiceQuote) { q.RawPayload = nil }),
			wantErr: "DiceQuote rawPayload is empty",
		},
		{
			name:    "invalid eat profile",
			quote:   mutate(func(q *pb.DiceQuote) { q.EatProfile = "1.2.3.4" }),
			wantErr: `DiceQuote eatProfile "1.2.3.4" not supported`,
		},
		{
			name:    "nil TDQuoteBody",
			quote:   mutate(func(q *pb.DiceQuote) { q.TdQuoteBody = nil }),
			wantErr: "DiceQuote TD Quote Body error: TD quote body is nil",
		},
		{
			name:    "invalid reportData size",
			quote:   mutate(func(q *pb.DiceQuote) { q.TdQuoteBody.ReportData = []byte{0x01} }),
			wantErr: "DiceQuote reportData size is 1 bytes. Expected 64 bytes",
		},
		{
			name:    "invalid signature size",
			quote:   mutate(func(q *pb.DiceQuote) { q.Signature = []byte{0x01, 0x02} }),
			wantErr: "DiceQuote signature size is 2 bytes. Expected 96 bytes",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := encodeDiceQuoteCBOR(tc.quote); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("encodeDiceQuoteCBOR() error = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}

func TestParseDiceQuoteEnvelopeNegative(t *testing.T) {
	validProtected := map[any]any{cose.HeaderLabelAlgorithm: cose.AlgorithmES384}
	validUnprotected := map[any]any{
		cose.HeaderLabelContentType: diceContentType,
		cose.HeaderLabelX5Bag:       [][]byte{{0x01}},
	}
	validPayload := map[any]any{
		cwtClaimEatProfile: testEatProfileDEROID,
		cwtClaimReportData: make([]byte, ReportDataSize),
	}
	validSig := make([]byte, diceSignatureSize)

	tcs := []struct {
		name    string
		raw     []byte
		wantErr string
	}{
		{
			name:    "empty input",
			raw:     nil,
			wantErr: ErrRawQuoteEmpty.Error(),
		},
		{
			name:    "truncated CBOR",
			raw:     test.RawQuoteDICE[:64],
			wantErr: "parsing DICE quote CBOR failed",
		},
		{
			name:    "trailing bytes after CBOR root",
			raw:     append(append([]byte{}, test.RawQuoteDICE...), 0x00),
			wantErr: "parsing DICE quote CBOR failed",
		},
		{
			name: "exceed max CBOR nesting depth",
			raw: func() []byte {
				b := []byte{0xd8, 0x3d}
				for i := 0; i < maxCBORDepth+2; i++ {
					b = append(b, 0xd2)
				}
				return append(b, 0x00)
			}(),
			wantErr: "parsing DICE quote CBOR failed",
		},
		{
			name:    "unexpected outer CBOR tag",
			raw:     []byte{0xd8, 0x63, 0x84, 0x40, 0xa0, 0x40, 0x40},
			wantErr: "expected CBOR Tag 61 (CWT) or 18 (COSE_Sign1), got tag 99",
		},
		{
			name:    "empty protected header",
			raw:     buildTestDiceQuoteCBOR(t, nil, validUnprotected, validPayload, validSig, true),
			wantErr: "protected header is empty",
		},
		{
			name:    "missing algorithm in protected header",
			raw:     buildTestDiceQuoteCBOR(t, map[any]any{int64(99): 1}, validUnprotected, validPayload, validSig, true),
			wantErr: "missing or invalid algorithm (key 1) in protected header",
		},
		{
			name:    "unsupported algorithm ES256 in protected header",
			raw:     buildTestDiceQuoteCBOR(t, map[any]any{cose.HeaderLabelAlgorithm: cose.AlgorithmES256}, validUnprotected, validPayload, validSig, true),
			wantErr: "unsupported algorithm -7 in protected header, expected -35 (ES384)",
		},
		{
			name: "unsupported critical header label in protected header",
			raw: buildTestDiceQuoteCBOR(
				t,
				map[any]any{
					cose.HeaderLabelAlgorithm: cose.AlgorithmES384,
					cose.HeaderLabelKeyID:     []byte{0x01},
					cose.HeaderLabelCritical:  []any{cose.HeaderLabelKeyID},
				},
				validUnprotected,
				validPayload,
				validSig,
				true,
			),
			wantErr: "unsupported critical header label 4 in protected header",
		},
		{
			name: "crit header present in unprotected header",
			raw: buildTestDiceQuoteCBOR(
				t,
				validProtected,
				map[any]any{
					cose.HeaderLabelCritical: []any{cose.HeaderLabelAlgorithm},
					cose.HeaderLabelX5Bag:    [][]byte{{0x01}},
				},
				validPayload,
				validSig,
				true,
			),
			wantErr: "crit: not allowed",
		},
		{
			name: "both x5bag and x5chain in unprotected header",
			raw: buildTestDiceQuoteCBOR(
				t,
				validProtected,
				map[any]any{
					cose.HeaderLabelX5Bag:   [][]byte{{0x01}},
					cose.HeaderLabelX5Chain: [][]byte{{0x01}},
				},
				validPayload,
				validSig,
				true,
			),
			wantErr: "must not contain both x5bag (key 32) and x5chain (key 33)",
		},
		{
			name:    "missing certificate chain in unprotected header",
			raw:     buildTestDiceQuoteCBOR(t, validProtected, map[any]any{cose.HeaderLabelContentType: diceContentType}, validPayload, validSig, true),
			wantErr: "missing certificate chain (key 32 or 33) in unprotected header",
		},
		{
			name:    "empty certificate chain array in unprotected header",
			raw:     buildTestDiceQuoteCBOR(t, validProtected, map[any]any{cose.HeaderLabelX5Bag: []any{}}, validPayload, validSig, true),
			wantErr: "certificate chain in unprotected header is empty",
		},
		{
			name:    "empty certificate bytes in x5bag",
			raw:     buildTestDiceQuoteCBOR(t, validProtected, map[any]any{cose.HeaderLabelX5Bag: [][]byte{{}}}, validPayload, validSig, true),
			wantErr: "certificate at index 0 is empty",
		},
		{
			name: "unsupported content-type in unprotected header",
			raw: buildTestDiceQuoteCBOR(
				t,
				validProtected,
				map[any]any{
					cose.HeaderLabelContentType: "application/cwt",
					cose.HeaderLabelX5Bag:       [][]byte{{0x01}},
				},
				validPayload,
				validSig,
				true,
			),
			wantErr: `unsupported content-type "application/cwt"`,
		},
		{
			name:    "missing eat_profile in CWT payload",
			raw:     buildTestDiceQuoteCBOR(t, validProtected, validUnprotected, map[any]any{cwtClaimReportData: make([]byte, ReportDataSize)}, validSig, true),
			wantErr: "missing eat_profile (claim 265) in CWT payload",
		},
		{
			name: "invalid DER OID eat_profile in CWT payload",
			raw: buildTestDiceQuoteCBOR(
				t,
				validProtected,
				validUnprotected,
				map[any]any{
					cwtClaimEatProfile: []byte{0xff, 0xff},
					cwtClaimReportData: make([]byte, ReportDataSize),
				},
				validSig,
				true,
			),
			wantErr: "invalid eat_profile DER OID (claim 265)",
		},
		{
			name: "wrong eat_profile OID in CWT payload",
			raw: buildTestDiceQuoteCBOR(
				t,
				validProtected,
				validUnprotected,
				map[any]any{
					cwtClaimEatProfile: "1.2.840.113549",
					cwtClaimReportData: make([]byte, ReportDataSize),
				},
				validSig,
				true,
			),
			wantErr: `unsupported eat_profile "1.2.840.113549"`,
		},
		{
			name: "missing report_data in CWT payload",
			raw: buildTestDiceQuoteCBOR(
				t,
				validProtected,
				validUnprotected,
				map[any]any{cwtClaimEatProfile: testEatProfileDEROID},
				validSig,
				true,
			),
			wantErr: "missing report_data (claim -212) in CWT payload",
		},
		{
			name: "wrong report_data size in CWT payload",
			raw: buildTestDiceQuoteCBOR(
				t,
				validProtected,
				validUnprotected,
				map[any]any{
					cwtClaimEatProfile: testEatProfileDEROID,
					cwtClaimReportData: []byte{0x01, 0x02},
				},
				validSig,
				true,
			),
			wantErr: "reportData size is 2 bytes. Expected 64 bytes",
		},
		{
			name:    "wrong signature size",
			raw:     buildTestDiceQuoteCBOR(t, validProtected, validUnprotected, validPayload, []byte{0x01, 0x02}, true),
			wantErr: "DiceQuote signature size is 2 bytes. Expected 96 bytes",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := parseDiceQuoteEnvelope(tc.raw); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("parseDiceQuoteEnvelope() error = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}
