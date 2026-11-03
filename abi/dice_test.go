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
	"errors"
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

	es384ProtectedHeader := []byte{0xa1, 0x01, 0x38, 0x22}
	es384WithCritProtectedHeader := []byte{0xa2, 0x01, 0x38, 0x22, 0x02, 0x81, 0x01}
	sampleKeyID := []byte{
		0xd1, 0xcd, 0x15, 0xfc, 0xef, 0xb8, 0xe6, 0xbc, 0x28, 0xc6, 0xec, 0xc3,
		0x68, 0x58, 0xe5, 0xdc, 0x9e, 0xc4, 0xd7, 0xbf, 0x99, 0xdd, 0x5f, 0x6f,
		0x4f, 0x04, 0xbd, 0xc4, 0xda, 0x9f, 0x1c, 0x9c, 0xaa, 0x7e, 0x70, 0xf9,
		0x30, 0x6a, 0x3c, 0xde, 0xa4, 0xb0, 0x5e, 0x4b, 0x8f, 0xa2, 0x18, 0xe5,
	}
	sampleReportData := []byte{
		0xdb, 0x73, 0xd4, 0x44, 0x25, 0xd6, 0xb0, 0xe9, 0xc1, 0x04, 0xeb, 0xef,
		0x4d, 0x0c, 0x08, 0x93, 0x2a, 0xe5, 0xf8, 0x8b, 0xf6, 0x98, 0x57, 0x6c,
		0x3f, 0x97, 0xa8, 0x1d, 0x05, 0x2d, 0xb7, 0xe0, 0xa1, 0x8b, 0x25, 0xc6,
		0x61, 0xd5, 0xaf, 0x23, 0xd9, 0x9a, 0x12, 0x26, 0xa6, 0x1a, 0xb9, 0xd0,
		0x00, 0xb1, 0x5c, 0xf6, 0x4a, 0xb3, 0x62, 0x89, 0x4a, 0x0a, 0xa6, 0x50,
		0x38, 0x5d, 0x30, 0xd9,
	}
	sampleSigPrefix := []byte{0x4d, 0x6a, 0x24, 0xe7, 0x56, 0x41, 0xab, 0x04}
	specKeyID := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00}
	specSigPrefix := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}

	tcs := []struct {
		name                string
		rawQuote            []byte
		wantProtectedHeader []byte
		wantKeyID           []byte
		wantCertCount       int
		wantFirstCertPrefix []byte
		wantPayloadLen      int
		wantReportData      []byte
		wantSigPrefix       []byte
		wantExactCBOR       bool
	}{
		{
			name:                "sample dice quote",
			rawQuote:            test.RawQuoteDICE,
			wantProtectedHeader: es384ProtectedHeader,
			wantKeyID:           sampleKeyID,
			wantCertCount:       9,
			wantFirstCertPrefix: []byte{0x30, 0x82},
			wantPayloadLen:      1051,
			wantReportData:      sampleReportData,
			wantSigPrefix:       sampleSigPrefix,
		},
		{
			name:                "specification example dice quote",
			rawQuote:            test.RawQuoteDICESpec,
			wantProtectedHeader: es384ProtectedHeader,
			wantKeyID:           specKeyID,
			wantCertCount:       9,
			wantFirstCertPrefix: []byte{0x01},
			wantPayloadLen:      1873,
			wantReportData:      make([]byte, ReportDataSize),
			wantSigPrefix:       specSigPrefix,
			wantExactCBOR:       true,
		},
		{
			name:                "bare COSE_Sign1 without outer Tag 61",
			rawQuote:            test.RawQuoteDICE[2:],
			wantProtectedHeader: es384ProtectedHeader,
			wantKeyID:           sampleKeyID,
			wantCertCount:       9,
			wantFirstCertPrefix: []byte{0x30, 0x82},
			wantPayloadLen:      1051,
			wantReportData:      sampleReportData,
			wantSigPrefix:       sampleSigPrefix,
		},
		{
			name:                "spec style quote with DER OID eat_profile, crit, and single-cert x5chain",
			rawQuote:            specStyleQuote,
			wantProtectedHeader: es384WithCritProtectedHeader,
			wantKeyID:           []byte{0x01, 0x02, 0x03, 0x04},
			wantCertCount:       1,
			wantFirstCertPrefix: []byte{0x30, 0x82, 0x01, 0x00},
			wantPayloadLen:      150,
			wantReportData:      validReportData,
			wantSigPrefix:       validSig[:8],
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
			if !bytes.Equal(quote.GetProtectedHeader(), tc.wantProtectedHeader) {
				t.Errorf("quote.GetProtectedHeader() = %x, want %x", quote.GetProtectedHeader(), tc.wantProtectedHeader)
			}
			if quote.GetAlgorithm() != int64(cose.AlgorithmES384) {
				t.Errorf("quote.GetAlgorithm() = %d, want %d", quote.GetAlgorithm(), cose.AlgorithmES384)
			}
			if !bytes.Equal(quote.GetKeyId(), tc.wantKeyID) {
				t.Errorf("quote.GetKeyId() = %x, want %x", quote.GetKeyId(), tc.wantKeyID)
			}
			if quote.GetContentType() != diceContentType {
				t.Errorf("quote.GetContentType() = %q, want %q", quote.GetContentType(), diceContentType)
			}
			if len(quote.GetCertChain()) != tc.wantCertCount {
				t.Fatalf("len(quote.GetCertChain()) = %d, want %d", len(quote.GetCertChain()), tc.wantCertCount)
			}
			if !bytes.HasPrefix(quote.GetCertChain()[0], tc.wantFirstCertPrefix) {
				t.Errorf("quote.GetCertChain()[0] prefix = %x, want prefix %x", quote.GetCertChain()[0], tc.wantFirstCertPrefix)
			}
			if len(quote.GetRawPayload()) != tc.wantPayloadLen {
				t.Errorf("len(quote.GetRawPayload()) = %d, want %d", len(quote.GetRawPayload()), tc.wantPayloadLen)
			}
			if quote.GetIssuer() != "DICE Intel TDX TD Attestation" {
				t.Errorf("quote.GetIssuer() = %q, want %q", quote.GetIssuer(), "DICE Intel TDX TD Attestation")
			}
			if quote.GetSubject() != "TEE Quote / Attestation Evidence" {
				t.Errorf("quote.GetSubject() = %q, want %q", quote.GetSubject(), "TEE Quote / Attestation Evidence")
			}
			if quote.GetEatProfile() != diceEatProfileOID {
				t.Errorf("quote.GetEatProfile() = %q, want %q", quote.GetEatProfile(), diceEatProfileOID)
			}
			if !bytes.Equal(quote.GetTdQuoteBody().GetReportData(), tc.wantReportData) {
				t.Errorf("quote.GetTdQuoteBody().GetReportData() = %x, want %x", quote.GetTdQuoteBody().GetReportData(), tc.wantReportData)
			}
			if len(quote.GetSignature()) != diceSignatureSize {
				t.Errorf("len(quote.GetSignature()) = %d, want %d", len(quote.GetSignature()), diceSignatureSize)
			}
			if !bytes.HasPrefix(quote.GetSignature(), tc.wantSigPrefix) {
				t.Errorf("quote.GetSignature() prefix = %x, want prefix %x", quote.GetSignature()[:8], tc.wantSigPrefix)
			}

			encoded, err := encodeDiceQuoteCBOR(quote)
			if err != nil {
				t.Fatalf("encodeDiceQuoteCBOR() failed: %v", err)
			}
			if tc.wantExactCBOR && !bytes.Equal(encoded, tc.rawQuote) {
				t.Errorf("encodeDiceQuoteCBOR() did not produce exact canonical CBOR bytes")
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

	es256ProtectedBytes, err := diceCBOREncMode.Marshal(map[any]any{
		cose.HeaderLabelAlgorithm: cose.AlgorithmES256,
	})
	if err != nil {
		t.Fatalf("failed to marshal ES256 protected header: %v", err)
	}

	tcs := []struct {
		name    string
		quote   *pb.DiceQuote
		wantErr error
	}{
		{
			name:    "nil quote",
			quote:   nil,
			wantErr: errDiceQuoteNil,
		},
		{
			name:    "empty protected header",
			quote:   mutate(func(q *pb.DiceQuote) { q.ProtectedHeader = nil }),
			wantErr: errDiceProtectedHeaderEmpty,
		},
		{
			name:    "invalid protected header CBOR bytes",
			quote:   mutate(func(q *pb.DiceQuote) { q.ProtectedHeader = []byte{0xff} }),
			wantErr: errDiceProtectedHeaderInvalid,
		},
		{
			name:    "unsupported algorithm",
			quote:   mutate(func(q *pb.DiceQuote) { q.Algorithm = int64(cose.AlgorithmES256) }),
			wantErr: errDiceAlgorithmUnsupported,
		},
		{
			name:    "protected header algorithm mismatch with quote algorithm",
			quote:   mutate(func(q *pb.DiceQuote) { q.ProtectedHeader = es256ProtectedBytes }),
			wantErr: errDiceAlgorithmMismatch,
		},
		{
			name:    "unsupported content type",
			quote:   mutate(func(q *pb.DiceQuote) { q.ContentType = "application/json" }),
			wantErr: errDiceContentTypeUnsupported,
		},
		{
			name:    "empty cert chain",
			quote:   mutate(func(q *pb.DiceQuote) { q.CertChain = nil }),
			wantErr: errDiceCertChainEmpty,
		},
		{
			name:    "empty cert element",
			quote:   mutate(func(q *pb.DiceQuote) { q.CertChain = [][]byte{{}} }),
			wantErr: errDiceCertEmpty,
		},
		{
			name:    "empty raw payload",
			quote:   mutate(func(q *pb.DiceQuote) { q.RawPayload = nil }),
			wantErr: errDicePayloadEmpty,
		},
		{
			name:    "invalid eat profile",
			quote:   mutate(func(q *pb.DiceQuote) { q.EatProfile = "1.2.3.4" }),
			wantErr: errDiceEatProfileUnsupported,
		},
		{
			name:    "nil TDQuoteBody",
			quote:   mutate(func(q *pb.DiceQuote) { q.TdQuoteBody = nil }),
			wantErr: ErrTDQuoteBodyNil,
		},
		{
			name:    "invalid reportData size",
			quote:   mutate(func(q *pb.DiceQuote) { q.TdQuoteBody.ReportData = []byte{0x01} }),
			wantErr: errDiceReportDataSize,
		},
		{
			name:    "invalid signature size",
			quote:   mutate(func(q *pb.DiceQuote) { q.Signature = []byte{0x01, 0x02} }),
			wantErr: errDiceSignatureSize,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := encodeDiceQuoteCBOR(tc.quote); !errors.Is(err, tc.wantErr) {
				t.Errorf("encodeDiceQuoteCBOR() error = %v, want errors.Is(_, %v)", err, tc.wantErr)
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
		name       string
		raw        []byte
		wantErr    error
		wantErrSub string
	}{
		{
			name:    "empty input",
			raw:     nil,
			wantErr: ErrRawQuoteEmpty,
		},
		{
			name:       "truncated CBOR",
			raw:        test.RawQuoteDICE[:64],
			wantErrSub: "parsing DICE quote CBOR failed",
		},
		{
			name:       "trailing bytes after CBOR root",
			raw:        append(append([]byte{}, test.RawQuoteDICE...), 0x00),
			wantErrSub: "parsing DICE quote CBOR failed",
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
			wantErrSub: "parsing DICE quote CBOR failed",
		},
		{
			name:    "unexpected outer CBOR tag",
			raw:     []byte{0xd8, 0x63, 0x84, 0x40, 0xa0, 0x40, 0x40},
			wantErr: errDiceCBORTagInvalid,
		},
		{
			name:    "empty protected header",
			raw:     buildTestDiceQuoteCBOR(t, nil, validUnprotected, validPayload, validSig, true),
			wantErr: errDiceProtectedHeaderEmpty,
		},
		{
			name:    "missing algorithm in protected header",
			raw:     buildTestDiceQuoteCBOR(t, map[any]any{int64(99): 1}, validUnprotected, validPayload, validSig, true),
			wantErr: errDiceAlgorithmInvalid,
		},
		{
			name:    "unsupported algorithm ES256 in protected header",
			raw:     buildTestDiceQuoteCBOR(t, map[any]any{cose.HeaderLabelAlgorithm: cose.AlgorithmES256}, validUnprotected, validPayload, validSig, true),
			wantErr: errDiceAlgorithmUnsupported,
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
			wantErr: errDiceCritLabelUnsupported,
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
			wantErrSub: "crit: not allowed",
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
			wantErr: errDiceCertChainConflict,
		},
		{
			name:    "missing certificate chain in unprotected header",
			raw:     buildTestDiceQuoteCBOR(t, validProtected, map[any]any{cose.HeaderLabelContentType: diceContentType}, validPayload, validSig, true),
			wantErr: errDiceCertChainMissing,
		},
		{
			name:    "empty certificate chain array in unprotected header",
			raw:     buildTestDiceQuoteCBOR(t, validProtected, map[any]any{cose.HeaderLabelX5Bag: []any{}}, validPayload, validSig, true),
			wantErr: errDiceCertChainEmpty,
		},
		{
			name:    "empty certificate bytes in x5bag",
			raw:     buildTestDiceQuoteCBOR(t, validProtected, map[any]any{cose.HeaderLabelX5Bag: [][]byte{{}}}, validPayload, validSig, true),
			wantErr: errDiceCertEmpty,
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
			wantErr: errDiceContentTypeUnsupported,
		},
		{
			name:    "missing eat_profile in CWT payload",
			raw:     buildTestDiceQuoteCBOR(t, validProtected, validUnprotected, map[any]any{cwtClaimReportData: make([]byte, ReportDataSize)}, validSig, true),
			wantErr: errDiceEatProfileMissing,
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
			wantErr: errDiceEatProfileInvalid,
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
			wantErr: errDiceEatProfileUnsupported,
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
			wantErr: errDiceReportDataMissing,
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
			wantErr: errDiceReportDataSize,
		},
		{
			name:    "wrong signature size",
			raw:     buildTestDiceQuoteCBOR(t, validProtected, validUnprotected, validPayload, []byte{0x01, 0x02}, true),
			wantErr: errDiceSignatureSize,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := parseDiceQuoteEnvelope(tc.raw)
			if err == nil {
				t.Fatalf("parseDiceQuoteEnvelope() succeeded, want error")
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Errorf("parseDiceQuoteEnvelope() error = %v, want errors.Is(_, %v)", err, tc.wantErr)
			}
			if tc.wantErrSub != "" && !strings.Contains(err.Error(), tc.wantErrSub) {
				t.Errorf("parseDiceQuoteEnvelope() error = %v, want substring %q", err, tc.wantErrSub)
			}
		})
	}
}
