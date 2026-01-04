// Copyright 2023 Google LLC
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
	"encoding/binary"
	"testing"

	pb "github.com/google/go-tdx-guest/proto/tdx"
	test "github.com/google/go-tdx-guest/testing/testdata"
	"google.golang.org/protobuf/proto"
)

// TODO: Use errors.Is() instead of string comparisons
func TestQuoteToProto(t *testing.T) {
	clone := func(b []byte) []byte {
		c := make([]byte, len(b))
		copy(c, b)
		return c
	}
	tcs := []struct {
		name     string
		rawQuote []byte
		wantErr  string
	}{
		{
			name:     "empty quote",
			rawQuote: []byte{},
			wantErr:  ErrRawQuoteEmpty.Error(),
		},
		{
			name:     "v4 quote",
			rawQuote: test.RawQuote,
			wantErr:  "",
		},
		{
			name:     "v5 quote",
			rawQuote: test.RawQuoteV5,
			wantErr:  "",
		},
		{
			name:     "v5 quote too small",
			rawQuote: test.RawQuoteV5[:100],
			wantErr:  "raw quote size is 100 bytes, a V5 TDX quote should have size a minimum size of 1026 bytes", // QuoteMinSizeV5
		},
		{
			name: "v5 quote unsupported body type",
			rawQuote: func() []byte {
				q := clone(test.RawQuoteV5)
				q[quoteBodyStart] = 1 // TdQuoteBodyType = 1, little-endian uint16
				q[quoteBodyStart+1] = 0
				return q
			}(),
			wantErr: "parsing TD Quote Body Descriptor failed: unsupported TD quote body type , got 1",
		},
		{
			name: "v5 quote body size too large",
			rawQuote: func() []byte {
				q := clone(test.RawQuoteV5)
				// modify the body size to be larger than expected (648)
				quoteBodySizeBytes := quoteHeaderSizeV5 + quoteBodyTypeSizeV5
				binary.LittleEndian.PutUint32(q[quoteBodySizeBytes:], uint32(999))
				return q
			}(),
			wantErr: "TD quote body size is 999, a V5 TDX1.5 quote should have size 648",
		},
		{
			name: "incorrect TDX version",
			rawQuote: func() []byte {
				q := clone(test.RawQuoteV5)
				binary.LittleEndian.PutUint16(q[quoteHeaderSizeV5:quoteHeaderSizeV5+quoteBodyTypeSizeV5], uint16(2))
				return q
			}(),
			wantErr: "TD quote body size is 648, a V5 TDX1.0 quote should have size 584",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			_, err := QuoteToProto(tc.rawQuote)
			if tc.wantErr == "" {
				if err != nil {
					t.Errorf("QuoteToProto() returned error %v, want nil", err)
				}
				return
			}
			if err == nil || err.Error() != tc.wantErr {
				t.Errorf("QuoteToProto() returned error %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestQuoteToAbiBytes(t *testing.T) {
	quote, err := QuoteToProto(test.RawQuote)
	if err != nil {
		t.Fatal(err)
	}
	rawQuote, err := QuoteToAbiBytes(quote)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(test.RawQuote, rawQuote) {
		t.Errorf("raw quote bytes got %v. Expected %v", rawQuote, test.RawQuote)
	}
	quoteV5, err := QuoteToProto(test.RawQuoteV5)
	if err != nil {
		t.Fatal(err)
	}
	rawQuoteV5, err := QuoteToAbiBytes(quoteV5)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(test.RawQuoteV5, rawQuoteV5) {
		t.Errorf("raw quote v5 bytes got %v. Expected %v", rawQuoteV5, test.RawQuoteV5)
	}
}

func TestNilToAbiBytesConversions(t *testing.T) {
	tcs := []struct {
		name string
		call func() ([]byte, error)
		want error
	}{
		{
			name: "QuoteToAbiBytes",
			call: func() ([]byte, error) { return QuoteToAbiBytes(nil) },
			want: ErrQuoteNil,
		},
		{
			name: "signedDataToAbiBytes",
			call: func() ([]byte, error) { return signedDataToAbiBytes(nil) },
			want: ErrQuoteV4AuthDataNil,
		},
		{
			name: "certificationDataToAbiBytes",
			call: func() ([]byte, error) { return certificationDataToAbiBytes(nil) },
			want: ErrCertificationDataNil,
		},
		{
			name: "qeReportCertificationDataToAbiBytes",
			call: func() ([]byte, error) { return qeReportCertificationDataToAbiBytes(nil) },
			want: ErrQeReportCertificationDataNil,
		},
		{
			name: "qeAuthDataToAbiBytes",
			call: func() ([]byte, error) { return qeAuthDataToAbiBytes(nil) },
			want: ErrQeAuthDataNil,
		},
		{
			name: "pckCertificateChainToAbiBytes",
			call: func() ([]byte, error) { return pckCertificateChainToAbiBytes(nil) },
			want: ErrPckCertChainNil,
		},
		{
			name: "TdQuoteBodyToAbiBytes",
			call: func() ([]byte, error) { return TdQuoteBodyToAbiBytes(nil) },
			want: ErrTDQuoteBodyNil,
		},
		{
			name: "HeaderToAbiBytes",
			call: func() ([]byte, error) { return HeaderToAbiBytes(nil) },
			want: ErrHeaderNil,
		},
		{
			name: "EnclaveReportToAbiBytes",
			call: func() ([]byte, error) { return EnclaveReportToAbiBytes(nil) },
			want: ErrQeReportNil,
		},
		{
			name: "TdQuoteBodyDescriptorToAbiBytes",
			call: func() ([]byte, error) { return TdQuoteBodyDescriptorToAbiBytes(nil) },
			want: ErrTDQuoteBodyDescriptorNil,
		},
		{
			name: "tdQuoteBodyV5ToAbiBytes",
			call: func() ([]byte, error) { return tdQuoteBodyV5ToAbiBytes(nil, tdxVersion15BodyType) },
			want: ErrQuoteV5Nil,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.call(); err != tc.want {
				t.Errorf("%s() returned error %v, want %v", tc.name, err, tc.want)
			}
		})
	}
}

func TestInvalidConversionsToAbiBytes(t *testing.T) {
	quoteV5, err := QuoteToProto(test.RawQuoteV5)
	if err != nil {
		t.Fatalf("failed to parse RawQuoteV5: %v", err)
	}
	tdQuoteBodyV5 := quoteV5.(*pb.QuoteV5).GetTdQuoteBodyDescriptor().GetTdQuoteBodyV5()

	tcs := []struct {
		name    string
		call    func() ([]byte, error)
		wantErr string
	}{
		{
			name:    "QuoteV4HeaderNil",
			call:    func() ([]byte, error) { return QuoteToAbiBytes(&pb.QuoteV4{}) },
			wantErr: "QuoteV4 invalid: QuoteV4 Header error: header is nil",
		},
		{
			name:    "Ecdsa256BitQuoteV4AuthDataNil",
			call:    func() ([]byte, error) { return signedDataToAbiBytes(&pb.Ecdsa256BitQuoteV4AuthData{}) },
			wantErr: "QuoteV4 AuthData invalid: signature size is 0 bytes. Expected 64 bytes",
		},
		{
			name:    "CertificationDataEmpty",
			call:    func() ([]byte, error) { return certificationDataToAbiBytes(&pb.CertificationData{}) },
			wantErr: "certification data invalid: certification data type invalid, got 0, expected 6",
		},
		{
			name: "CertificationDataType7",
			call: func() ([]byte, error) {
				return certificationDataToAbiBytes(&pb.CertificationData{CertificateDataType: 7})
			},
			wantErr: "certification data invalid: certification data type invalid, got 7, expected 6",
		},
		{
			name: "CertificationDataQeReportNil",
			call: func() ([]byte, error) {
				return certificationDataToAbiBytes(&pb.CertificationData{CertificateDataType: qeReportCertificationDataType, Size: 2})
			},
			wantErr: "certification data invalid: QE Report certification data error: QE Report certification data is nil",
		},
		{
			name:    "QEReportCertificationDataEmpty",
			call:    func() ([]byte, error) { return qeReportCertificationDataToAbiBytes(&pb.QEReportCertificationData{}) },
			wantErr: "QE Report certification data invalid: QE Report error: QE Report is nil",
		},
		{
			name:    "QeAuthDataEmpty",
			call:    func() ([]byte, error) { return qeAuthDataToAbiBytes(&pb.QeAuthData{ParsedDataSize: 1}) },
			wantErr: "QE AuthData invalid: parsed data size is 0 bytes. Expected 1 bytes",
		},
		{
			name:    "PCKCertificateChainDataEmpty",
			call:    func() ([]byte, error) { return pckCertificateChainToAbiBytes(&pb.PCKCertificateChainData{}) },
			wantErr: "PCK certificate chain data invalid: PCK certificate chain data type invalid, got 0, expected 5",
		},
		{
			name: "PCKCertificateChainDataType7",
			call: func() ([]byte, error) {
				return pckCertificateChainToAbiBytes(&pb.PCKCertificateChainData{CertificateDataType: 7})
			},
			wantErr: "PCK certificate chain data invalid: PCK certificate chain data type invalid, got 7, expected 5",
		},
		{
			name: "PCKCertificateChainDataSize0",
			call: func() ([]byte, error) {
				return pckCertificateChainToAbiBytes(&pb.PCKCertificateChainData{CertificateDataType: pckReportCertificationDataType, Size: 2})
			},
			wantErr: "PCK certificate chain data invalid: PCK certificate chain size is 0. Expected size 2",
		},
		{
			name:    "TDQuoteBodyEmpty",
			call:    func() ([]byte, error) { return TdQuoteBodyToAbiBytes(&pb.TDQuoteBody{}) },
			wantErr: "TD quote body invalid: teeTcbSvn size is 0 bytes. Expected 16 bytes",
		},
		{
			name:    "HeaderEmpty",
			call:    func() ([]byte, error) { return HeaderToAbiBytes(&pb.Header{}) },
			wantErr: "header invalid: version 0 not supported",
		},
		{
			name:    "HeaderV1",
			call:    func() ([]byte, error) { return HeaderToAbiBytes(&pb.Header{Version: 1}) },
			wantErr: "header invalid: version 1 not supported",
		},
		{
			name: "HeaderAttestationKeyType1",
			call: func() ([]byte, error) {
				return HeaderToAbiBytes(&pb.Header{Version: QuoteVersionV4, AttestationKeyType: 1})
			},
			wantErr: "header invalid: attestation key type not supported",
		},
		{
			name: "HeaderTeeType1",
			call: func() ([]byte, error) {
				return HeaderToAbiBytes(&pb.Header{Version: QuoteVersionV4, AttestationKeyType: AttestationKeyType, TeeType: 0x01})
			},
			wantErr: "header invalid: TEE type is not TDX",
		},
		{
			name:    "EnclaveReportEmpty",
			call:    func() ([]byte, error) { return EnclaveReportToAbiBytes(&pb.EnclaveReport{}) },
			wantErr: "QE Report invalid: cpuSvn size is 0 bytes. Expected 16 bytes",
		},
		{
			name:    "QuoteV5HeaderNil",
			call:    func() ([]byte, error) { return QuoteToAbiBytes(&pb.QuoteV5{}) },
			wantErr: "quoteV5 invalid: quoteV5 Header error: header is nil",
		},
		{
			name:    "TDQuoteBodyV5Version5",
			call:    func() ([]byte, error) { return tdQuoteBodyV5ToAbiBytes(&pb.TDQuoteBodyV5{}, 5) },
			wantErr: "td quote body V5 invalid: tdx version 5 is not supported",
		},
		{
			name:    "TDQuoteBodyV5Empty",
			call:    func() ([]byte, error) { return tdQuoteBodyV5ToAbiBytes(&pb.TDQuoteBodyV5{}, tdxVersion10BodyType) },
			wantErr: "td quote body V5 invalid: teeTcbSvn size is 0 bytes. Expected 16 bytes",
		},
		{
			name:    "TdQuoteBodyV5Svn2ForTdx10",
			call:    func() ([]byte, error) { return tdQuoteBodyV5ToAbiBytes(tdQuoteBodyV5, tdxVersion10BodyType) },
			wantErr: "td quote body V5 invalid: teeTcbSvn2 is not expected to be set for TDX version 1.0",
		},
		{
			name: "TdQuoteBodyV5Svn2InvalidSize",
			call: func() ([]byte, error) {
				body := proto.Clone(tdQuoteBodyV5).(*pb.TDQuoteBodyV5)
				body.TeeTcbSvn2 = []byte{1}
				return tdQuoteBodyV5ToAbiBytes(body, tdxVersion15BodyType)
			},
			wantErr: "td quote body V5 invalid: teeTcbSvn2 size is 1 bytes. Expected 16 bytes",
		},
		{
			name:    "TDQuoteBodyDescriptorEmpty",
			call:    func() ([]byte, error) { return TdQuoteBodyDescriptorToAbiBytes(&pb.TDQuoteBodyDescriptor{}) },
			wantErr: "td quote body descriptor invalid: unsupported TD quote body type , got 0",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.call(); err == nil || err.Error() != tc.wantErr {
				t.Errorf("%s() returned error %v, want %v", tc.name, err, tc.wantErr)
			}
		})
	}
}
