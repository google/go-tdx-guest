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
	"testing"

	pb "github.com/google/go-tdx-guest/proto/tdx"
	test "github.com/google/go-tdx-guest/testing/testdata"
)

func TestQuoteToProto(t *testing.T) {
	_, err := QuoteToProto(test.RawQuote)
	if err != nil {
		t.Fatal(err)
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
}

func TestNilToAbiBytesConversions(t *testing.T) {

	if _, err := QuoteToAbiBytes(nil); err != ErrQuoteNil {
		t.Error(err)
	}
	if _, err := signedDataToAbiBytes(nil); err != ErrQuoteV4AuthDataNil {
		t.Error(err)
	}
	if _, err := certificationDataToAbiBytes(nil); err != ErrCertificationDataNil {
		t.Error(err)
	}
	if _, err := qeReportCertificationDataToAbiBytes(nil); err != ErrQeReportCertificationDataNil {
		t.Error(err)
	}
	if _, err := qeAuthDataToAbiBytes(nil); err != ErrQeAuthDataNil {
		t.Error(err)
	}
	if _, err := pckCertificateChainToAbiBytes(nil); err != ErrPckCertChainNil {
		t.Error(err)
	}
	if _, err := TdQuoteBodyToAbiBytes(nil); err != ErrTDQuoteBodyNil {
		t.Error(err)
	}
	if _, err := HeaderToAbiBytes(nil); err != ErrHeaderNil {
		t.Error(err)
	}
	if _, err := EnclaveReportToAbiBytes(nil); err != ErrQeReportNil {
		t.Error(err)
	}
}

func TestInvalidConversionsToAbiBytes(t *testing.T) {
	expectedErrors := []string{
		"QuoteV4 invalid: QuoteV4 Header error: header is nil",
		"QuoteV4 AuthData invalid: signature size is 0 bytes. Expected 64 bytes",
		"certification data invalid: certification data type invalid, got 0, expected 6",
		"certification data invalid: certification data type invalid, got 7, expected 6",
		"certification data invalid: QE Report certification data error: QE Report certification data is nil",
		"QE Report certification data invalid: QE Report error: QE Report is nil",
		"QE AuthData invalid: parsed data size is 0 bytes. Expected 1 bytes",
		"PCK certificate chain data invalid: PCK certificate chain data type invalid, got 0, expected 5",
		"PCK certificate chain data invalid: PCK certificate chain data type invalid, got 7, expected 5",
		"PCK certificate chain data invalid: PCK certificate chain size is 0. Expected size 2",
		"TD quote body invalid: teeTcbSvn size is 0 bytes. Expected 16 bytes",
		"header invalid: version 0 not supported",
		"header invalid: version 1 not supported",
		"header invalid: attestation key type not supported",
		"header invalid: TEE type is not TDX",
		"QE Report invalid: cpuSvn size is 0 bytes. Expected 16 bytes",
	}
	if _, err := QuoteToAbiBytes(&pb.QuoteV4{}); err == nil || err.Error() != expectedErrors[0] {
		t.Errorf("error found: %v, want error: %s", err, expectedErrors[0])
	}
	if _, err := signedDataToAbiBytes(&pb.Ecdsa256BitQuoteV4AuthData{}); err == nil || err.Error() != expectedErrors[1] {
		t.Errorf("error found: %v, want error: %s", err, expectedErrors[1])
	}
	if _, err := certificationDataToAbiBytes(&pb.CertificationData{}); err == nil || err.Error() != expectedErrors[2] {
		t.Errorf("error found: %v, want error: %s", err, expectedErrors[2])
	}
	if _, err := certificationDataToAbiBytes(&pb.CertificationData{CertificateDataType: 7}); err == nil || err.Error() != expectedErrors[3] {
		t.Errorf("error found: %v, want error: %s", err, expectedErrors[3])
	}
	if _, err := certificationDataToAbiBytes(&pb.CertificationData{CertificateDataType: qeReportCertificationDataType, Size: 2}); err == nil || err.Error() != expectedErrors[4] {
		t.Errorf("error found: %v, want error: %s", err, expectedErrors[4])
	}
	if _, err := qeReportCertificationDataToAbiBytes(&pb.QEReportCertificationData{}); err == nil || err.Error() != expectedErrors[5] {
		t.Errorf("error found: %v, want error: %s", err, expectedErrors[5])
	}
	if _, err := qeAuthDataToAbiBytes(&pb.QeAuthData{ParsedDataSize: 1}); err == nil || err.Error() != expectedErrors[6] {

		t.Errorf("error found: %v, want error: %s", err, expectedErrors[6])
	}
	if _, err := pckCertificateChainToAbiBytes(&pb.PCKCertificateChainData{}); err == nil || err.Error() != expectedErrors[7] {
		t.Errorf("error found: %v, want error: %s", err, expectedErrors[7])
	}
	if _, err := pckCertificateChainToAbiBytes(&pb.PCKCertificateChainData{CertificateDataType: 7}); err == nil || err.Error() != expectedErrors[8] {
		t.Errorf("error found: %v, want error: %s", err, expectedErrors[8])
	}
	if _, err := pckCertificateChainToAbiBytes(&pb.PCKCertificateChainData{CertificateDataType: pckReportCertificationDataType, Size: 2}); err == nil || err.Error() != expectedErrors[9] {
		t.Errorf("error found: %v, want error: %s", err, expectedErrors[9])
	}
	if _, err := TdQuoteBodyToAbiBytes(&pb.TDQuoteBody{}); err == nil || err.Error() != expectedErrors[10] {
		t.Errorf("error found: %v, want error: %s", err, expectedErrors[10])
	}
	if _, err := HeaderToAbiBytes(&pb.Header{}); err == nil || err.Error() != expectedErrors[11] {
		t.Errorf("error found: %v, want error: %s", err, expectedErrors[11])
	}
	if _, err := HeaderToAbiBytes(&pb.Header{Version: 1}); err == nil || err.Error() != expectedErrors[12] {
		t.Errorf("error found: %v, want error: %s", err, expectedErrors[12])
	}
	if _, err := HeaderToAbiBytes(&pb.Header{Version: QuoteVersion, AttestationKeyType: 1}); err == nil || err.Error() != expectedErrors[13] {
		t.Errorf("error found: %v, want error: %s", err, expectedErrors[13])
	}
	if _, err := HeaderToAbiBytes(&pb.Header{Version: QuoteVersion, AttestationKeyType: AttestationKeyType, TeeType: 0x01}); err == nil || err.Error() != expectedErrors[14] {
		t.Errorf("error found: %v, want error: %s", err, expectedErrors[14])
	}
	if _, err := EnclaveReportToAbiBytes(&pb.EnclaveReport{}); err == nil || err.Error() != expectedErrors[15] {
		t.Errorf("error found: %v, want error: %s", err, expectedErrors[15])
	}
}
