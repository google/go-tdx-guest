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

package dice

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/google/go-tdx-guest/testing/testdata"
)

const (
	// Source: Intel Trusted Services Certificates Infrastructure (TSCI) DICE Root CA certificate:
	// https://tsci.intel.com/content/DICE/RootCA/DCP_DICE_Global_Root_CA.cer
	// The Common Name and SHA-256 fingerprint can be verified with:
	//   openssl x509 -in DCP_DICE_Global_Root_CA.cer -inform DER -noout -subject -fingerprint -sha256
	expectedDiceRootCN     = "DCP DICE Global Root CA"
	expectedDiceRootSHA256 = "8031cd5e07d49be7f308900ef1775145cde8d264d385450038f2e82904d5c907"

	// Expected byte size of the embedded sample quote (testing/testdata/quote_sample_dice.dat).
	expectedDiceQuoteSampleSize = 9107
)

func TestTrustedDiceRootCertificate(t *testing.T) {
	if trustedDiceRootCertificate == nil {
		t.Fatalf("trustedDiceRootCertificate is nil")
	}

	if trustedDiceRootCertificate.Subject.CommonName != expectedDiceRootCN {
		t.Errorf("subject CommonName = %q, want %q", trustedDiceRootCertificate.Subject.CommonName, expectedDiceRootCN)
	}
	if trustedDiceRootCertificate.Issuer.CommonName != expectedDiceRootCN {
		t.Errorf("issuer CommonName = %q, want %q", trustedDiceRootCertificate.Issuer.CommonName, expectedDiceRootCN)
	}

	if !trustedDiceRootCertificate.IsCA {
		t.Errorf("expected trustedDiceRootCertificate to be CA, got false")
	}

	pubKey, ok := trustedDiceRootCertificate.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected ECDSA public key, got %T", trustedDiceRootCertificate.PublicKey)
	}
	if pubKey.Curve.Params().Name != "P-384" {
		t.Errorf("expected curve P-384, got %s", pubKey.Curve.Params().Name)
	}

	// Verify self-signature
	if err := trustedDiceRootCertificate.CheckSignatureFrom(trustedDiceRootCertificate); err != nil {
		t.Errorf("trustedDiceRootCertificate self-signature check failed: %v", err)
	}

	// Verify SHA-256 fingerprint
	hash := sha256.Sum256(trustedDiceRootCertificate.Raw)
	actualHex := hex.EncodeToString(hash[:])
	if actualHex != expectedDiceRootSHA256 {
		t.Errorf("fingerprint = %s, want %s", actualHex, expectedDiceRootSHA256)
	}
}

func TestRawQuoteDICE(t *testing.T) {
	if len(testdata.RawQuoteDICE) == 0 {
		t.Fatalf("RawQuoteDICE is empty")
	}
	if len(testdata.RawQuoteDICE) != expectedDiceQuoteSampleSize {
		t.Errorf("len(RawQuoteDICE) = %d, want %d", len(testdata.RawQuoteDICE), expectedDiceQuoteSampleSize)
	}

	// Verify the leading CBOR tags of the CWT/COSE_Sign1 quote:
	// - Tag 61 (0xd8, 0x3d): CBOR Web Token (CWT), defined in RFC 8392 Section 6
	//   (https://datatracker.ietf.org/doc/html/rfc8392#section-6).
	// - Tag 18 (0xd2): COSE_Sign1 Single Signer Data Object, defined in RFC 9052 Section 2 Table 1
	//   (https://datatracker.ietf.org/doc/html/rfc9052#section-2).
	// - CBOR tag numbers list: https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml
	// - Binary encoding (0xd8 0x3d = 0xc0+24 followed by 61; 0xd2 = 0xc0+18): defined in
	//   RFC 8949 Section 3 (https://datatracker.ietf.org/doc/html/rfc8949#section-3).
	if testdata.RawQuoteDICE[0] != 0xd8 || testdata.RawQuoteDICE[1] != 0x3d {
		t.Errorf("expected Tag 61 (0xd83d), got %x %x", testdata.RawQuoteDICE[0], testdata.RawQuoteDICE[1])
	}
	if testdata.RawQuoteDICE[2] != 0xd2 {
		t.Errorf("expected Tag 18 (0xd2), got %x", testdata.RawQuoteDICE[2])
	}
}
