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
	"crypto/x509"
	"fmt"

	"github.com/veraison/go-cose"
)

// selectLeafCertBySignature identifies the unique non-CA certificate in certs
// whose public key cryptographically verifies the COSE_Sign1 signature of msg.
// The signing algorithm in alg has already been validated by
// abi.DiceQuoteToCOSESign1.
//
// TODO: Add custom verifier dispatch for ESP384 (COSE algorithm ID -51) or
// ML-DSA-87 (COSE algorithm ID -50) if algorithms not natively supported by
// go-cose are introduced in the future.
func selectLeafCertBySignature(certs []*x509.Certificate, msg *cose.Sign1Message, alg int64) (*x509.Certificate, error) {
	var nonCA []*x509.Certificate
	for _, cert := range certs {
		if !cert.IsCA {
			nonCA = append(nonCA, cert)
		}
	}
	if len(nonCA) == 0 {
		return nil, ErrLeafCertNotFound
	}

	coseAlg := cose.Algorithm(alg)
	var matched []*x509.Certificate
	var lastKeyErr error
	for _, cert := range nonCA {
		verifier, err := cose.NewVerifier(coseAlg, cert.PublicKey)
		if err != nil {
			lastKeyErr = err
			continue
		}
		if err := msg.Verify(nil, verifier); err == nil {
			matched = append(matched, cert)
		}
	}

	if len(matched) == 1 {
		return matched[0], nil
	}
	// Duplicate leaf certificates verifying the same signature are not expected
	// in a valid DICE quote bag and are rejected to avoid certificate ambiguity.
	if len(matched) > 1 {
		return nil, fmt.Errorf("%w: %d certificates verified COSE_Sign1 signature", ErrLeafCertAmbiguous, len(matched))
	}
	if lastKeyErr != nil && len(nonCA) == 1 {
		return nil, fmt.Errorf("%w: %v", ErrCertInvalidKey, lastKeyErr)
	}
	return nil, ErrSignatureInvalid
}
