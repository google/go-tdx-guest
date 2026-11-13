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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	pb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/veraison/go-cose"
)

const (
	// es384SignatureSize is the raw ECDSA P-384 COSE_Sign1 signature length
	// (48-byte big-endian R || 48-byte big-endian S).
	es384SignatureSize = 96
)

var diceCBOREncMode cbor.EncMode

func init() {
	encOpts := cbor.EncOptions{
		Sort:        cbor.SortCoreDeterministic,
		IndefLength: cbor.IndefLengthForbidden,
	}
	var err error
	diceCBOREncMode, err = encOpts.EncMode()
	if err != nil {
		panic(err)
	}
}

// verifyCOSESign1 reconstructs the RFC 9052 COSE_Sign1 message from the
// preserved raw protected header, raw payload, and signature bytes, and
// verifies the cryptographic signature against the verified leaf public key.
func verifyCOSESign1(quote *pb.DiceQuote, leafPub crypto.PublicKey) error {
	rawProtected, err := diceCBOREncMode.Marshal(quote.GetProtectedHeader())
	if err != nil {
		return fmt.Errorf("%w: encoding protected header bstr failed: %v", ErrProtectedHeaderInvalid, err)
	}

	var protected cose.ProtectedHeader
	if err := protected.UnmarshalCBOR(rawProtected); err != nil {
		return fmt.Errorf("%w: %v", ErrProtectedHeaderInvalid, err)
	}

	hdrAlg, err := protected.Algorithm()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrAlgorithmInvalid, err)
	}
	if int64(hdrAlg) != quote.GetAlgorithm() {
		return fmt.Errorf("%w: quote algorithm %d != protected header algorithm %d", ErrAlgorithmMismatch, quote.GetAlgorithm(), int64(hdrAlg))
	}

	critLabels, err := protected.Critical()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrProtectedHeaderInvalid, err)
	}
	for _, label := range critLabels {
		if label != cose.HeaderLabelAlgorithm && label != cose.HeaderLabelContentType {
			return fmt.Errorf("%w: %v", ErrCritLabelUnsupported, label)
		}
	}

	verifier, expectedSigSize, err := newDiceVerifier(quote.GetAlgorithm(), leafPub)
	if err != nil {
		return err
	}
	if len(quote.GetSignature()) != expectedSigSize {
		return fmt.Errorf("%w: got %d bytes, expected %d bytes for algorithm %d", ErrSignatureSize, len(quote.GetSignature()), expectedSigSize, quote.GetAlgorithm())
	}

	msg := &cose.Sign1Message{
		Headers: cose.Headers{
			RawProtected: rawProtected,
			Protected:    protected,
		},
		Payload:   quote.GetRawPayload(),
		Signature: quote.GetSignature(),
	}
	if err := msg.Verify(nil, verifier); err != nil {
		return fmt.Errorf("%w: %v", ErrSignatureInvalid, err)
	}
	return nil
}

// newDiceVerifier returns a COSE verifier and expected raw signature length for
// the given COSE algorithm identifier and leaf certificate public key.
//
// Currently only ES384 (COSE algorithm ID -35) is enabled. Additional COSE
// algorithms can be added as separate cases below without changing callers:
//   - TODO: Add ESP384 (COSE algorithm ID -51, RFC 9864 fully-specified ECDSA
//     P-384 with SHA-384) once confirmed in the DICE quote profile.
//   - TODO: Add ML-DSA-87 (COSE algorithm ID -50) when post-quantum signing
//     support is introduced.
func newDiceVerifier(alg int64, pub crypto.PublicKey) (cose.Verifier, int, error) {
	switch cose.Algorithm(alg) {
	case cose.AlgorithmES384:
		ecdsaPub, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return nil, 0, fmt.Errorf("%w: expected ECDSA public key for ES384, got %T", ErrCertInvalidKey, pub)
		}
		if ecdsaPub.Curve != elliptic.P384() {
			return nil, 0, fmt.Errorf("%w: expected P-384 curve for ES384, got %s", ErrCertInvalidKey, ecdsaPub.Curve.Params().Name)
		}
		verifier, err := cose.NewVerifier(cose.AlgorithmES384, ecdsaPub)
		if err != nil {
			return nil, 0, fmt.Errorf("%w: %v", ErrSignatureInvalid, err)
		}
		return verifier, es384SignatureSize, nil
	default:
		return nil, 0, fmt.Errorf("%w: COSE algorithm %d", ErrAlgorithmUnsupported, alg)
	}
}
