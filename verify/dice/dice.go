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

// Package dice provides the library functions to verify a DICE-based TDX quote.
package dice

import (
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	pb "github.com/google/go-tdx-guest/proto/tdx"
)

var (
	// Embedded certificate used when trusted root is nil for DICE quotes.
	// Source: https://tsci.intel.com/content/DICE/RootCA/DCP_DICE_Global_Root_CA.cer
	//go:embed trusted_dice_root.pem
	defaultDiceRootCertByte []byte

	trustedDiceRootCertificate *x509.Certificate

	// ErrQuoteNil error returned when DiceQuote is nil
	ErrQuoteNil = errors.New("DiceQuote is nil")

	// ErrOptionsNil error returned when Options parameter is nil
	ErrOptionsNil = errors.New("options parameter is nil")

	// ErrProtectedHeaderEmpty error returned when DiceQuote protected header is empty
	ErrProtectedHeaderEmpty = errors.New("DiceQuote protected header is empty")

	// ErrProtectedHeaderInvalid error returned when DiceQuote protected header is invalid CBOR
	ErrProtectedHeaderInvalid = errors.New("DiceQuote protected header is invalid")

	// ErrAlgorithmInvalid error returned when algorithm in protected header is missing or invalid
	ErrAlgorithmInvalid = errors.New("missing or invalid algorithm in protected header")

	// ErrAlgorithmUnsupported error returned when DiceQuote signing algorithm is not supported
	ErrAlgorithmUnsupported = errors.New("DiceQuote signing algorithm is not supported")

	// ErrAlgorithmMismatch error returned when DiceQuote algorithm does not match protected header
	ErrAlgorithmMismatch = errors.New("DiceQuote algorithm does not match protected header")

	// ErrCritLabelUnsupported error returned when protected header contains an unsupported critical label
	ErrCritLabelUnsupported = errors.New("unsupported critical header label in protected header")

	// ErrPayloadEmpty error returned when DiceQuote raw CWT payload is empty
	ErrPayloadEmpty = errors.New("DiceQuote CWT payload is empty")

	// ErrSignatureEmpty error returned when DiceQuote signature is empty
	ErrSignatureEmpty = errors.New("DiceQuote signature is empty")

	// ErrSignatureSize error returned when DiceQuote signature size does not match algorithm
	ErrSignatureSize = errors.New("invalid DiceQuote signature size")

	// ErrSignatureInvalid error returned when COSE_Sign1 signature verification fails
	ErrSignatureInvalid = errors.New("COSE_Sign1 signature verification failed")

	// ErrCertChainEmpty error returned when DiceQuote certificate chain is empty
	ErrCertChainEmpty = errors.New("DiceQuote certificate chain is empty")

	// ErrCertChainTooLarge error returned when DiceQuote certificate chain exceeds maximum allowed length
	ErrCertChainTooLarge = errors.New("DiceQuote certificate chain exceeds maximum allowed length")

	// ErrCertEmpty error returned when a DER certificate entry in the chain is empty
	ErrCertEmpty = errors.New("certificate entry in chain is empty")

	// ErrCertParse error returned when a DER certificate in the chain fails to parse
	ErrCertParse = errors.New("failed to parse DER certificate")

	// ErrUnhandledCriticalExt error returned when a certificate contains an unrecognized critical extension
	ErrUnhandledCriticalExt = errors.New("certificate contains an unrecognized critical extension")

	// ErrCriticalExtInvalid error returned when a recognized DICE critical extension is malformed
	ErrCriticalExtInvalid = errors.New("certificate contains a malformed DICE critical extension")

	// ErrLeafCertNotFound error returned when no valid signing leaf certificate is found in the certificate bag
	ErrLeafCertNotFound = errors.New("unable to identify signing leaf certificate in certificate chain")

	// ErrLeafCertAmbiguous error returned when multiple candidate signing leaf certificates match
	ErrLeafCertAmbiguous = errors.New("multiple candidate signing leaf certificates found in certificate chain")

	// ErrCertChainVerify error returned when X.509 certificate chain verification fails
	ErrCertChainVerify = errors.New("DICE certificate chain verification failed")

	// ErrCertInvalidKey error returned when a certificate public key type or curve does not satisfy DICE profile
	ErrCertInvalidKey = errors.New("certificate public key does not satisfy DICE profile")

	// ErrCertInvalidSigAlg error returned when a certificate signature algorithm does not satisfy DICE profile
	ErrCertInvalidSigAlg = errors.New("certificate signature algorithm does not satisfy DICE profile")

	// ErrCertInvalidKeyUsage error returned when a certificate key usage or basic constraints do not satisfy role
	ErrCertInvalidKeyUsage = errors.New("certificate key usage or basic constraints are invalid for its role")

	// ErrCertInvalidExtKeyUsage error returned when the leaf certificate is missing a required DICE attestation EKU
	ErrCertInvalidExtKeyUsage = errors.New("leaf certificate is missing required DICE attestation extended key usage")

	// ErrRootCertUnavailable error returned when no trusted DICE root certificate is available
	ErrRootCertUnavailable = errors.New("trusted DICE root certificate is unavailable")
)

// Options represents verification options for a DICE-based TDX attestation quote.
type Options struct {
	// Now is the reference time used to check certificate validity windows.
	// If zero, time.Now() is used.
	Now time.Time

	// TrustedRoots specifies the root CertPool trusted when verifying the DICE
	// certificate chain. If nil, the embedded Intel DICE Root CA certificate is used.
	TrustedRoots *x509.CertPool
}

// DefaultOptions returns a default Options configuration for DICE quote verification.
func DefaultOptions() *Options {
	return &Options{
		Now: time.Now(),
	}
}

// VerifyQuote verifies the DICE X.509 certificate chain (anchored at
// options.TrustedRoots or the embedded DCP DICE Global Root CA) and the
// COSE_Sign1 cryptographic signature of a parsed DiceQuote protobuf message.
func VerifyQuote(quote *pb.DiceQuote, options *Options) error {
	_, err := verifyQuoteAndChain(quote, options)
	return err
}

func verifyQuoteAndChain(quote *pb.DiceQuote, options *Options) ([]*x509.Certificate, error) {
	if quote == nil {
		return nil, ErrQuoteNil
	}
	if options == nil {
		return nil, ErrOptionsNil
	}
	if err := checkQuoteInputs(quote); err != nil {
		return nil, err
	}

	verifiedChain, err := verifyCertificateChain(quote.GetCertChain(), quote.GetKeyId(), options)
	if err != nil {
		return nil, err
	}

	leafCert := verifiedChain[0]
	if err := verifyCOSESign1(quote, leafCert.PublicKey); err != nil {
		return nil, fmt.Errorf("verifying COSE_Sign1 signature failed: %w", err)
	}
	return verifiedChain, nil
}

func checkQuoteInputs(quote *pb.DiceQuote) error {
	if len(quote.GetProtectedHeader()) == 0 {
		return ErrProtectedHeaderEmpty
	}
	if len(quote.GetRawPayload()) == 0 {
		return ErrPayloadEmpty
	}
	if len(quote.GetCertChain()) == 0 {
		return ErrCertChainEmpty
	}
	if len(quote.GetSignature()) == 0 {
		return ErrSignatureEmpty
	}
	return nil
}

// Parse root certificate from the embedded trusted_dice_root certificate file.
func init() {
	diceRoot, _ := pem.Decode(defaultDiceRootCertByte)
	if diceRoot != nil {
		trustedDiceRootCertificate, _ = x509.ParseCertificate(diceRoot.Bytes)
	}
}
