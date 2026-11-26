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

	"github.com/google/go-tdx-guest/abi"
	pb "github.com/google/go-tdx-guest/proto/tdx"
)

var (
	// Embedded certificate used when trusted root is nil for DICE quotes.
	// Source: https://tsci.intel.com/content/DICE/RootCA/DCP_DICE_Global_Root_CA.cer
	//go:embed trusted_dice_root.pem
	defaultDiceRootCertByte []byte

	trustedDiceRootCertificate *x509.Certificate

	// ErrOptionsNil error returned when Options parameter is nil
	ErrOptionsNil = errors.New("options parameter is nil")

	// ErrSignatureInvalid error returned when COSE_Sign1 signature verification fails
	ErrSignatureInvalid = errors.New("COSE_Sign1 signature verification failed")

	// ErrCertChainTooLarge error returned when DiceQuote certificate chain exceeds maximum allowed length
	ErrCertChainTooLarge = errors.New("DiceQuote certificate chain exceeds maximum allowed length")

	// ErrCertParse error returned when a DER certificate in the chain fails to parse
	ErrCertParse = errors.New("failed to parse DER certificate")

	// ErrUnhandledCriticalExt error returned when a certificate contains an unrecognized critical extension
	ErrUnhandledCriticalExt = errors.New("certificate contains an unrecognized critical extension")

	// ErrCriticalExtInvalid error returned when a recognized DICE critical extension is malformed
	ErrCriticalExtInvalid = errors.New("certificate contains a malformed DICE critical extension")

	// ErrLeafCertNotFound error returned when no non-CA leaf certificate is found in the certificate bag
	ErrLeafCertNotFound = errors.New("unable to identify signing leaf certificate in certificate chain")

	// ErrCertChainVerify error returned when X.509 certificate chain verification fails
	ErrCertChainVerify = errors.New("DICE certificate chain verification failed")

	// ErrCertInvalidKey error returned when a certificate public key type or curve does not satisfy DICE profile
	ErrCertInvalidKey = errors.New("certificate public key does not satisfy DICE profile")

	// ErrCertInvalidSigAlg error returned when a certificate signature algorithm does not satisfy DICE profile
	ErrCertInvalidSigAlg = errors.New("certificate signature algorithm does not satisfy DICE profile")

	// ErrCertInvalidKeyUsage error returned when the leaf certificate key usage is invalid for signing
	ErrCertInvalidKeyUsage = errors.New("leaf certificate key usage is invalid for signing")

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

// VerifyQuote verifies the COSE_Sign1 cryptographic signature and the DICE X.509
// certificate chain (anchored at options.TrustedRoots or the embedded DCP DICE
// Global Root CA) of a parsed DiceQuote protobuf message.
func VerifyQuote(quote *pb.DiceQuote, options *Options) error {
	return verifyQuote(quote, options)
}

func verifyQuote(quote *pb.DiceQuote, options *Options) error {
	if options == nil {
		return ErrOptionsNil
	}

	msg, err := abi.DiceQuoteToCOSESign1(quote)
	if err != nil {
		return fmt.Errorf("invalid DICE quote envelope: %w", err)
	}

	certs, err := parseAndValidateCerts(quote.GetCertChain())
	if err != nil {
		return err
	}

	leafCert, err := selectLeafCertBySignature(certs, msg, quote.GetAlgorithm())
	if err != nil {
		return err
	}

	return verifyCertificateChain(certs, leafCert, options)
}

// Parse root certificate from the embedded trusted_dice_root certificate file.
func init() {
	diceRoot, _ := pem.Decode(defaultDiceRootCertByte)
	if diceRoot != nil {
		trustedDiceRootCertificate, _ = x509.ParseCertificate(diceRoot.Bytes)
	}
}
