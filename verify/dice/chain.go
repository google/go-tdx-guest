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
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"time"
)

const (
	// maxDiceCertChainLen bounds the number of certificates accepted in a single
	// x5bag / x5chain to protect against excessive memory/CPU use on untrusted inputs
	// while comfortably accommodating multi-socket and bound-device bags.
	maxDiceCertChainLen = 512
)

var (
	// TCG DICE X.509 extension OIDs that may be marked critical.
	// See TCG DICE Concise Evidence Binding / Attestation Architecture specifications.
	oidTCGDICEMultiTcbInfo             = asn1.ObjectIdentifier{2, 23, 133, 5, 4, 5}
	oidTCGDICEConceptualMessageWrapper = asn1.ObjectIdentifier{2, 23, 133, 5, 4, 9}

	// TCG DICE Extended Key Usage OIDs for attestation signing leaf certificates.
	// TODO: Confirm whether finalized DICE leaf certificates use
	// tcg-dice-kp-attestInit (.100.8) or tcg-dice-kp-attestLoc (.100.9, observed
	// in the current sample quote) once the final sample quote is available.
	oidTCGDICEKpAttestInit = asn1.ObjectIdentifier{2, 23, 133, 5, 4, 100, 8}
	oidTCGDICEKpAttestLoc  = asn1.ObjectIdentifier{2, 23, 133, 5, 4, 100, 9}
)

func parseAndValidateCerts(certChainDER [][]byte) ([]*x509.Certificate, error) {
	if len(certChainDER) > maxDiceCertChainLen {
		return nil, fmt.Errorf("%w: got %d certificates, max %d", ErrCertChainTooLarge, len(certChainDER), maxDiceCertChainLen)
	}

	certs := make([]*x509.Certificate, 0, len(certChainDER))
	for i, der := range certChainDER {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("%w: index %d: %v", ErrCertParse, i, err)
		}
		if err := processCriticalExtensions(cert); err != nil {
			return nil, fmt.Errorf("certificate index %d (%s): %w", i, cert.Subject.CommonName, err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

func verifyCertificateChain(certs []*x509.Certificate, leafCert *x509.Certificate, options *Options) ([]*x509.Certificate, error) {
	if err := validateLeafCertUsage(leafCert); err != nil {
		return nil, err
	}

	roots, err := buildRootPool(options)
	if err != nil {
		return nil, err
	}
	intermediates := buildIntermediatePool(certs, leafCert)

	now := options.Now
	if now.IsZero() {
		now = time.Now()
	}

	verifyOpts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		// TCG DICE certificates carry custom EKU OIDs (2.23.133.5.4.100.*) in
		// UnknownExtKeyUsage rather than standard TLS EKUs. Use ExtKeyUsageAny
		// here and enforce DICE EKU requirements explicitly via validateLeafCertUsage.
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	chains, err := leafCert.Verify(verifyOpts)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCertChainVerify, err)
	}
	if len(chains[0]) < 2 {
		return nil, fmt.Errorf("%w: verified chain has fewer than 2 certificates", ErrCertChainVerify)
	}

	verifiedChain := chains[0]
	if err := validateVerifiedChainProfile(verifiedChain); err != nil {
		return nil, err
	}
	return verifiedChain, nil
}

// processCriticalExtensions verifies that all critical extensions not natively
// handled by crypto/x509 belong to the recognized TCG DICE extension allowlist
// and have well-formed DER structure, then removes only those handled OIDs from
// cert.UnhandledCriticalExtensions so x509.Certificate.Verify can proceed.
func processCriticalExtensions(cert *x509.Certificate) error {
	if len(cert.UnhandledCriticalExtensions) == 0 {
		return nil
	}

	for _, oid := range cert.UnhandledCriticalExtensions {
		if !isRecognizedDiceCriticalExt(oid) {
			return fmt.Errorf("%w: OID %s", ErrUnhandledCriticalExt, oid.String())
		}
		extVal, found := findExtensionValue(cert, oid)
		if !found || len(extVal) == 0 {
			return fmt.Errorf("%w: missing value for OID %s", ErrCriticalExtInvalid, oid.String())
		}
		if err := validateDERSequence(extVal); err != nil {
			return fmt.Errorf("%w: OID %s: %v", ErrCriticalExtInvalid, oid.String(), err)
		}
	}

	cert.UnhandledCriticalExtensions = nil
	return nil
}

func isRecognizedDiceCriticalExt(oid asn1.ObjectIdentifier) bool {
	return oid.Equal(oidTCGDICEMultiTcbInfo) || oid.Equal(oidTCGDICEConceptualMessageWrapper)
}

func findExtensionValue(cert *x509.Certificate, oid asn1.ObjectIdentifier) ([]byte, bool) {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oid) {
			return ext.Value, true
		}
	}
	return nil, false
}

func validateDERSequence(b []byte) error {
	var raw asn1.RawValue
	rest, err := asn1.Unmarshal(b, &raw)
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return fmt.Errorf("trailing bytes (%d) after ASN.1 value", len(rest))
	}
	if raw.Class != asn1.ClassUniversal || raw.Tag != asn1.TagSequence || !raw.IsCompound {
		return fmt.Errorf("expected ASN.1 SEQUENCE, got class=%d tag=%d compound=%v", raw.Class, raw.Tag, raw.IsCompound)
	}
	return nil
}

func validateLeafCertUsage(cert *x509.Certificate) error {
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return fmt.Errorf("%w: leaf certificate missing digitalSignature key usage", ErrCertInvalidKeyUsage)
	}
	if cert.KeyUsage&x509.KeyUsageCertSign != 0 {
		return fmt.Errorf("%w: leaf certificate must not have keyCertSign key usage", ErrCertInvalidKeyUsage)
	}
	if !hasDiceAttestationEKU(cert) {
		return fmt.Errorf("%w: subject %q", ErrCertInvalidExtKeyUsage, cert.Subject.CommonName)
	}
	return nil
}

func hasDiceAttestationEKU(cert *x509.Certificate) bool {
	for _, oid := range cert.UnknownExtKeyUsage {
		if oid.Equal(oidTCGDICEKpAttestInit) || oid.Equal(oidTCGDICEKpAttestLoc) {
			return true
		}
	}
	return false
}

func buildRootPool(options *Options) (*x509.CertPool, error) {
	if options.TrustedRoots != nil {
		return options.TrustedRoots, nil
	}
	if trustedDiceRootCertificate == nil {
		return nil, ErrRootCertUnavailable
	}
	roots := x509.NewCertPool()
	roots.AddCert(trustedDiceRootCertificate)
	return roots, nil
}

func buildIntermediatePool(certs []*x509.Certificate, leaf *x509.Certificate) *x509.CertPool {
	intermediates := x509.NewCertPool()
	for _, cert := range certs {
		if cert == leaf || !cert.IsCA {
			continue
		}
		// Never treat self-signed certificates from the untrusted quote bag as intermediates.
		if isSelfSignedCert(cert) {
			continue
		}
		intermediates.AddCert(cert)
	}
	return intermediates
}

func isSelfSignedCert(cert *x509.Certificate) bool {
	return bytes.Equal(cert.RawIssuer, cert.RawSubject) && cert.CheckSignatureFrom(cert) == nil
}

func validateVerifiedChainProfile(chain []*x509.Certificate) error {
	for i, cert := range chain {
		if err := validateCertCryptoProfile(cert); err != nil {
			return fmt.Errorf("verified chain[%d] (%s): %w", i, cert.Subject.CommonName, err)
		}
	}
	return nil
}

// validateCertCryptoProfile enforces the cryptographic strength requirements for
// DICE certificates (currently ECDSA P-384 with SHA-384).
//
// TODO: Extend this check when additional DICE signing profiles (such as
// post-quantum algorithms like ML-DSA-87) are introduced.
func validateCertCryptoProfile(cert *x509.Certificate) error {
	if cert.SignatureAlgorithm != x509.ECDSAWithSHA384 {
		return fmt.Errorf("%w: got %s, expected %s", ErrCertInvalidSigAlg, cert.SignatureAlgorithm, x509.ECDSAWithSHA384)
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("%w: expected ECDSA public key, got %T", ErrCertInvalidKey, cert.PublicKey)
	}
	if pub.Curve != elliptic.P384() {
		return fmt.Errorf("%w: expected P-384 curve, got %s", ErrCertInvalidKey, pub.Curve.Params().Name)
	}
	return nil
}
