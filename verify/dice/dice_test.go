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
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	pb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/go-tdx-guest/testing/testdata"
	"github.com/veraison/go-cose"
	"google.golang.org/protobuf/proto"
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

var (
	// Reference time inside the validity window of all 9 certificates in RawQuoteDICE
	// (IDevID NotBefore is 2026-08-02T00:00:00Z; earliest NotAfter is 2048-08-24T23:59:59Z).
	realSampleValidTime = time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

	oidTestUnknownCritical = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55555, 1, 1}
	oidTestOtherEKU        = asn1.ObjectIdentifier{2, 23, 133, 5, 4, 100, 12}
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

// decodeRawDiceQuoteForTest extracts the COSE_Sign1 envelope fields from raw
// CWT-wrapped DICE quote bytes into a pb.DiceQuote for offline verification tests.
func decodeRawDiceQuoteForTest(t *testing.T, raw []byte) *pb.DiceQuote {
	t.Helper()
	var outer cbor.RawTag
	if err := cbor.Unmarshal(raw, &outer); err != nil {
		t.Fatalf("failed to unmarshal outer CWT tag: %v", err)
	}
	if outer.Number != 61 {
		t.Fatalf("expected outer CBOR tag 61, got %d", outer.Number)
	}

	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(outer.Content); err != nil {
		t.Fatalf("failed to unmarshal COSE_Sign1: %v", err)
	}

	var protectedBytes []byte
	if err := cbor.Unmarshal(msg.Headers.RawProtected, &protectedBytes); err != nil {
		t.Fatalf("failed to decode RawProtected bstr: %v", err)
	}
	alg, err := msg.Headers.Protected.Algorithm()
	if err != nil {
		t.Fatalf("failed to read algorithm from protected header: %v", err)
	}

	var kid []byte
	if v, ok := msg.Headers.Unprotected[cose.HeaderLabelKeyID]; ok {
		kid, _ = v.([]byte)
	}
	var contentType string
	if v, ok := msg.Headers.Unprotected[cose.HeaderLabelContentType]; ok {
		contentType, _ = v.(string)
	}
	rawCerts, ok := msg.Headers.Unprotected[cose.HeaderLabelX5Bag].([]any)
	if !ok {
		t.Fatalf("expected []any under x5bag, got %T", msg.Headers.Unprotected[cose.HeaderLabelX5Bag])
	}
	certChain := make([][]byte, 0, len(rawCerts))
	for i, c := range rawCerts {
		b, ok := c.([]byte)
		if !ok {
			t.Fatalf("certChain[%d] is %T, want []byte", i, c)
		}
		certChain = append(certChain, b)
	}

	return &pb.DiceQuote{
		ProtectedHeader: protectedBytes,
		Algorithm:       int64(alg),
		KeyId:           kid,
		ContentType:     contentType,
		CertChain:       certChain,
		RawPayload:      msg.Payload,
		Signature:       msg.Signature,
	}
}

func TestVerifyQuoteRealSample(t *testing.T) {
	quote := decodeRawDiceQuoteForTest(t, testdata.RawQuoteDICE)
	opts := &Options{
		Now: realSampleValidTime,
	}

	chain, err := verifyQuoteAndChain(quote, opts)
	if err != nil {
		t.Fatalf("verifyQuoteAndChain(RawQuoteDICE) failed: %v", err)
	}
	if len(chain) != 9 {
		t.Errorf("len(verifiedChain) = %d, want 9", len(chain))
	}
	if chain[len(chain)-1].Subject.CommonName != expectedDiceRootCN {
		t.Errorf("root CN = %q, want %q", chain[len(chain)-1].Subject.CommonName, expectedDiceRootCN)
	}

	if err := VerifyQuote(quote, opts); err != nil {
		t.Fatalf("VerifyQuote(RawQuoteDICE) failed: %v", err)
	}

	// Reordering x5bag certificates should still verify cleanly.
	reordered := proto.Clone(quote).(*pb.DiceQuote)
	for i, j := 0, len(reordered.CertChain)-1; i < j; i, j = i+1, j-1 {
		reordered.CertChain[i], reordered.CertChain[j] = reordered.CertChain[j], reordered.CertChain[i]
	}
	if err := VerifyQuote(reordered, opts); err != nil {
		t.Fatalf("VerifyQuote(reordered RawQuoteDICE) failed: %v", err)
	}

	// Tampering with payload, signature, or protected header must fail verification.
	tamperedPayload := proto.Clone(quote).(*pb.DiceQuote)
	tamperedPayload.RawPayload[len(tamperedPayload.RawPayload)-1] ^= 0xff
	if err := VerifyQuote(tamperedPayload, opts); !errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("tampered payload error = %v, want %v", err, ErrSignatureInvalid)
	}

	tamperedSig := proto.Clone(quote).(*pb.DiceQuote)
	tamperedSig.Signature[0] ^= 0xff
	if err := VerifyQuote(tamperedSig, opts); !errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("tampered signature error = %v, want %v", err, ErrSignatureInvalid)
	}

	tamperedProtected := proto.Clone(quote).(*pb.DiceQuote)
	altProtected, err := diceCBOREncMode.Marshal(map[any]any{
		cose.HeaderLabelAlgorithm:   cose.AlgorithmES384,
		cose.HeaderLabelContentType: "application/eat+cwt",
	})
	if err != nil {
		t.Fatalf("failed to marshal alternate protected header: %v", err)
	}
	tamperedProtected.ProtectedHeader = altProtected
	if err := VerifyQuote(tamperedProtected, opts); !errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("tampered protected header error = %v, want %v", err, ErrSignatureInvalid)
	}

	// Expired reference time must fail chain verification.
	expiredOpts := &Options{Now: time.Date(2060, 1, 1, 0, 0, 0, 0, time.UTC)}
	if err := VerifyQuote(quote, expiredOpts); !errors.Is(err, ErrCertChainVerify) {
		t.Errorf("expired Now error = %v, want %v", err, ErrCertChainVerify)
	}

	// Not-yet-valid reference time must fail chain verification.
	earlyOpts := &Options{Now: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)}
	if err := VerifyQuote(quote, earlyOpts); !errors.Is(err, ErrCertChainVerify) {
		t.Errorf("early Now error = %v, want %v", err, ErrCertChainVerify)
	}
}

type syntheticDiceFixture struct {
	rootCert     *x509.Certificate
	rootKey      *ecdsa.PrivateKey
	intermCerts  []*x509.Certificate
	intermKeys   []*ecdsa.PrivateKey
	leafCert     *x509.Certificate
	leafKey      *ecdsa.PrivateKey
	trustedRoots *x509.CertPool
	now          time.Time
	quote        *pb.DiceQuote
}

func makeDERSequence(t *testing.T, inner []byte) []byte {
	t.Helper()
	seq, err := asn1.Marshal(struct{ Data []byte }{Data: inner})
	if err != nil {
		t.Fatalf("failed to marshal DER sequence: %v", err)
	}
	return seq
}

func generateP384Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate P-384 key: %v", err)
	}
	return key
}

func createTestCert(t *testing.T, tmpl *x509.Certificate, parent *x509.Certificate, pub any, signerKey any) (*x509.Certificate, []byte) {
	t.Helper()
	if parent == nil {
		parent = tmpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signerKey)
	if err != nil {
		t.Fatalf("failed to create certificate %q: %v", tmpl.Subject.CommonName, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse created certificate %q: %v", tmpl.Subject.CommonName, err)
	}
	return cert, der
}

func signTestDiceQuote(t *testing.T, protected map[any]any, kid []byte, certChain [][]byte, payload []byte, leafKey *ecdsa.PrivateKey) *pb.DiceQuote {
	t.Helper()
	protectedBytes, err := diceCBOREncMode.Marshal(protected)
	if err != nil {
		t.Fatalf("failed to marshal protected map: %v", err)
	}
	rawProtected, err := diceCBOREncMode.Marshal(protectedBytes)
	if err != nil {
		t.Fatalf("failed to marshal protected bstr: %v", err)
	}

	var protectedHdr cose.ProtectedHeader
	if err := protectedHdr.UnmarshalCBOR(rawProtected); err != nil {
		t.Fatalf("failed to unmarshal protected header: %v", err)
	}

	msg := &cose.Sign1Message{
		Headers: cose.Headers{
			RawProtected: rawProtected,
			Protected:    protectedHdr,
		},
		Payload: payload,
	}
	signer, err := cose.NewSigner(cose.AlgorithmES384, leafKey)
	if err != nil {
		t.Fatalf("failed to create ES384 signer: %v", err)
	}
	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		t.Fatalf("failed to sign COSE_Sign1 message: %v", err)
	}

	alg, _ := protectedHdr.Algorithm()
	return &pb.DiceQuote{
		ProtectedHeader: protectedBytes,
		Algorithm:       int64(alg),
		KeyId:           kid,
		ContentType:     "application/eat+cwt",
		CertChain:       certChain,
		RawPayload:      payload,
		Signature:       msg.Signature,
	}
}

func newSyntheticDiceFixture(t *testing.T, leafEKU asn1.ObjectIdentifier) *syntheticDiceFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	notBefore := now.Add(-24 * time.Hour)
	notAfter := now.Add(24 * time.Hour)

	rootKey := generateP384Key(t)
	rootSKI := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test DICE Root CA"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          rootSKI,
		SignatureAlgorithm:    x509.ECDSAWithSHA384,
	}
	rootCert, rootDER := createTestCert(t, rootTmpl, nil, &rootKey.PublicKey, rootKey)

	// Build 7 intermediate CAs to mirror the 9-certificate DICE chain hierarchy,
	// including critical DICE MultiTcbInfo and CMW extensions.
	intermCerts := make([]*x509.Certificate, 0, 7)
	intermKeys := make([]*ecdsa.PrivateKey, 0, 7)
	intermDERs := make([][]byte, 0, 7)
	parentCert := rootCert
	parentKey := rootKey
	for lvl := 1; lvl <= 7; lvl++ {
		k := generateP384Key(t)
		ski := []byte{0x10, byte(lvl), 0xaa, 0xbb, 0xcc}
		var exts []pkix.Extension
		if lvl == 5 {
			exts = append(exts, pkix.Extension{
				Id:       oidTCGDICEMultiTcbInfo,
				Critical: true,
				Value:    makeDERSequence(t, []byte("multi-tcb-info")),
			})
		}
		if lvl == 7 {
			exts = append(exts, pkix.Extension{
				Id:       oidTCGDICEConceptualMessageWrapper,
				Critical: true,
				Value:    makeDERSequence(t, []byte("platform-cmw")),
			})
		}
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(int64(lvl + 1)),
			Subject:               pkix.Name{CommonName: fmt.Sprintf("Test DICE Intermediate CA %d", lvl)},
			NotBefore:             notBefore,
			NotAfter:              notAfter,
			KeyUsage:              x509.KeyUsageCertSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
			SubjectKeyId:          ski,
			UnknownExtKeyUsage:    []asn1.ObjectIdentifier{oidTestOtherEKU},
			ExtraExtensions:       exts,
			SignatureAlgorithm:    x509.ECDSAWithSHA384,
		}
		c, der := createTestCert(t, tmpl, parentCert, &k.PublicKey, parentKey)
		intermCerts = append(intermCerts, c)
		intermKeys = append(intermKeys, k)
		intermDERs = append(intermDERs, der)
		parentCert = c
		parentKey = k
	}

	leafKey := generateP384Key(t)
	leafSKI := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22}
	leafTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "Test DICE Leaf Attestation"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		SubjectKeyId:          leafSKI,
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{leafEKU},
		ExtraExtensions: []pkix.Extension{
			{
				Id:       oidTCGDICEConceptualMessageWrapper,
				Critical: true,
				Value:    makeDERSequence(t, []byte("leaf-cmw")),
			},
		},
		SignatureAlgorithm: x509.ECDSAWithSHA384,
	}
	leafCert, leafDER := createTestCert(t, leafTmpl, parentCert, &leafKey.PublicKey, parentKey)

	// Intentionally store certs unordered (mirroring real x5bag layout).
	certBag := make([][]byte, 0, 9)
	certBag = append(certBag, intermDERs[6], rootDER)
	certBag = append(certBag, intermDERs[:6]...)
	certBag = append(certBag, leafDER)

	// Full kid starts with leaf SKI prefix (matching real sample behavior).
	kid := append(append([]byte{}, leafSKI...), 0x99, 0x88, 0x77, 0x66)
	payload, err := diceCBOREncMode.Marshal(map[any]any{
		1:  "Test DICE Issuer",
		10: make([]byte, 64),
	})
	if err != nil {
		t.Fatalf("failed to marshal test payload: %v", err)
	}

	quote := signTestDiceQuote(
		t,
		map[any]any{
			cose.HeaderLabelAlgorithm:   cose.AlgorithmES384,
			cose.HeaderLabelContentType: "application/eat+cwt",
			cose.HeaderLabelCritical:    []any{cose.HeaderLabelAlgorithm, cose.HeaderLabelContentType},
		},
		kid,
		certBag,
		payload,
		leafKey,
	)

	roots := x509.NewCertPool()
	roots.AddCert(rootCert)

	return &syntheticDiceFixture{
		rootCert:     rootCert,
		rootKey:      rootKey,
		intermCerts:  intermCerts,
		intermKeys:   intermKeys,
		leafCert:     leafCert,
		leafKey:      leafKey,
		trustedRoots: roots,
		now:          now,
		quote:        quote,
	}
}

func TestVerifyQuoteSyntheticPositive(t *testing.T) {
	t.Run("attestLoc EKU with unordered 9-cert bag", func(t *testing.T) {
		fx := newSyntheticDiceFixture(t, oidTCGDICEKpAttestLoc)
		if err := VerifyQuote(fx.quote, &Options{TrustedRoots: fx.trustedRoots, Now: fx.now}); err != nil {
			t.Fatalf("VerifyQuote failed: %v", err)
		}
	})

	t.Run("attestInit EKU and zero Now defaults to time.Now", func(t *testing.T) {
		fx := newSyntheticDiceFixture(t, oidTCGDICEKpAttestInit)
		if err := VerifyQuote(fx.quote, &Options{TrustedRoots: fx.trustedRoots}); err != nil {
			t.Fatalf("VerifyQuote with zero Now failed: %v", err)
		}
	})

	t.Run("DefaultOptions returns non-nil with current time", func(t *testing.T) {
		opts := DefaultOptions()
		if opts == nil || opts.Now.IsZero() {
			t.Fatalf("DefaultOptions() = %+v, want non-nil with non-zero Now", opts)
		}
	})

	t.Run("bag with extra non-attestation device leaf cert", func(t *testing.T) {
		fx := newSyntheticDiceFixture(t, oidTCGDICEKpAttestLoc)
		otherKey := generateP384Key(t)
		otherTmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(201),
			Subject:               pkix.Name{CommonName: "Auxiliary Device Cert"},
			NotBefore:             fx.now.Add(-time.Hour),
			NotAfter:              fx.now.Add(time.Hour),
			KeyUsage:              x509.KeyUsageKeyEncipherment,
			BasicConstraintsValid: true,
			IsCA:                  false,
			SubjectKeyId:          []byte{0xde, 0xad},
			SignatureAlgorithm:    x509.ECDSAWithSHA384,
		}
		_, otherDER := createTestCert(t, otherTmpl, fx.intermCerts[6], &otherKey.PublicKey, fx.intermKeys[6])

		q := proto.Clone(fx.quote).(*pb.DiceQuote)
		q.CertChain = append(q.CertChain, otherDER)
		q.KeyId = nil // disambiguation succeeds via DICE attestation EKU + key usage alone
		if err := VerifyQuote(q, &Options{TrustedRoots: fx.trustedRoots, Now: fx.now}); err != nil {
			t.Fatalf("VerifyQuote with auxiliary device cert failed: %v", err)
		}
	})

	t.Run("bag with two DICE attestation leaves disambiguated by kid", func(t *testing.T) {
		fx := newSyntheticDiceFixture(t, oidTCGDICEKpAttestLoc)
		secondKey := generateP384Key(t)
		secondTmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(202),
			Subject:               pkix.Name{CommonName: "Second DICE Leaf"},
			NotBefore:             fx.now.Add(-time.Hour),
			NotAfter:              fx.now.Add(time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
			IsCA:                  false,
			SubjectKeyId:          []byte{0x55, 0x66, 0x77, 0x88},
			UnknownExtKeyUsage:    []asn1.ObjectIdentifier{oidTCGDICEKpAttestLoc},
			SignatureAlgorithm:    x509.ECDSAWithSHA384,
		}
		_, secondDER := createTestCert(t, secondTmpl, fx.intermCerts[6], &secondKey.PublicKey, fx.intermKeys[6])

		q := proto.Clone(fx.quote).(*pb.DiceQuote)
		q.CertChain = append(q.CertChain, secondDER)
		if err := VerifyQuote(q, &Options{TrustedRoots: fx.trustedRoots, Now: fx.now}); err != nil {
			t.Fatalf("VerifyQuote with two leaves disambiguated by kid failed: %v", err)
		}
	})
}

func TestVerifyQuoteNegative(t *testing.T) {
	fx := newSyntheticDiceFixture(t, oidTCGDICEKpAttestLoc)
	validOpts := &Options{TrustedRoots: fx.trustedRoots, Now: fx.now}

	t.Run("nil quote", func(t *testing.T) {
		if err := VerifyQuote(nil, validOpts); !errors.Is(err, ErrQuoteNil) {
			t.Errorf("got %v, want %v", err, ErrQuoteNil)
		}
	})

	t.Run("nil options", func(t *testing.T) {
		if err := VerifyQuote(fx.quote, nil); !errors.Is(err, ErrOptionsNil) {
			t.Errorf("got %v, want %v", err, ErrOptionsNil)
		}
	})

	t.Run("empty protected header", func(t *testing.T) {
		q := proto.Clone(fx.quote).(*pb.DiceQuote)
		q.ProtectedHeader = nil
		if err := VerifyQuote(q, validOpts); !errors.Is(err, ErrProtectedHeaderEmpty) {
			t.Errorf("got %v, want %v", err, ErrProtectedHeaderEmpty)
		}
	})

	t.Run("empty raw payload", func(t *testing.T) {
		q := proto.Clone(fx.quote).(*pb.DiceQuote)
		q.RawPayload = nil
		if err := VerifyQuote(q, validOpts); !errors.Is(err, ErrPayloadEmpty) {
			t.Errorf("got %v, want %v", err, ErrPayloadEmpty)
		}
	})

	t.Run("empty cert chain", func(t *testing.T) {
		q := proto.Clone(fx.quote).(*pb.DiceQuote)
		q.CertChain = nil
		if err := VerifyQuote(q, validOpts); !errors.Is(err, ErrCertChainEmpty) {
			t.Errorf("got %v, want %v", err, ErrCertChainEmpty)
		}
	})

	t.Run("empty signature", func(t *testing.T) {
		q := proto.Clone(fx.quote).(*pb.DiceQuote)
		q.Signature = nil
		if err := VerifyQuote(q, validOpts); !errors.Is(err, ErrSignatureEmpty) {
			t.Errorf("got %v, want %v", err, ErrSignatureEmpty)
		}
	})

	t.Run("cert chain exceeds max length", func(t *testing.T) {
		q := proto.Clone(fx.quote).(*pb.DiceQuote)
		q.CertChain = make([][]byte, maxDiceCertChainLen+1)
		if err := VerifyQuote(q, validOpts); !errors.Is(err, ErrCertChainTooLarge) {
			t.Errorf("got %v, want %v", err, ErrCertChainTooLarge)
		}
	})

	t.Run("empty cert entry in chain", func(t *testing.T) {
		q := proto.Clone(fx.quote).(*pb.DiceQuote)
		q.CertChain = append(q.CertChain, []byte{})
		if err := VerifyQuote(q, validOpts); !errors.Is(err, ErrCertEmpty) {
			t.Errorf("got %v, want %v", err, ErrCertEmpty)
		}
	})

	t.Run("malformed DER cert in chain", func(t *testing.T) {
		q := proto.Clone(fx.quote).(*pb.DiceQuote)
		q.CertChain = [][]byte{{0xde, 0xad, 0xbe, 0xef}}
		if err := VerifyQuote(q, validOpts); !errors.Is(err, ErrCertParse) {
			t.Errorf("got %v, want %v", err, ErrCertParse)
		}
	})

	t.Run("unrecognized critical extension rejected", func(t *testing.T) {
		badKey := generateP384Key(t)
		badTmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(300),
			Subject:               pkix.Name{CommonName: "Bad Critical Ext Leaf"},
			NotBefore:             fx.now.Add(-time.Hour),
			NotAfter:              fx.now.Add(time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
			IsCA:                  false,
			UnknownExtKeyUsage:    []asn1.ObjectIdentifier{oidTCGDICEKpAttestLoc},
			ExtraExtensions: []pkix.Extension{
				{
					Id:       oidTestUnknownCritical,
					Critical: true,
					Value:    makeDERSequence(t, []byte("unknown")),
				},
			},
			SignatureAlgorithm: x509.ECDSAWithSHA384,
		}
		_, badDER := createTestCert(t, badTmpl, fx.intermCerts[6], &badKey.PublicKey, fx.intermKeys[6])
		q := proto.Clone(fx.quote).(*pb.DiceQuote)
		q.CertChain[len(q.CertChain)-1] = badDER
		if err := VerifyQuote(q, validOpts); !errors.Is(err, ErrUnhandledCriticalExt) {
			t.Errorf("got %v, want %v", err, ErrUnhandledCriticalExt)
		}
	})

	t.Run("malformed recognized DICE critical extension rejected", func(t *testing.T) {
		badKey := generateP384Key(t)
		badTmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(301),
			Subject:               pkix.Name{CommonName: "Malformed CMW Leaf"},
			NotBefore:             fx.now.Add(-time.Hour),
			NotAfter:              fx.now.Add(time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
			IsCA:                  false,
			UnknownExtKeyUsage:    []asn1.ObjectIdentifier{oidTCGDICEKpAttestLoc},
			ExtraExtensions: []pkix.Extension{
				{
					Id:       oidTCGDICEConceptualMessageWrapper,
					Critical: true,
					Value:    []byte{0x04, 0x02, 0x01, 0x02}, // OCTET STRING instead of SEQUENCE
				},
			},
			SignatureAlgorithm: x509.ECDSAWithSHA384,
		}
		_, badDER := createTestCert(t, badTmpl, fx.intermCerts[6], &badKey.PublicKey, fx.intermKeys[6])
		q := proto.Clone(fx.quote).(*pb.DiceQuote)
		q.CertChain[len(q.CertChain)-1] = badDER
		if err := VerifyQuote(q, validOpts); !errors.Is(err, ErrCriticalExtInvalid) {
			t.Errorf("got %v, want %v", err, ErrCriticalExtInvalid)
		}
	})

	t.Run("no leaf cert in bag (CA certs only)", func(t *testing.T) {
		q := proto.Clone(fx.quote).(*pb.DiceQuote)
		q.CertChain = q.CertChain[:len(q.CertChain)-1] // remove leaf
		if err := VerifyQuote(q, validOpts); !errors.Is(err, ErrLeafCertNotFound) {
			t.Errorf("got %v, want %v", err, ErrLeafCertNotFound)
		}
	})

	t.Run("ambiguous leaf certs without kid", func(t *testing.T) {
		secondKey := generateP384Key(t)
		secondTmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(302),
			Subject:               pkix.Name{CommonName: "Ambiguous Leaf"},
			NotBefore:             fx.now.Add(-time.Hour),
			NotAfter:              fx.now.Add(time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
			IsCA:                  false,
			SubjectKeyId:          []byte{0x77, 0x88},
			UnknownExtKeyUsage:    []asn1.ObjectIdentifier{oidTCGDICEKpAttestLoc},
			SignatureAlgorithm:    x509.ECDSAWithSHA384,
		}
		_, secondDER := createTestCert(t, secondTmpl, fx.intermCerts[6], &secondKey.PublicKey, fx.intermKeys[6])

		q := proto.Clone(fx.quote).(*pb.DiceQuote)
		q.CertChain = append(q.CertChain, secondDER)
		q.KeyId = nil
		if err := VerifyQuote(q, validOpts); !errors.Is(err, ErrLeafCertAmbiguous) {
			t.Errorf("got %v, want %v", err, ErrLeafCertAmbiguous)
		}

		// Non-matching kid across multiple valid leaves yields ErrLeafCertNotFound.
		q.KeyId = []byte{0x00, 0x00, 0x00}
		if err := VerifyQuote(q, validOpts); !errors.Is(err, ErrLeafCertNotFound) {
			t.Errorf("non-matching kid got %v, want %v", err, ErrLeafCertNotFound)
		}
	})

	t.Run("leaf missing digitalSignature key usage", func(t *testing.T) {
		badKey := generateP384Key(t)
		badTmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(303),
			Subject:               pkix.Name{CommonName: "No DigitalSignature Leaf"},
			NotBefore:             fx.now.Add(-time.Hour),
			NotAfter:              fx.now.Add(time.Hour),
			KeyUsage:              x509.KeyUsageKeyEncipherment,
			BasicConstraintsValid: true,
			IsCA:                  false,
			UnknownExtKeyUsage:    []asn1.ObjectIdentifier{oidTCGDICEKpAttestLoc},
			SignatureAlgorithm:    x509.ECDSAWithSHA384,
		}
		_, badDER := createTestCert(t, badTmpl, fx.intermCerts[6], &badKey.PublicKey, fx.intermKeys[6])
		q := proto.Clone(fx.quote).(*pb.DiceQuote)
		q.CertChain[len(q.CertChain)-1] = badDER
		if err := VerifyQuote(q, validOpts); !errors.Is(err, ErrCertInvalidKeyUsage) {
			t.Errorf("got %v, want %v", err, ErrCertInvalidKeyUsage)
		}
	})

	t.Run("leaf missing required DICE attestation EKU", func(t *testing.T) {
		badKey := generateP384Key(t)
		badTmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(304),
			Subject:               pkix.Name{CommonName: "Missing DICE EKU Leaf"},
			NotBefore:             fx.now.Add(-time.Hour),
			NotAfter:              fx.now.Add(time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
			IsCA:                  false,
			UnknownExtKeyUsage:    []asn1.ObjectIdentifier{oidTestOtherEKU},
			SignatureAlgorithm:    x509.ECDSAWithSHA384,
		}
		_, badDER := createTestCert(t, badTmpl, fx.intermCerts[6], &badKey.PublicKey, fx.intermKeys[6])
		q := proto.Clone(fx.quote).(*pb.DiceQuote)
		q.CertChain[len(q.CertChain)-1] = badDER
		if err := VerifyQuote(q, validOpts); !errors.Is(err, ErrCertInvalidExtKeyUsage) {
			t.Errorf("got %v, want %v", err, ErrCertInvalidExtKeyUsage)
		}
	})

	t.Run("untrusted root rejected even when self-signed root is in x5bag", func(t *testing.T) {
		// Use embedded DCP DICE Global Root CA while quote is signed by synthetic root.
		if err := VerifyQuote(fx.quote, &Options{Now: fx.now}); !errors.Is(err, ErrCertChainVerify) {
			t.Errorf("got %v, want %v", err, ErrCertChainVerify)
		}
	})

	t.Run("broken intermediate chain", func(t *testing.T) {
		q := proto.Clone(fx.quote).(*pb.DiceQuote)
		q.CertChain = append([][]byte{}, q.CertChain[1:]...) // drop intermediate CA[6]
		if err := VerifyQuote(q, validOpts); !errors.Is(err, ErrCertChainVerify) {
			t.Errorf("got %v, want %v", err, ErrCertChainVerify)
		}
	})

	t.Run("non-P384 cert key rejected", func(t *testing.T) {
		p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate P-256 key: %v", err)
		}
		p256Tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(305),
			Subject:               pkix.Name{CommonName: "P256 Leaf"},
			NotBefore:             fx.now.Add(-time.Hour),
			NotAfter:              fx.now.Add(time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
			IsCA:                  false,
			UnknownExtKeyUsage:    []asn1.ObjectIdentifier{oidTCGDICEKpAttestLoc},
			SignatureAlgorithm:    x509.ECDSAWithSHA384,
		}
		_, p256DER := createTestCert(t, p256Tmpl, fx.intermCerts[6], &p256Key.PublicKey, fx.intermKeys[6])
		q := proto.Clone(fx.quote).(*pb.DiceQuote)
		q.CertChain[len(q.CertChain)-1] = p256DER
		if err := VerifyQuote(q, validOpts); !errors.Is(err, ErrCertInvalidKey) {
			t.Errorf("got %v, want %v", err, ErrCertInvalidKey)
		}
	})

	t.Run("non-ECDSAWithSHA384 cert signature algorithm rejected", func(t *testing.T) {
		leafKey := generateP384Key(t)
		sha256Tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(306),
			Subject:               pkix.Name{CommonName: "SHA256 Signed Leaf"},
			NotBefore:             fx.now.Add(-time.Hour),
			NotAfter:              fx.now.Add(time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
			IsCA:                  false,
			UnknownExtKeyUsage:    []asn1.ObjectIdentifier{oidTCGDICEKpAttestLoc},
			SignatureAlgorithm:    x509.ECDSAWithSHA256,
		}
		_, badDER := createTestCert(t, sha256Tmpl, fx.intermCerts[6], &leafKey.PublicKey, fx.intermKeys[6])
		q := proto.Clone(fx.quote).(*pb.DiceQuote)
		q.CertChain[len(q.CertChain)-1] = badDER
		if err := VerifyQuote(q, validOpts); !errors.Is(err, ErrCertInvalidSigAlg) {
			t.Errorf("got %v, want %v", err, ErrCertInvalidSigAlg)
		}
	})

	t.Run("invalid CBOR protected header", func(t *testing.T) {
		q := proto.Clone(fx.quote).(*pb.DiceQuote)
		q.ProtectedHeader = []byte{0xff, 0xff}
		if err := VerifyQuote(q, validOpts); !errors.Is(err, ErrProtectedHeaderInvalid) {
			t.Errorf("got %v, want %v", err, ErrProtectedHeaderInvalid)
		}
	})

	t.Run("missing algorithm in protected header", func(t *testing.T) {
		hdrNoAlg, _ := diceCBOREncMode.Marshal(map[any]any{cose.HeaderLabelContentType: "application/eat+cwt"})
		q := proto.Clone(fx.quote).(*pb.DiceQuote)
		q.ProtectedHeader = hdrNoAlg
		if err := VerifyQuote(q, validOpts); !errors.Is(err, ErrAlgorithmInvalid) {
			t.Errorf("got %v, want %v", err, ErrAlgorithmInvalid)
		}
	})

	t.Run("algorithm mismatch between quote and protected header", func(t *testing.T) {
		q := proto.Clone(fx.quote).(*pb.DiceQuote)
		q.Algorithm = int64(cose.AlgorithmES256)
		if err := VerifyQuote(q, validOpts); !errors.Is(err, ErrAlgorithmMismatch) {
			t.Errorf("got %v, want %v", err, ErrAlgorithmMismatch)
		}
	})

	t.Run("unsupported algorithm in quote and protected header", func(t *testing.T) {
		hdrESP384, _ := diceCBOREncMode.Marshal(map[any]any{cose.HeaderLabelAlgorithm: int64(-51)})
		q := proto.Clone(fx.quote).(*pb.DiceQuote)
		q.ProtectedHeader = hdrESP384
		q.Algorithm = -51
		if err := VerifyQuote(q, validOpts); !errors.Is(err, ErrAlgorithmUnsupported) {
			t.Errorf("got %v, want %v", err, ErrAlgorithmUnsupported)
		}
	})

	t.Run("unsupported crit label in protected header", func(t *testing.T) {
		hdrBadCrit, _ := diceCBOREncMode.Marshal(map[any]any{
			cose.HeaderLabelAlgorithm: cose.AlgorithmES384,
			cose.HeaderLabelCritical:  []any{99},
			99:                        "custom-critical-value",
		})
		q := proto.Clone(fx.quote).(*pb.DiceQuote)
		q.ProtectedHeader = hdrBadCrit
		if err := VerifyQuote(q, validOpts); !errors.Is(err, ErrCritLabelUnsupported) {
			t.Errorf("got %v, want %v", err, ErrCritLabelUnsupported)
		}
	})

	t.Run("leaf cert with keyCertSign rejected", func(t *testing.T) {
		badKey := generateP384Key(t)
		badTmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(307),
			Subject:               pkix.Name{CommonName: "CertSign Leaf"},
			NotBefore:             fx.now.Add(-time.Hour),
			NotAfter:              fx.now.Add(time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			BasicConstraintsValid: true,
			IsCA:                  false,
			UnknownExtKeyUsage:    []asn1.ObjectIdentifier{oidTCGDICEKpAttestLoc},
			SignatureAlgorithm:    x509.ECDSAWithSHA384,
		}
		_, badDER := createTestCert(t, badTmpl, fx.intermCerts[6], &badKey.PublicKey, fx.intermKeys[6])
		q := proto.Clone(fx.quote).(*pb.DiceQuote)
		q.CertChain[len(q.CertChain)-1] = badDER
		if err := VerifyQuote(q, validOpts); !errors.Is(err, ErrCertInvalidKeyUsage) {
			t.Errorf("got %v, want %v", err, ErrCertInvalidKeyUsage)
		}
	})

	t.Run("ambiguous leaf certs sharing matching kid", func(t *testing.T) {
		secondKey := generateP384Key(t)
		secondTmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(308),
			Subject:               pkix.Name{CommonName: "Duplicate SKI Leaf"},
			NotBefore:             fx.now.Add(-time.Hour),
			NotAfter:              fx.now.Add(time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
			IsCA:                  false,
			SubjectKeyId:          append([]byte{}, fx.leafCert.SubjectKeyId...),
			UnknownExtKeyUsage:    []asn1.ObjectIdentifier{oidTCGDICEKpAttestLoc},
			SignatureAlgorithm:    x509.ECDSAWithSHA384,
		}
		_, secondDER := createTestCert(t, secondTmpl, fx.intermCerts[6], &secondKey.PublicKey, fx.intermKeys[6])
		q := proto.Clone(fx.quote).(*pb.DiceQuote)
		q.CertChain = append(q.CertChain, secondDER)
		if err := VerifyQuote(q, validOpts); !errors.Is(err, ErrLeafCertAmbiguous) {
			t.Errorf("got %v, want %v", err, ErrLeafCertAmbiguous)
		}
	})

	t.Run("DICE critical extension with trailing bytes rejected", func(t *testing.T) {
		badKey := generateP384Key(t)
		badExtVal := append(makeDERSequence(t, []byte("cmw")), 0x00)
		badTmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(309),
			Subject:               pkix.Name{CommonName: "Trailing Bytes CMW Leaf"},
			NotBefore:             fx.now.Add(-time.Hour),
			NotAfter:              fx.now.Add(time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
			IsCA:                  false,
			UnknownExtKeyUsage:    []asn1.ObjectIdentifier{oidTCGDICEKpAttestLoc},
			ExtraExtensions: []pkix.Extension{
				{
					Id:       oidTCGDICEConceptualMessageWrapper,
					Critical: true,
					Value:    badExtVal,
				},
			},
			SignatureAlgorithm: x509.ECDSAWithSHA384,
		}
		_, badDER := createTestCert(t, badTmpl, fx.intermCerts[6], &badKey.PublicKey, fx.intermKeys[6])
		q := proto.Clone(fx.quote).(*pb.DiceQuote)
		q.CertChain[len(q.CertChain)-1] = badDER
		if err := VerifyQuote(q, validOpts); !errors.Is(err, ErrCriticalExtInvalid) {
			t.Errorf("got %v, want %v", err, ErrCriticalExtInvalid)
		}
	})

	t.Run("wrong signature size", func(t *testing.T) {
		q := proto.Clone(fx.quote).(*pb.DiceQuote)
		q.Signature = make([]byte, 64)
		if err := VerifyQuote(q, validOpts); !errors.Is(err, ErrSignatureSize) {
			t.Errorf("got %v, want %v", err, ErrSignatureSize)
		}
	})

	t.Run("signature created by different P-384 key", func(t *testing.T) {
		otherKey := generateP384Key(t)
		wrongSigQuote := signTestDiceQuote(
			t,
			map[any]any{
				cose.HeaderLabelAlgorithm:   cose.AlgorithmES384,
				cose.HeaderLabelContentType: "application/eat+cwt",
				cose.HeaderLabelCritical:    []any{cose.HeaderLabelAlgorithm, cose.HeaderLabelContentType},
			},
			fx.quote.KeyId,
			fx.quote.CertChain,
			fx.quote.RawPayload,
			otherKey,
		)
		if err := VerifyQuote(wrongSigQuote, validOpts); !errors.Is(err, ErrSignatureInvalid) {
			t.Errorf("got %v, want %v", err, ErrSignatureInvalid)
		}
	})

	t.Run("newDiceVerifier rejects non-ECDSA and non-P384 keys", func(t *testing.T) {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("failed to generate RSA key: %v", err)
		}
		if _, _, err := newDiceVerifier(int64(cose.AlgorithmES384), &rsaKey.PublicKey); !errors.Is(err, ErrCertInvalidKey) {
			t.Errorf("RSA key got %v, want %v", err, ErrCertInvalidKey)
		}
		p256Key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if _, _, err := newDiceVerifier(int64(cose.AlgorithmES384), &p256Key.PublicKey); !errors.Is(err, ErrCertInvalidKey) {
			t.Errorf("P-256 key got %v, want %v", err, ErrCertInvalidKey)
		}
	})

	t.Run("root cert unavailable when embedded root is nil", func(t *testing.T) {
		orig := trustedDiceRootCertificate
		trustedDiceRootCertificate = nil
		t.Cleanup(func() { trustedDiceRootCertificate = orig })
		if _, err := buildRootPool(&Options{}); !errors.Is(err, ErrRootCertUnavailable) {
			t.Errorf("got %v, want %v", err, ErrRootCertUnavailable)
		}
	})
}
