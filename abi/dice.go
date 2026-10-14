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
	stdasn1 "encoding/asn1"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	pb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/veraison/go-cose"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

const (
	// CBOR initial byte constants for DICE quote format detection.
	cborTag1BytePrefix  = 0xd8
	cborTagCWTByte      = 0x3d // Tag 61: CBOR Web Token (RFC 8392)
	cborTagCOSESign1Raw = 0xd2 // Tag 18: COSE_Sign1 (RFC 9052)
	cborArray4Prefix    = 0x84 // 4-element CBOR array
	cborMajorMap        = 5    // CBOR major type 5 (map)

	// CBOR semantic tag numbers.
	cborTagCWT = 61 // RFC 8392 CWT

	// DICE COSE / CWT constants.
	diceSignatureSize = 96 // ECDSA P-384 signature size in bytes (48-byte R || 48-byte S)
	diceContentType   = "application/eat+cwt"
	diceEatProfileOID = "2.16.840.1.113741.1.16.1"

	// CWT claim keys (RFC 8392 / RFC 9711 EAT).
	cwtClaimIss        int64 = 1
	cwtClaimSub        int64 = 2
	cwtClaimEatProfile int64 = 265
	cwtClaimReportData int64 = -212

	maxCBORDepth = 32
)

var (
	errDiceQuoteNil = errors.New("DiceQuote is nil")

	diceCBORDecMode cbor.DecMode
	diceCBOREncMode cbor.EncMode
)

func init() {
	var err error
	decOpts := cbor.DecOptions{
		DupMapKey:       cbor.DupMapKeyEnforcedAPF,
		MaxNestedLevels: maxCBORDepth,
		IntDec:          cbor.IntDecConvertSigned,
	}
	diceCBORDecMode, err = decOpts.DecMode()
	if err != nil {
		panic(err)
	}

	encOpts := cbor.EncOptions{
		Sort:        cbor.SortCoreDeterministic,
		IndefLength: cbor.IndefLengthForbidden,
	}
	diceCBOREncMode, err = encOpts.EncMode()
	if err != nil {
		panic(err)
	}
}

func isDiceQuoteBytes(b []byte) bool {
	if len(b) < 2 {
		return false
	}
	return (b[0] == cborTag1BytePrefix && b[1] == cborTagCWTByte) ||
		(b[0] == cborTagCOSESign1Raw && b[1] == cborArray4Prefix)
}

// parseDiceQuoteEnvelope decodes and validates the outer CWT / COSE_Sign1
// envelope, COSE protected/unprotected headers, and top-level CWT claims
// (iss, sub, eat_profile, report_data), returning a partially populated
// DiceQuote and the decoded CWT claims map for subsequent measurement parsing.
func parseDiceQuoteEnvelope(b []byte) (*pb.DiceQuote, map[any]any, error) {
	if len(b) == 0 {
		return nil, nil, ErrRawQuoteEmpty
	}
	data := clone(b)

	var outerTag cbor.RawTag
	if err := diceCBORDecMode.Unmarshal(data, &outerTag); err != nil {
		return nil, nil, fmt.Errorf("parsing DICE quote CBOR failed: %v", err)
	}

	var coseBytes []byte
	switch outerTag.Number {
	case cborTagCWT:
		coseBytes = outerTag.Content
	case cose.CBORTagSign1Message:
		coseBytes = data
	default:
		return nil, nil, fmt.Errorf("expected CBOR Tag %d (CWT) or %d (COSE_Sign1), got tag %d", cborTagCWT, cose.CBORTagSign1Message, outerTag.Number)
	}

	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(coseBytes); err != nil {
		return nil, nil, fmt.Errorf("parsing COSE_Sign1 message failed: %v", err)
	}

	protectedBytes, alg, err := parseDiceProtectedHeader(&msg.Headers)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing COSE_Sign1 protected header failed: %v", err)
	}

	keyID, contentType, certChain, err := parseDiceUnprotectedHeader(msg.Headers.Unprotected)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing COSE_Sign1 unprotected header failed: %v", err)
	}

	if len(msg.Payload) == 0 {
		return nil, nil, errors.New("COSE_Sign1 payload is empty")
	}
	issuer, subject, eatProfile, reportData, claims, err := parseDiceCWTPayload(msg.Payload)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing DICE CWT payload failed: %v", err)
	}

	quote := &pb.DiceQuote{
		ProtectedHeader: protectedBytes,
		Algorithm:       alg,
		KeyId:           keyID,
		ContentType:     contentType,
		CertChain:       certChain,
		RawPayload:      msg.Payload,
		Issuer:          issuer,
		Subject:         subject,
		EatProfile:      eatProfile,
		TdQuoteBody: &pb.TDQuoteBodyV5{
			ReportData: reportData,
		},
		Signature: msg.Signature,
	}

	if err := checkDiceQuoteEnvelope(quote); err != nil {
		return nil, nil, fmt.Errorf("validating DICE quote envelope failed: %v", err)
	}
	return quote, claims, nil
}

func parseDiceProtectedHeader(headers *cose.Headers) ([]byte, int64, error) {
	var protectedBytes []byte
	if err := diceCBORDecMode.Unmarshal(headers.RawProtected, &protectedBytes); err != nil {
		return nil, 0, fmt.Errorf("decoding protected header bstr failed: %v", err)
	}
	if len(protectedBytes) == 0 {
		return nil, 0, errors.New("protected header is empty")
	}

	alg, err := headers.Protected.Algorithm()
	if err != nil {
		return nil, 0, fmt.Errorf("missing or invalid algorithm (key %d) in protected header: %v", cose.HeaderLabelAlgorithm, err)
	}
	if alg != cose.AlgorithmES384 {
		return nil, 0, fmt.Errorf("unsupported algorithm %d in protected header, expected %d (ES384)", int64(alg), int64(cose.AlgorithmES384))
	}

	critLabels, err := headers.Protected.Critical()
	if err != nil {
		return nil, 0, fmt.Errorf("invalid crit header: %v", err)
	}
	for _, label := range critLabels {
		if label != cose.HeaderLabelAlgorithm {
			return nil, 0, fmt.Errorf("unsupported critical header label %v in protected header", label)
		}
	}

	return protectedBytes, int64(alg), nil
}

func parseDiceUnprotectedHeader(unprotected cose.UnprotectedHeader) ([]byte, string, [][]byte, error) {
	var keyID []byte
	if kidVal, ok := unprotected[cose.HeaderLabelKeyID]; ok {
		kidBytes, isBytes := kidVal.([]byte)
		if !isBytes {
			return nil, "", nil, fmt.Errorf("kid (key %d) must be a byte string", cose.HeaderLabelKeyID)
		}
		keyID = kidBytes
	}

	var contentType string
	if ctVal, ok := unprotected[cose.HeaderLabelContentType]; ok {
		ctStr, isStr := ctVal.(string)
		if !isStr {
			return nil, "", nil, fmt.Errorf("content-type (key %d) must be a text string", cose.HeaderLabelContentType)
		}
		if ctStr != diceContentType {
			return nil, "", nil, fmt.Errorf("unsupported content-type %q, expected %q", ctStr, diceContentType)
		}
		contentType = ctStr
	}

	_, hasX5Bag := unprotected[cose.HeaderLabelX5Bag]
	_, hasX5Chain := unprotected[cose.HeaderLabelX5Chain]
	if hasX5Bag && hasX5Chain {
		return nil, "", nil, fmt.Errorf("unprotected header must not contain both x5bag (key %d) and x5chain (key %d)", cose.HeaderLabelX5Bag, cose.HeaderLabelX5Chain)
	}

	var certsRaw any
	switch {
	case hasX5Bag:
		certsRaw = unprotected[cose.HeaderLabelX5Bag]
	case hasX5Chain:
		certsRaw = unprotected[cose.HeaderLabelX5Chain]
	default:
		return nil, "", nil, fmt.Errorf("missing certificate chain (key %d or %d) in unprotected header", cose.HeaderLabelX5Bag, cose.HeaderLabelX5Chain)
	}

	certChain, err := extractCOSECertChain(certsRaw)
	if err != nil {
		return nil, "", nil, err
	}
	return keyID, contentType, certChain, nil
}

func extractCOSECertChain(certsRaw any) ([][]byte, error) {
	switch v := certsRaw.(type) {
	case []byte:
		if len(v) == 0 {
			return nil, errors.New("certificate in unprotected header is empty")
		}
		return [][]byte{v}, nil
	case []any:
		if len(v) == 0 {
			return nil, errors.New("certificate chain in unprotected header is empty")
		}
		certChain := make([][]byte, 0, len(v))
		for i, item := range v {
			certBytes, ok := item.([]byte)
			if !ok {
				return nil, fmt.Errorf("certificate at index %d is not a byte string", i)
			}
			if len(certBytes) == 0 {
				return nil, fmt.Errorf("certificate at index %d is empty", i)
			}
			certChain = append(certChain, certBytes)
		}
		return certChain, nil
	default:
		return nil, errors.New("certificate chain in unprotected header must be a byte string or array of byte strings")
	}
}

func parseDiceCWTPayload(rawPayload []byte) (string, string, string, []byte, map[any]any, error) {
	if len(rawPayload) == 0 || rawPayload[0]>>5 != cborMajorMap {
		return "", "", "", nil, nil, errors.New("CWT payload is not a CBOR map")
	}

	var claims map[any]any
	if err := diceCBORDecMode.Unmarshal(rawPayload, &claims); err != nil {
		return "", "", "", nil, nil, err
	}

	var issuer string
	if issVal, ok := claims[cwtClaimIss]; ok {
		issStr, isStr := issVal.(string)
		if !isStr {
			return "", "", "", nil, nil, fmt.Errorf("issuer (claim %d) in CWT payload must be a text string", cwtClaimIss)
		}
		issuer = issStr
	}

	var subject string
	if subVal, ok := claims[cwtClaimSub]; ok {
		subStr, isStr := subVal.(string)
		if !isStr {
			return "", "", "", nil, nil, fmt.Errorf("subject (claim %d) in CWT payload must be a text string", cwtClaimSub)
		}
		subject = subStr
	}

	profileVal, ok := claims[cwtClaimEatProfile]
	if !ok {
		return "", "", "", nil, nil, fmt.Errorf("missing eat_profile (claim %d) in CWT payload", cwtClaimEatProfile)
	}
	var eatProfile string
	switch v := profileVal.(type) {
	case []byte:
		oidStr, err := decodeDEROIDToString(v)
		if err != nil {
			return "", "", "", nil, nil, fmt.Errorf("invalid eat_profile DER OID (claim %d): %v", cwtClaimEatProfile, err)
		}
		eatProfile = oidStr
	case string:
		// TODO: Remove string fallback once temporary sample quote compatibility is no longer needed.
		eatProfile = v
	default:
		return "", "", "", nil, nil, fmt.Errorf("eat_profile (claim %d) in CWT payload must be a byte string or text string", cwtClaimEatProfile)
	}
	if eatProfile != diceEatProfileOID {
		return "", "", "", nil, nil, fmt.Errorf("unsupported eat_profile %q, expected %q", eatProfile, diceEatProfileOID)
	}

	reportDataVal, ok := claims[cwtClaimReportData]
	if !ok {
		return "", "", "", nil, nil, fmt.Errorf("missing report_data (claim %d) in CWT payload", cwtClaimReportData)
	}
	reportData, ok := reportDataVal.([]byte)
	if !ok {
		return "", "", "", nil, nil, fmt.Errorf("report_data (claim %d) in CWT payload must be a byte string", cwtClaimReportData)
	}
	if len(reportData) != ReportDataSize {
		return "", "", "", nil, nil, fmt.Errorf("reportData size is %d bytes. Expected %d bytes", len(reportData), ReportDataSize)
	}

	return issuer, subject, eatProfile, reportData, claims, nil
}

// decodeDEROIDToString converts raw DER-encoded OBJECT IDENTIFIER value bytes
// (without ASN.1 tag and length) into dotted string notation.
func decodeDEROIDToString(b []byte) (string, error) {
	if len(b) == 0 {
		return "", errors.New("empty DER OID bytes")
	}
	var bldr cryptobyte.Builder
	bldr.AddASN1(cbasn1.OBJECT_IDENTIFIER, func(child *cryptobyte.Builder) {
		child.AddBytes(b)
	})
	derBytes, err := bldr.Bytes()
	if err != nil {
		return "", err
	}
	var oid stdasn1.ObjectIdentifier
	rest, err := stdasn1.Unmarshal(derBytes, &oid)
	if err != nil || len(rest) != 0 {
		return "", fmt.Errorf("invalid DER OID bytes: %v", err)
	}
	return oid.String(), nil
}

func checkDiceQuoteEnvelope(quote *pb.DiceQuote) error {
	if quote == nil {
		return errDiceQuoteNil
	}
	if len(quote.GetProtectedHeader()) == 0 {
		return errors.New("DiceQuote protectedHeader is empty")
	}
	if quote.GetAlgorithm() != int64(cose.AlgorithmES384) {
		return fmt.Errorf("DiceQuote algorithm %d not supported, expected %d", quote.GetAlgorithm(), int64(cose.AlgorithmES384))
	}
	if quote.GetContentType() != "" && quote.GetContentType() != diceContentType {
		return fmt.Errorf("DiceQuote contentType %q not supported, expected %q", quote.GetContentType(), diceContentType)
	}
	if len(quote.GetCertChain()) == 0 {
		return errors.New("DiceQuote certChain is empty")
	}
	for i, cert := range quote.GetCertChain() {
		if len(cert) == 0 {
			return fmt.Errorf("DiceQuote certChain[%d] is empty", i)
		}
	}
	if len(quote.GetRawPayload()) == 0 {
		return errors.New("DiceQuote rawPayload is empty")
	}
	if quote.GetEatProfile() != diceEatProfileOID {
		return fmt.Errorf("DiceQuote eatProfile %q not supported, expected %q", quote.GetEatProfile(), diceEatProfileOID)
	}
	if quote.GetTdQuoteBody() == nil {
		return fmt.Errorf("DiceQuote TD Quote Body error: %v", ErrTDQuoteBodyNil)
	}
	if len(quote.GetTdQuoteBody().GetReportData()) != ReportDataSize {
		return fmt.Errorf("DiceQuote reportData size is %d bytes. Expected %d bytes", len(quote.GetTdQuoteBody().GetReportData()), ReportDataSize)
	}
	if len(quote.GetSignature()) != diceSignatureSize {
		return fmt.Errorf("DiceQuote signature size is %d bytes. Expected %d bytes", len(quote.GetSignature()), diceSignatureSize)
	}
	return nil
}

func encodeDiceQuoteCBOR(quote *pb.DiceQuote) ([]byte, error) {
	if err := checkDiceQuoteEnvelope(quote); err != nil {
		return nil, fmt.Errorf("DiceQuote invalid: %v", err)
	}

	rawProtected, err := diceCBOREncMode.Marshal(quote.GetProtectedHeader())
	if err != nil {
		return nil, fmt.Errorf("encoding protected header failed: %v", err)
	}

	unprotected := cose.UnprotectedHeader{
		cose.HeaderLabelX5Bag: quote.GetCertChain(),
	}
	if len(quote.GetKeyId()) > 0 {
		unprotected[cose.HeaderLabelKeyID] = quote.GetKeyId()
	}
	if quote.GetContentType() != "" {
		unprotected[cose.HeaderLabelContentType] = quote.GetContentType()
	}

	msg := &cose.Sign1Message{
		Headers: cose.Headers{
			RawProtected: rawProtected,
			Unprotected:  unprotected,
		},
		Payload:   quote.GetRawPayload(),
		Signature: quote.GetSignature(),
	}
	coseBytes, err := msg.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("encoding COSE_Sign1 message failed: %v", err)
	}

	return cbor.RawTag{
		Number:  cborTagCWT,
		Content: coseBytes,
	}.MarshalCBOR()
}
