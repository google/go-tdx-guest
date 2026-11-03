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
	// errDiceQuoteNil error returned when DiceQuote is nil
	errDiceQuoteNil = errors.New("DiceQuote is nil")

	// errDiceCBORTagInvalid error returned when outer CBOR tag is not CWT (61) or COSE_Sign1 (18)
	errDiceCBORTagInvalid = errors.New("invalid outer CBOR tag for DICE quote")

	// errDiceProtectedHeaderEmpty error returned when DiceQuote protected header is empty
	errDiceProtectedHeaderEmpty = errors.New("DiceQuote protected header is empty")

	// errDiceProtectedHeaderInvalid error returned when DiceQuote protected header is not valid CBOR
	errDiceProtectedHeaderInvalid = errors.New("DiceQuote protected header is invalid")

	// errDiceAlgorithmInvalid error returned when algorithm is missing or invalid in protected header
	errDiceAlgorithmInvalid = errors.New("missing or invalid algorithm in protected header")

	// errDiceAlgorithmUnsupported error returned when DiceQuote algorithm is not ES384
	errDiceAlgorithmUnsupported = errors.New("DiceQuote algorithm not supported")

	// errDiceAlgorithmMismatch error returned when DiceQuote algorithm field does not match protected header
	errDiceAlgorithmMismatch = errors.New("DiceQuote algorithm does not match protected header")

	// errDiceCritHeaderInvalid error returned when crit header in protected header is malformed
	errDiceCritHeaderInvalid = errors.New("invalid crit header in protected header")

	// errDiceCritLabelUnsupported error returned when protected header contains an unsupported critical label
	errDiceCritLabelUnsupported = errors.New("unsupported critical header label in protected header")

	// errDiceKeyIDInvalid error returned when kid in unprotected header is not a byte string
	errDiceKeyIDInvalid = errors.New("DiceQuote kid must be a byte string")

	// errDiceContentTypeInvalid error returned when content-type in unprotected header is not a text string
	errDiceContentTypeInvalid = errors.New("DiceQuote content-type must be a text string")

	// errDiceContentTypeUnsupported error returned when DiceQuote content-type is not supported
	errDiceContentTypeUnsupported = errors.New("DiceQuote content-type not supported")

	// errDiceCertChainConflict error returned when unprotected header contains both x5bag and x5chain
	errDiceCertChainConflict = errors.New("unprotected header must not contain both x5bag and x5chain")

	// errDiceCertChainMissing error returned when certificate chain is missing from unprotected header
	errDiceCertChainMissing = errors.New("missing certificate chain in unprotected header")

	// errDiceCertChainEmpty error returned when DiceQuote certificate chain is empty
	errDiceCertChainEmpty = errors.New("DiceQuote certificate chain is empty")

	// errDiceCertChainInvalid error returned when certificate chain in unprotected header has an invalid CBOR type
	errDiceCertChainInvalid = errors.New("certificate chain in unprotected header must be a byte string or array of byte strings")

	// errDiceCertEmpty error returned when a certificate in the certificate chain is empty
	errDiceCertEmpty = errors.New("certificate in unprotected header is empty")

	// errDiceCertInvalid error returned when a certificate in the certificate chain is not a byte string
	errDiceCertInvalid = errors.New("certificate in unprotected header is not a byte string")

	// errDicePayloadEmpty error returned when COSE_Sign1 payload is empty
	errDicePayloadEmpty = errors.New("DiceQuote CWT payload is empty")

	// errDicePayloadNotMap error returned when CWT payload is not a CBOR map
	errDicePayloadNotMap = errors.New("DiceQuote CWT payload is not a CBOR map")

	// errDiceIssuerInvalid error returned when issuer claim in CWT payload is not a text string
	errDiceIssuerInvalid = errors.New("issuer in CWT payload must be a text string")

	// errDiceSubjectInvalid error returned when subject claim in CWT payload is not a text string
	errDiceSubjectInvalid = errors.New("subject in CWT payload must be a text string")

	// errDiceEatProfileMissing error returned when eat_profile claim is missing from CWT payload
	errDiceEatProfileMissing = errors.New("missing eat_profile in CWT payload")

	// errDiceEatProfileInvalid error returned when eat_profile claim in CWT payload cannot be decoded
	errDiceEatProfileInvalid = errors.New("invalid eat_profile in CWT payload")

	// errDiceEatProfileUnsupported error returned when DiceQuote eat_profile OID is not supported
	errDiceEatProfileUnsupported = errors.New("DiceQuote eat_profile not supported")

	// errDiceReportDataMissing error returned when report_data claim is missing from CWT payload
	errDiceReportDataMissing = errors.New("missing report_data in CWT payload")

	// errDiceReportDataInvalid error returned when report_data claim in CWT payload is not a byte string
	errDiceReportDataInvalid = errors.New("report_data in CWT payload must be a byte string")

	// errDiceReportDataSize error returned when DiceQuote report_data size is not 64 bytes
	errDiceReportDataSize = errors.New("invalid DiceQuote report_data size")

	// errDiceSignatureSize error returned when DiceQuote signature size is not 96 bytes
	errDiceSignatureSize = errors.New("invalid DiceQuote signature size")

	// errDiceDEROIDEmpty error returned when DER OID byte slice is empty
	errDiceDEROIDEmpty = errors.New("empty DER OID bytes")

	// errDiceDEROIDInvalid error returned when DER OID bytes are malformed
	errDiceDEROIDInvalid = errors.New("invalid DER OID bytes")

	diceCBORDecMode cbor.DecMode
	diceCBOREncMode cbor.EncMode
)

func init() {
	var err error
	decOpts := cbor.DecOptions{
		DupMapKey:       cbor.DupMapKeyEnforcedAPF,
		MaxNestedLevels: maxCBORDepth,
		IntDec:          cbor.IntDecConvertSignedOrFail,
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

// parseDiceQuoteEnvelope decodes the outer CWT / COSE_Sign1 CBOR envelope,
// COSE protected/unprotected headers, and top-level CWT claims (iss, sub,
// eat_profile, report_data), and performs structural, format, and field-size
// checks.
func parseDiceQuoteEnvelope(b []byte) (*pb.DiceQuote, map[any]any, error) {
	if len(b) == 0 {
		return nil, nil, ErrRawQuoteEmpty
	}
	data := clone(b)

	var outerTag cbor.RawTag
	if err := diceCBORDecMode.Unmarshal(data, &outerTag); err != nil {
		return nil, nil, fmt.Errorf("parsing DICE quote CBOR failed: %w", err)
	}

	var coseBytes []byte
	switch outerTag.Number {
	case cborTagCWT:
		coseBytes = outerTag.Content
	case cose.CBORTagSign1Message:
		coseBytes = data
	default:
		return nil, nil, fmt.Errorf("%w: expected CBOR Tag %d (CWT) or %d (COSE_Sign1), got tag %d", errDiceCBORTagInvalid, cborTagCWT, cose.CBORTagSign1Message, outerTag.Number)
	}

	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(coseBytes); err != nil {
		return nil, nil, fmt.Errorf("parsing COSE_Sign1 message failed: %w", err)
	}

	protectedBytes, alg, err := parseDiceProtectedHeader(&msg.Headers)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing COSE_Sign1 protected header failed: %w", err)
	}

	keyID, contentType, certChain, err := parseDiceUnprotectedHeader(msg.Headers.Unprotected)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing COSE_Sign1 unprotected header failed: %w", err)
	}

	if len(msg.Payload) == 0 {
		return nil, nil, errDicePayloadEmpty
	}
	issuer, subject, eatProfile, reportData, claims, err := parseDiceCWTPayload(msg.Payload)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing DICE CWT payload failed: %w", err)
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
		return nil, nil, fmt.Errorf("checking DICE quote envelope structure failed: %w", err)
	}
	return quote, claims, nil
}

func parseDiceProtectedHeader(headers *cose.Headers) ([]byte, int64, error) {
	var protectedBytes []byte
	if err := diceCBORDecMode.Unmarshal(headers.RawProtected, &protectedBytes); err != nil {
		return nil, 0, fmt.Errorf("%w: decoding protected header bstr failed: %v", errDiceProtectedHeaderInvalid, err)
	}
	if len(protectedBytes) == 0 {
		return nil, 0, errDiceProtectedHeaderEmpty
	}

	alg, err := headers.Protected.Algorithm()
	if err != nil {
		return nil, 0, fmt.Errorf("%w (key %d): %v", errDiceAlgorithmInvalid, cose.HeaderLabelAlgorithm, err)
	}
	if alg != cose.AlgorithmES384 {
		return nil, 0, fmt.Errorf("%w: algorithm %d in protected header, expected %d (ES384)", errDiceAlgorithmUnsupported, int64(alg), int64(cose.AlgorithmES384))
	}

	critLabels, err := headers.Protected.Critical()
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %v", errDiceCritHeaderInvalid, err)
	}
	for _, label := range critLabels {
		if label != cose.HeaderLabelAlgorithm {
			return nil, 0, fmt.Errorf("%w: %v", errDiceCritLabelUnsupported, label)
		}
	}

	return protectedBytes, int64(alg), nil
}

func parseDiceUnprotectedHeader(unprotected cose.UnprotectedHeader) ([]byte, string, [][]byte, error) {
	var keyID []byte
	if kidVal, ok := unprotected[cose.HeaderLabelKeyID]; ok {
		kidBytes, isBytes := kidVal.([]byte)
		if !isBytes {
			return nil, "", nil, fmt.Errorf("%w (key %d)", errDiceKeyIDInvalid, cose.HeaderLabelKeyID)
		}
		keyID = kidBytes
	}

	var contentType string
	if ctVal, ok := unprotected[cose.HeaderLabelContentType]; ok {
		ctStr, isStr := ctVal.(string)
		if !isStr {
			return nil, "", nil, fmt.Errorf("%w (key %d)", errDiceContentTypeInvalid, cose.HeaderLabelContentType)
		}
		if ctStr != diceContentType {
			return nil, "", nil, fmt.Errorf("%w: got %q, expected %q", errDiceContentTypeUnsupported, ctStr, diceContentType)
		}
		contentType = ctStr
	}

	// DICE quotes encode the certificate chain under COSE header label 32 (x5bag).
	// Label 33 (x5chain) is also accepted when parsing for RFC 9360 compatibility.
	_, hasX5Bag := unprotected[cose.HeaderLabelX5Bag]
	_, hasX5Chain := unprotected[cose.HeaderLabelX5Chain]
	if hasX5Bag && hasX5Chain {
		return nil, "", nil, fmt.Errorf("%w (key %d and key %d)", errDiceCertChainConflict, cose.HeaderLabelX5Bag, cose.HeaderLabelX5Chain)
	}

	var certsRaw any
	switch {
	case hasX5Bag:
		certsRaw = unprotected[cose.HeaderLabelX5Bag]
	case hasX5Chain:
		certsRaw = unprotected[cose.HeaderLabelX5Chain]
	default:
		return nil, "", nil, fmt.Errorf("%w (key %d or %d)", errDiceCertChainMissing, cose.HeaderLabelX5Bag, cose.HeaderLabelX5Chain)
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
			return nil, errDiceCertEmpty
		}
		return [][]byte{v}, nil
	case []any:
		if len(v) == 0 {
			return nil, errDiceCertChainEmpty
		}
		certChain := make([][]byte, 0, len(v))
		for i, item := range v {
			certBytes, ok := item.([]byte)
			if !ok {
				return nil, fmt.Errorf("%w: certificate at index %d", errDiceCertInvalid, i)
			}
			if len(certBytes) == 0 {
				return nil, fmt.Errorf("%w: certificate at index %d", errDiceCertEmpty, i)
			}
			certChain = append(certChain, certBytes)
		}
		return certChain, nil
	default:
		return nil, errDiceCertChainInvalid
	}
}

func parseDiceCWTPayload(rawPayload []byte) (string, string, string, []byte, map[any]any, error) {
	if len(rawPayload) == 0 || rawPayload[0]>>5 != cborMajorMap {
		return "", "", "", nil, nil, errDicePayloadNotMap
	}

	var claims map[any]any
	if err := diceCBORDecMode.Unmarshal(rawPayload, &claims); err != nil {
		return "", "", "", nil, nil, err
	}

	var issuer string
	if issVal, ok := claims[cwtClaimIss]; ok {
		issStr, isStr := issVal.(string)
		if !isStr {
			return "", "", "", nil, nil, fmt.Errorf("%w (claim %d)", errDiceIssuerInvalid, cwtClaimIss)
		}
		issuer = issStr
	}

	var subject string
	if subVal, ok := claims[cwtClaimSub]; ok {
		subStr, isStr := subVal.(string)
		if !isStr {
			return "", "", "", nil, nil, fmt.Errorf("%w (claim %d)", errDiceSubjectInvalid, cwtClaimSub)
		}
		subject = subStr
	}

	profileVal, ok := claims[cwtClaimEatProfile]
	if !ok {
		return "", "", "", nil, nil, fmt.Errorf("%w (claim %d)", errDiceEatProfileMissing, cwtClaimEatProfile)
	}
	var eatProfile string
	switch v := profileVal.(type) {
	case []byte:
		oidStr, err := decodeDEROIDToString(v)
		if err != nil {
			return "", "", "", nil, nil, fmt.Errorf("%w: invalid DER OID (claim %d): %v", errDiceEatProfileInvalid, cwtClaimEatProfile, err)
		}
		eatProfile = oidStr
	case string:
		// TODO: Remove string fallback once temporary sample quote compatibility is no longer needed.
		eatProfile = v
	default:
		return "", "", "", nil, nil, fmt.Errorf("%w: claim %d must be a byte string or text string", errDiceEatProfileInvalid, cwtClaimEatProfile)
	}
	if eatProfile != diceEatProfileOID {
		return "", "", "", nil, nil, fmt.Errorf("%w: got %q, expected %q", errDiceEatProfileUnsupported, eatProfile, diceEatProfileOID)
	}

	reportDataVal, ok := claims[cwtClaimReportData]
	if !ok {
		return "", "", "", nil, nil, fmt.Errorf("%w (claim %d)", errDiceReportDataMissing, cwtClaimReportData)
	}
	reportData, ok := reportDataVal.([]byte)
	if !ok {
		return "", "", "", nil, nil, fmt.Errorf("%w (claim %d)", errDiceReportDataInvalid, cwtClaimReportData)
	}
	if len(reportData) != ReportDataSize {
		return "", "", "", nil, nil, fmt.Errorf("%w: reportData size is %d bytes. Expected %d bytes", errDiceReportDataSize, len(reportData), ReportDataSize)
	}

	return issuer, subject, eatProfile, reportData, claims, nil
}

// decodeDEROIDToString converts raw DER-encoded OBJECT IDENTIFIER value bytes
// (without ASN.1 tag and length) into dotted string notation.
func decodeDEROIDToString(b []byte) (string, error) {
	if len(b) == 0 {
		return "", errDiceDEROIDEmpty
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
		return "", fmt.Errorf("%w: %v", errDiceDEROIDInvalid, err)
	}
	return oid.String(), nil
}

// checkDiceQuoteEnvelope performs structural, format, and byte-length checks
// on the envelope fields of a DiceQuote protobuf message. It does not perform
// cryptographic signature verification or X.509 certificate chain verification.
func checkDiceQuoteEnvelope(quote *pb.DiceQuote) error {
	if quote == nil {
		return errDiceQuoteNil
	}
	if len(quote.GetProtectedHeader()) == 0 {
		return errDiceProtectedHeaderEmpty
	}
	if quote.GetAlgorithm() != int64(cose.AlgorithmES384) {
		return fmt.Errorf("%w: DiceQuote algorithm %d not supported, expected %d", errDiceAlgorithmUnsupported, quote.GetAlgorithm(), int64(cose.AlgorithmES384))
	}
	rawProtected, err := diceCBOREncMode.Marshal(quote.GetProtectedHeader())
	if err != nil {
		return fmt.Errorf("%w: %v", errDiceProtectedHeaderInvalid, err)
	}
	var protected cose.ProtectedHeader
	if err := protected.UnmarshalCBOR(rawProtected); err != nil {
		return fmt.Errorf("%w: %v", errDiceProtectedHeaderInvalid, err)
	}
	hdrAlg, err := protected.Algorithm()
	if err != nil {
		return fmt.Errorf("%w: %v", errDiceAlgorithmInvalid, err)
	}
	if int64(hdrAlg) != quote.GetAlgorithm() {
		return fmt.Errorf("%w: quote algorithm %d != protected header algorithm %d", errDiceAlgorithmMismatch, quote.GetAlgorithm(), int64(hdrAlg))
	}
	if quote.GetContentType() != "" && quote.GetContentType() != diceContentType {
		return fmt.Errorf("%w: DiceQuote contentType %q not supported, expected %q", errDiceContentTypeUnsupported, quote.GetContentType(), diceContentType)
	}
	if len(quote.GetCertChain()) == 0 {
		return errDiceCertChainEmpty
	}
	for i, cert := range quote.GetCertChain() {
		if len(cert) == 0 {
			return fmt.Errorf("%w: DiceQuote certChain[%d] is empty", errDiceCertEmpty, i)
		}
	}
	if len(quote.GetRawPayload()) == 0 {
		return errDicePayloadEmpty
	}
	if quote.GetEatProfile() != diceEatProfileOID {
		return fmt.Errorf("%w: DiceQuote eatProfile %q not supported, expected %q", errDiceEatProfileUnsupported, quote.GetEatProfile(), diceEatProfileOID)
	}
	if quote.GetTdQuoteBody() == nil {
		return fmt.Errorf("DiceQuote TD Quote Body error: %w", ErrTDQuoteBodyNil)
	}
	if len(quote.GetTdQuoteBody().GetReportData()) != ReportDataSize {
		return fmt.Errorf("%w: DiceQuote reportData size is %d bytes. Expected %d bytes", errDiceReportDataSize, len(quote.GetTdQuoteBody().GetReportData()), ReportDataSize)
	}
	if len(quote.GetSignature()) != diceSignatureSize {
		return fmt.Errorf("%w: DiceQuote signature size is %d bytes. Expected %d bytes", errDiceSignatureSize, len(quote.GetSignature()), diceSignatureSize)
	}
	return nil
}

func encodeDiceQuoteCBOR(quote *pb.DiceQuote) ([]byte, error) {
	if err := checkDiceQuoteEnvelope(quote); err != nil {
		return nil, fmt.Errorf("DiceQuote invalid: %w", err)
	}

	rawProtected, err := diceCBOREncMode.Marshal(quote.GetProtectedHeader())
	if err != nil {
		return nil, fmt.Errorf("encoding protected header failed: %w", err)
	}

	// DICE quotes encode the certificate chain under COSE header label 32 (x5bag).
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
		return nil, fmt.Errorf("encoding COSE_Sign1 message failed: %w", err)
	}

	return cbor.RawTag{
		Number:  cborTagCWT,
		Content: coseBytes,
	}.MarshalCBOR()
}
