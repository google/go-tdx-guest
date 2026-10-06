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
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	pb "github.com/google/go-tdx-guest/proto/tdx"
)

const (
	// QuoteVersionDICE represents the DICE quote format identifier returned by determineQuoteFormat.
	// A DICE quote begins with CBOR Tag 61 (0xd8, 0x3d = 0x3dd8 in little-endian uint16) or CBOR Tag 18 (0xd2).
	QuoteVersionDICE = 0x3dd8

	// CBOR initial byte constants for format detection.
	cborTag1BytePrefix  = 0xd8
	cborTagCWTByte      = 0x3d // Tag 61: CBOR Web Token (RFC 8392)
	cborTagCOSESign1Raw = 0xd2 // Tag 18: COSE_Sign1 (RFC 9052)
	cborArray4Prefix    = 0x84 // 4-element CBOR array

	// CBOR semantic tag numbers.
	cborTagCWT       = 61  // RFC 8392 CWT
	cborTagCOSESign1 = 18  // RFC 9052 COSE_Sign1
	cborTagCoRIM     = 571 // CoRIM / Concise Evidence

	// COSE header parameter labels (RFC 9052 / RFC 9360).
	coseHeaderAlg         = 1
	coseHeaderContentType = 3
	coseHeaderKid         = 4
	coseHeaderX5Bag       = 32
	coseHeaderX5Chain     = 33

	// COSE algorithm identifiers (RFC 9053).
	coseAlgES384 = -35 // ECDSA w/ SHA-384 on P-384 curve

	// DiceSignatureSize is the DICE ECDSA P-384 signature size in bytes (48-byte R || 48-byte S).
	DiceSignatureSize = 96

	// CWT claim keys (RFC 8392 / EAT / Intel DICE TDX profile).
	cwtClaimIss        = 1
	cwtClaimSub        = 2
	cwtClaimEatProfile = 265
	cwtClaimReportData = -212
	cwtClaimSubmods    = -11

	// Submodule OID keys in the CWT cmw-collection (-11) map.
	//
	// TODO: Remove temporary integration sample quote compatibility (.1 outer OIDs)
	// once the sample quote is updated to the official specification, where outer
	// cmw-collection keys use .0 as the final epoch version component.
	diceSubmodOIDPrefix       = "2.16.840.1.113741.1.13.2."
	diceSubmodPlatformTCBOID0 = diceSubmodOIDPrefix + "1.0"
	diceSubmodPlatformTCBOID1 = diceSubmodOIDPrefix + "1.1" // TODO: Remove temporary sample quote outer OID
	diceSubmodSEAMOID0        = diceSubmodOIDPrefix + "8.0"
	diceSubmodSEAMOID1        = diceSubmodOIDPrefix + "8.1"
	diceSubmodTDQuoteBodyOID0 = diceSubmodOIDPrefix + "4.0"
	diceSubmodTDQuoteBodyOID1 = diceSubmodOIDPrefix + "4.1" // TODO: Remove temporary sample quote outer OID
	diceSubmodServiceTDOID0   = diceSubmodOIDPrefix + "7.0"
	diceSubmodServiceTDOID1   = diceSubmodOIDPrefix + "7.1" // TODO: Remove temporary sample quote outer OID

	// CoRIM measurement-values-map keys for TDX quote body fields.
	corimKeyAttributes    = -82  // seam_attributes in SEAM, td_attributes in TD
	corimKeyPrimaryDigest = -83  // mr_seam in SEAM, mr_td in TD
	corimKeyMrSignerSeam  = -84  // mr_signer_seam
	corimKeyTeeTcbSvn     = -125 // tee_tcb_svn (16-element uint array)
	// TODO: Remove corimKeyTeeTcbSvn2 (-153) once temporary sample quote compatibility is no longer needed.
	// In the official specification, both origin (tee_tcb_svn) and current (tee_tcb_svn2)
	// use key -125 inside separate "0" (origin) and "1" (current) maps.
	corimKeyTeeTcbSvn2    = -153
	corimKeyXfam          = -201
	corimKeyMrConfigID    = -203
	corimKeyMrOwner       = -204
	corimKeyMrOwnerConfig = -205
	corimKeyRtmr0         = -206
	corimKeyRtmr1         = -207
	corimKeyRtmr2         = -208
	corimKeyRtmr3         = -209
	corimKeyMrServiceTd   = -210

	maxCBORDepth = 32
)

// ErrDiceQuoteNil is returned when a DiceQuote pointer is nil.
var ErrDiceQuoteNil = errors.New("DiceQuote is nil")

// CBOR major types (RFC 8949 Section 3.1).
const (
	cborMajorUint   = 0
	cborMajorNegInt = 1
	cborMajorBytes  = 2
	cborMajorText   = 3
	cborMajorArray  = 4
	cborMajorMap    = 5
	cborMajorTag    = 6
	cborMajorSimple = 7
)

type cborMapEntry struct {
	key   cborValue
	value cborValue
}

type cborValue struct {
	majorType uint8
	intVal    int64 // Signed value for cborMajorUint and cborMajorNegInt
	bytesVal  []byte
	textVal   string
	arrayVal  []cborValue
	mapVal    []cborMapEntry
	tagNum    uint64
	taggedVal *cborValue
}

func (v cborValue) isInt() bool {
	return v.majorType == cborMajorUint || v.majorType == cborMajorNegInt
}

func (v cborValue) findIntKey(target int64) (cborValue, bool) {
	if v.majorType != cborMajorMap {
		return cborValue{}, false
	}
	for _, entry := range v.mapVal {
		if entry.key.isInt() && entry.key.intVal == target {
			return entry.value, true
		}
	}
	return cborValue{}, false
}

func (v cborValue) findTextKey(targets ...string) (cborValue, bool) {
	if v.majorType != cborMajorMap {
		return cborValue{}, false
	}
	for _, t := range targets {
		for _, entry := range v.mapVal {
			if entry.key.majorType == cborMajorText && entry.key.textVal == t {
				return entry.value, true
			}
		}
	}
	return cborValue{}, false
}

func decodeCBOR(data []byte) (cborValue, error) {
	val, rest, err := decodeCBORItem(data, 0)
	if err != nil {
		return cborValue{}, err
	}
	if len(rest) != 0 {
		return cborValue{}, fmt.Errorf("trailing bytes after CBOR data item: %d bytes", len(rest))
	}
	return val, nil
}

func decodeCBORItem(data []byte, depth int) (cborValue, []byte, error) {
	if depth > maxCBORDepth {
		return cborValue{}, nil, fmt.Errorf("CBOR maximum nesting depth %d exceeded", maxCBORDepth)
	}
	if len(data) == 0 {
		return cborValue{}, nil, fmt.Errorf("unexpected EOF while decoding CBOR")
	}

	majorType := data[0] >> 5
	addInfo := data[0] & 0x1f
	rest := data[1:]
	indefinite := addInfo == 31

	var arg uint64
	if !indefinite {
		var err error
		arg, rest, err = readCBORArgument(addInfo, rest)
		if err != nil {
			return cborValue{}, nil, err
		}
	} else if majorType != cborMajorArray && majorType != cborMajorMap {
		return cborValue{}, nil, fmt.Errorf("unsupported CBOR indefinite length for major type %d", majorType)
	}

	switch majorType {
	case cborMajorUint:
		if arg > math.MaxInt64 {
			return cborValue{}, nil, fmt.Errorf("CBOR unsigned integer overflow")
		}
		return cborValue{majorType: cborMajorUint, intVal: int64(arg)}, rest, nil
	case cborMajorNegInt:
		if arg > math.MaxInt64 {
			return cborValue{}, nil, fmt.Errorf("CBOR negative integer overflow")
		}
		return cborValue{majorType: cborMajorNegInt, intVal: -1 - int64(arg)}, rest, nil
	case cborMajorBytes:
		if uint64(len(rest)) < arg {
			return cborValue{}, nil, fmt.Errorf("unexpected EOF reading CBOR byte string of length %d", arg)
		}
		return cborValue{majorType: cborMajorBytes, bytesVal: clone(rest[:arg])}, rest[arg:], nil
	case cborMajorText:
		if uint64(len(rest)) < arg {
			return cborValue{}, nil, fmt.Errorf("unexpected EOF reading CBOR text string of length %d", arg)
		}
		return cborValue{majorType: cborMajorText, textVal: string(rest[:arg])}, rest[arg:], nil
	case cborMajorArray:
		if !indefinite && arg > uint64(len(rest)) {
			return cborValue{}, nil, fmt.Errorf("CBOR array length %d exceeds remaining input size %d", arg, len(rest))
		}
		var items []cborValue
		for i := uint64(0); indefinite || i < arg; i++ {
			if indefinite {
				if len(rest) == 0 {
					return cborValue{}, nil, fmt.Errorf("unexpected EOF in indefinite-length CBOR array")
				}
				if rest[0] == 0xff {
					rest = rest[1:]
					break
				}
			}
			item, nextRest, err := decodeCBORItem(rest, depth+1)
			if err != nil {
				return cborValue{}, nil, err
			}
			items = append(items, item)
			rest = nextRest
		}
		return cborValue{majorType: cborMajorArray, arrayVal: items}, rest, nil
	case cborMajorMap:
		if !indefinite && arg > uint64(len(rest)) {
			return cborValue{}, nil, fmt.Errorf("CBOR map length %d exceeds remaining input size %d", arg, len(rest))
		}
		var entries []cborMapEntry
		for i := uint64(0); indefinite || i < arg; i++ {
			if indefinite {
				if len(rest) == 0 {
					return cborValue{}, nil, fmt.Errorf("unexpected EOF in indefinite-length CBOR map")
				}
				if rest[0] == 0xff {
					rest = rest[1:]
					break
				}
			}
			k, nextRest, err := decodeCBORItem(rest, depth+1)
			if err != nil {
				return cborValue{}, nil, err
			}
			v, nextRest, err := decodeCBORItem(nextRest, depth+1)
			if err != nil {
				return cborValue{}, nil, err
			}
			entries = append(entries, cborMapEntry{key: k, value: v})
			rest = nextRest
		}
		return cborValue{majorType: cborMajorMap, mapVal: entries}, rest, nil
	case cborMajorTag:
		tagged, nextRest, err := decodeCBORItem(rest, depth+1)
		if err != nil {
			return cborValue{}, nil, err
		}
		return cborValue{majorType: cborMajorTag, tagNum: arg, taggedVal: &tagged}, nextRest, nil
	default:
		return cborValue{majorType: cborMajorSimple, intVal: int64(arg)}, rest, nil
	}
}

func readCBORArgument(addInfo uint8, data []byte) (uint64, []byte, error) {
	switch {
	case addInfo < 24:
		return uint64(addInfo), data, nil
	case addInfo == 24 && len(data) >= 1:
		return uint64(data[0]), data[1:], nil
	case addInfo == 25 && len(data) >= 2:
		return uint64(binary.BigEndian.Uint16(data[:2])), data[2:], nil
	case addInfo == 26 && len(data) >= 4:
		return uint64(binary.BigEndian.Uint32(data[:4])), data[4:], nil
	case addInfo == 27 && len(data) >= 8:
		return binary.BigEndian.Uint64(data[:8]), data[8:], nil
	case addInfo >= 24 && addInfo <= 27:
		return 0, nil, fmt.Errorf("unexpected EOF reading CBOR argument (addInfo=%d)", addInfo)
	default:
		return 0, nil, fmt.Errorf("unsupported CBOR additional information value %d", addInfo)
	}
}

func isDiceQuoteBytes(b []byte) bool {
	if len(b) < 2 {
		return false
	}
	return (b[0] == cborTag1BytePrefix && b[1] == cborTagCWTByte) ||
		(b[0] == cborTagCOSESign1Raw && b[1] == cborArray4Prefix)
}

func quoteToProtoDICE(b []byte) (*pb.DiceQuote, error) {
	rawQuote := clone(b)
	root, err := decodeCBOR(rawQuote)
	if err != nil {
		return nil, fmt.Errorf("parsing DICE quote CBOR failed: %v", err)
	}

	// Unwrap optional outer CBOR Tag 61 (CWT).
	coseItem := root
	if coseItem.majorType == cborMajorTag && coseItem.tagNum == cborTagCWT && coseItem.taggedVal != nil {
		coseItem = *coseItem.taggedVal
	}

	// Expect CBOR Tag 18 (COSE_Sign1) wrapping a 4-element array.
	if coseItem.majorType != cborMajorTag || coseItem.tagNum != cborTagCOSESign1 || coseItem.taggedVal == nil {
		return nil, fmt.Errorf("expected CBOR Tag %d (COSE_Sign1), got majorType=%d tag=%d", cborTagCOSESign1, coseItem.majorType, coseItem.tagNum)
	}
	coseArray := *coseItem.taggedVal
	if coseArray.majorType != cborMajorArray || len(coseArray.arrayVal) != 4 {
		return nil, fmt.Errorf("COSE_Sign1 must be a 4-element CBOR array, got %d elements", len(coseArray.arrayVal))
	}

	// 1. Protected header (bstr containing a CBOR map).
	if coseArray.arrayVal[0].majorType != cborMajorBytes {
		return nil, fmt.Errorf("COSE_Sign1 protected header must be a byte string")
	}
	protectedBytes := coseArray.arrayVal[0].bytesVal
	alg, err := parseCOSEProtectedHeader(protectedBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing COSE_Sign1 protected header failed: %v", err)
	}

	// 2. Unprotected header (map containing kid, content_type, x5bag/x5chain).
	if coseArray.arrayVal[1].majorType != cborMajorMap {
		return nil, fmt.Errorf("COSE_Sign1 unprotected header must be a CBOR map")
	}
	keyID, contentType, certChain, err := parseCOSEUnprotectedHeader(coseArray.arrayVal[1])
	if err != nil {
		return nil, fmt.Errorf("parsing COSE_Sign1 unprotected header failed: %v", err)
	}

	// 3. Payload (bstr containing CWT claims CBOR map).
	if coseArray.arrayVal[2].majorType != cborMajorBytes {
		return nil, fmt.Errorf("COSE_Sign1 payload must be a byte string")
	}
	rawPayload := coseArray.arrayVal[2].bytesVal
	issuer, subject, eatProfile, tdQuoteBody, err := parseDiceCWTPayload(rawPayload)
	if err != nil {
		return nil, fmt.Errorf("parsing DICE CWT payload failed: %v", err)
	}

	// 4. Signature (bstr containing 96-byte ECDSA P-384 signature).
	if coseArray.arrayVal[3].majorType != cborMajorBytes {
		return nil, fmt.Errorf("COSE_Sign1 signature must be a byte string")
	}

	quote := &pb.DiceQuote{
		ProtectedHeader: protectedBytes,
		Algorithm:       alg,
		KeyId:           keyID,
		ContentType:     contentType,
		CertChain:       certChain,
		RawPayload:      rawPayload,
		Issuer:          issuer,
		Subject:         subject,
		EatProfile:      eatProfile,
		TdQuoteBody:     tdQuoteBody,
		Signature:       coseArray.arrayVal[3].bytesVal,
		RawQuote:        rawQuote,
	}

	if err := CheckQuote(quote); err != nil {
		return nil, fmt.Errorf("parsing DiceQuote failed: %v", err)
	}
	return quote, nil
}

func parseCOSEProtectedHeader(protectedBytes []byte) (int64, error) {
	if len(protectedBytes) == 0 {
		return 0, fmt.Errorf("protected header is empty")
	}
	hdrMap, err := decodeCBOR(protectedBytes)
	if err != nil {
		return 0, err
	}
	if hdrMap.majorType != cborMajorMap {
		return 0, fmt.Errorf("protected header CBOR is not a map")
	}
	algVal, ok := hdrMap.findIntKey(coseHeaderAlg)
	if !ok {
		return 0, fmt.Errorf("missing algorithm (key %d) in protected header", coseHeaderAlg)
	}
	if !algVal.isInt() {
		return 0, fmt.Errorf("algorithm in protected header is not an integer")
	}
	return algVal.intVal, nil
}

func parseCOSEUnprotectedHeader(hdrMap cborValue) ([]byte, string, [][]byte, error) {
	var keyID []byte
	if kidVal, ok := hdrMap.findIntKey(coseHeaderKid); ok {
		if kidVal.majorType != cborMajorBytes {
			return nil, "", nil, fmt.Errorf("kid (key %d) must be a byte string", coseHeaderKid)
		}
		keyID = kidVal.bytesVal
	}

	var contentType string
	if ctVal, ok := hdrMap.findIntKey(coseHeaderContentType); ok && ctVal.majorType == cborMajorText {
		contentType = ctVal.textVal
	}

	// Extract certificate chain from key 32 (x5bag) or key 33 (x5chain).
	certsVal, ok := hdrMap.findIntKey(coseHeaderX5Bag)
	if !ok {
		certsVal, ok = hdrMap.findIntKey(coseHeaderX5Chain)
	}
	if !ok {
		return nil, "", nil, fmt.Errorf("missing certificate chain (key %d or %d) in unprotected header", coseHeaderX5Bag, coseHeaderX5Chain)
	}

	var certChain [][]byte
	switch certsVal.majorType {
	case cborMajorBytes:
		certChain = [][]byte{certsVal.bytesVal}
	case cborMajorArray:
		for i, item := range certsVal.arrayVal {
			if item.majorType != cborMajorBytes {
				return nil, "", nil, fmt.Errorf("certificate at index %d is not a byte string", i)
			}
			certChain = append(certChain, item.bytesVal)
		}
	default:
		return nil, "", nil, fmt.Errorf("certificate chain in unprotected header must be a byte string or array of byte strings")
	}

	return keyID, contentType, certChain, nil
}

func decodeDEROIDToString(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	first, second := uint64(b[0])/40, uint64(b[0])%40
	if first > 2 {
		first, second = 2, uint64(b[0])-80
	}
	var sb strings.Builder
	sb.WriteString(strconv.FormatUint(first, 10))
	sb.WriteByte('.')
	sb.WriteString(strconv.FormatUint(second, 10))
	var val uint64
	for _, c := range b[1:] {
		val = (val << 7) | uint64(c&0x7f)
		if c&0x80 == 0 {
			sb.WriteByte('.')
			sb.WriteString(strconv.FormatUint(val, 10))
			val = 0
		}
	}
	return sb.String()
}

func parseDiceCWTPayload(rawPayload []byte) (string, string, string, *pb.TDQuoteBodyV5, error) {
	claims, err := decodeCBOR(rawPayload)
	if err != nil {
		return "", "", "", nil, err
	}
	if claims.majorType != cborMajorMap {
		return "", "", "", nil, fmt.Errorf("CWT payload is not a CBOR map")
	}

	var issuer, subject, eatProfile string
	if issVal, ok := claims.findIntKey(cwtClaimIss); ok && issVal.majorType == cborMajorText {
		issuer = issVal.textVal
	}
	if subVal, ok := claims.findIntKey(cwtClaimSub); ok && subVal.majorType == cborMajorText {
		subject = subVal.textVal
	}
	if profileVal, ok := claims.findIntKey(cwtClaimEatProfile); ok {
		// TODO: Remove cborMajorText fallback once temporary sample quote compatibility is no longer needed.
		// The official specification encodes eat-profile (key 265) as a raw DER OID
		// byte string (bstr), whereas the temporary integration sample quote encodes
		// it as a text string (tstr).
		switch profileVal.majorType {
		case cborMajorText:
			eatProfile = profileVal.textVal
		case cborMajorBytes:
			eatProfile = decodeDEROIDToString(profileVal.bytesVal)
		}
	}

	reportDataVal, ok := claims.findIntKey(cwtClaimReportData)
	if !ok || reportDataVal.majorType != cborMajorBytes {
		return "", "", "", nil, fmt.Errorf("missing or invalid report_data (claim %d) in CWT payload", cwtClaimReportData)
	}
	submodsVal, ok := claims.findIntKey(cwtClaimSubmods)
	if !ok || submodsVal.majorType != cborMajorMap {
		return "", "", "", nil, fmt.Errorf("missing or invalid submods map (claim %d) in CWT payload", cwtClaimSubmods)
	}

	body := &pb.TDQuoteBodyV5{ReportData: reportDataVal.bytesVal}

	// 1. Parse Platform TCB and SEAM submodules.
	tcbSubmod, ok := submodsVal.findTextKey(diceSubmodPlatformTCBOID1, diceSubmodPlatformTCBOID0)
	if !ok {
		return "", "", "", nil, fmt.Errorf("missing Platform TCB submodule (%s) in CWT payload", diceSubmodPlatformTCBOID1)
	}
	tcbOriginMap, tcbCurrentMap, err := extractOriginAndCurrentMeasurements(tcbSubmod)
	if err != nil {
		return "", "", "", nil, fmt.Errorf("parsing Platform TCB submodule failed: %v", err)
	}
	if body.TeeTcbSvn, err = extractSVNFromMap(tcbOriginMap, corimKeyTeeTcbSvn, "tee_tcb_svn"); err != nil {
		return "", "", "", nil, err
	}
	// TODO: Remove key -153 (corimKeyTeeTcbSvn2) fallback once temporary sample quote compatibility is no longer needed.
	// In the temporary integration sample quote, tee_tcb_svn2 is stored at key -153
	// of the single Platform TCB map. In the official specification, tee_tcb_svn2 is
	// stored at key -125 inside the "1" ("current") map.
	if svn2, err2 := extractSVNFromMap(tcbOriginMap, corimKeyTeeTcbSvn2, "tee_tcb_svn2"); err2 == nil {
		body.TeeTcbSvn2 = svn2
	} else if tcbCurrentMap.majorType == cborMajorMap {
		if body.TeeTcbSvn2, err = extractSVNFromMap(tcbCurrentMap, corimKeyTeeTcbSvn, "tee_tcb_svn2"); err != nil {
			return "", "", "", nil, err
		}
	} else {
		return "", "", "", nil, err2
	}

	// TODO: Require a dedicated SEAM submodule once temporary sample quote compatibility is no longer needed.
	// The official specification separates SEAM (TDX Module) measurements into a dedicated
	// submodule, whereas the temporary integration sample quote merges SEAM measurements
	// (mr_seam, mr_signer_seam, seam_attributes) into the Platform TCB submodule.
	seamMap := tcbOriginMap
	if seamSubmod, hasDedicatedSEAM := submodsVal.findTextKey(diceSubmodSEAMOID1, diceSubmodSEAMOID0); hasDedicatedSEAM {
		if seamMap, _, err = extractOriginAndCurrentMeasurements(seamSubmod); err != nil {
			return "", "", "", nil, fmt.Errorf("parsing SEAM submodule failed: %v", err)
		}
	}

	// 2. Parse TD Quote Body submodule.
	tdSubmod, ok := submodsVal.findTextKey(diceSubmodTDQuoteBodyOID1, diceSubmodTDQuoteBodyOID0)
	if !ok {
		return "", "", "", nil, fmt.Errorf("missing TD quote body submodule (%s) in CWT payload", diceSubmodTDQuoteBodyOID1)
	}
	tdMap, _, err := extractOriginAndCurrentMeasurements(tdSubmod)
	if err != nil {
		return "", "", "", nil, fmt.Errorf("parsing TD quote body submodule failed: %v", err)
	}

	// 3. Parse Service TD submodule.
	serviceTDSubmod, ok := submodsVal.findTextKey(diceSubmodServiceTDOID1, diceSubmodServiceTDOID0)
	if !ok {
		return "", "", "", nil, fmt.Errorf("missing Service TD submodule (%s) in CWT payload", diceSubmodServiceTDOID1)
	}
	serviceTDMap, _, err := extractOriginAndCurrentMeasurements(serviceTDSubmod)
	if err != nil {
		return "", "", "", nil, fmt.Errorf("parsing Service TD submodule failed: %v", err)
	}

	// Extract raw byte fields and digest tuples across SEAM, TD, and Service TD maps.
	byteFields := []struct {
		src  cborValue
		key  int64
		name string
		dst  *[]byte
	}{
		{seamMap, corimKeyAttributes, "seam_attributes", &body.SeamAttributes},
		{tdMap, corimKeyAttributes, "td_attributes", &body.TdAttributes},
		{tdMap, corimKeyXfam, "xfam", &body.Xfam},
	}
	for _, bf := range byteFields {
		if *bf.dst, err = extractBytesFromMap(bf.src, bf.key, bf.name); err != nil {
			return "", "", "", nil, err
		}
	}

	body.Rtmrs = make([][]byte, 4)
	digestFields := []struct {
		src  cborValue
		key  int64
		name string
		dst  *[]byte
	}{
		{seamMap, corimKeyPrimaryDigest, "mr_seam", &body.MrSeam},
		{seamMap, corimKeyMrSignerSeam, "mr_signer_seam", &body.MrSignerSeam},
		{tdMap, corimKeyPrimaryDigest, "mr_td", &body.MrTd},
		{tdMap, corimKeyMrConfigID, "mr_config_id", &body.MrConfigId},
		{tdMap, corimKeyMrOwner, "mr_owner", &body.MrOwner},
		{tdMap, corimKeyMrOwnerConfig, "mr_owner_config", &body.MrOwnerConfig},
		{tdMap, corimKeyRtmr0, "rtmr0", &body.Rtmrs[0]},
		{tdMap, corimKeyRtmr1, "rtmr1", &body.Rtmrs[1]},
		{tdMap, corimKeyRtmr2, "rtmr2", &body.Rtmrs[2]},
		{tdMap, corimKeyRtmr3, "rtmr3", &body.Rtmrs[3]},
		{serviceTDMap, corimKeyMrServiceTd, "mr_service_td", &body.MrServiceTd},
	}
	for _, df := range digestFields {
		if *df.dst, err = extractDigestFromMap(df.src, df.key, df.name); err != nil {
			return "", "", "", nil, err
		}
	}

	return issuer, subject, eatProfile, body, nil
}

// extractOriginAndCurrentMeasurements handles both:
//   - Official specification format: nested map {"0": 571(<<origin>>), "1": 571(<<current>>)}
//   - Temporary sample quote format: direct Tag 571 value without the outer "0"/"1" map.
func extractOriginAndCurrentMeasurements(submod cborValue) (cborValue, cborValue, error) {
	if submod.majorType == cborMajorMap {
		if originEntry, ok := submod.findTextKey("0"); ok {
			originMap, err := extractCoRIMMeasurements(originEntry)
			if err != nil {
				return cborValue{}, cborValue{}, err
			}
			var currentMap cborValue
			if currEntry, hasCurr := submod.findTextKey("1", "2"); hasCurr {
				if currentMap, err = extractCoRIMMeasurements(currEntry); err != nil {
					return cborValue{}, cborValue{}, err
				}
			}
			return originMap, currentMap, nil
		}
	}
	// TODO: Remove direct Tag 571 fallback once temporary sample quote compatibility is no longer needed.
	// In the temporary integration sample quote, each OID key in -11 maps directly
	// to Tag 571(...) without an intermediate {"0": ..., "1": ...} map.
	m, err := extractCoRIMMeasurements(submod)
	return m, cborValue{}, err
}

// extractCoRIMMeasurements navigates a CBOR Tag 571 (CoRIM / Concise Evidence) value:
//   - Official specification format: Tag(571, << bstr containing concise-evidence-map >>)
//   - Temporary sample quote format: Tag(571, concise-evidence-map directly)
//
// and returns the inner measurement-values-map.
func extractCoRIMMeasurements(v cborValue) (cborValue, error) {
	if v.majorType != cborMajorTag || v.tagNum != cborTagCoRIM || v.taggedVal == nil {
		return cborValue{}, fmt.Errorf("expected CBOR Tag %d, got majorType=%d tag=%d", cborTagCoRIM, v.majorType, v.tagNum)
	}
	curr := *v.taggedVal
	// TODO: Require embedded CBOR bytes (cborMajorBytes) inside Tag 571 once temporary sample quote compatibility is no longer needed.
	// In the official specification, Tag 571 wraps a byte string (<< concise-evidence-map >>).
	// In the temporary sample quote, Tag 571 directly wraps the CBOR map.
	if curr.majorType == cborMajorBytes {
		var err error
		if curr, err = decodeCBOR(curr.bytesVal); err != nil {
			return cborValue{}, fmt.Errorf("decoding embedded CoRIM CBOR bytes failed: %v", err)
		}
	}
	outer0, ok := curr.findIntKey(0)
	if !ok {
		return cborValue{}, fmt.Errorf("missing key 0 in CoRIM outer map")
	}
	triplesArr, ok := outer0.findIntKey(0)
	if !ok || triplesArr.majorType != cborMajorArray || len(triplesArr.arrayVal) == 0 {
		return cborValue{}, fmt.Errorf("missing or empty triples array at key 0 in CoRIM map")
	}
	triple := triplesArr.arrayVal[0]
	if triple.majorType != cborMajorArray || len(triple.arrayVal) < 2 {
		return cborValue{}, fmt.Errorf("invalid CoRIM triple structure")
	}
	measList := triple.arrayVal[1]
	if measList.majorType != cborMajorArray || len(measList.arrayVal) == 0 {
		return cborValue{}, fmt.Errorf("empty measurement list in CoRIM triple")
	}
	measValues, ok := measList.arrayVal[0].findIntKey(1)
	if !ok || measValues.majorType != cborMajorMap {
		return cborValue{}, fmt.Errorf("missing measurement values map (key 1) in CoRIM entry")
	}
	return measValues, nil
}

func extractBytesFromMap(m cborValue, key int64, fieldName string) ([]byte, error) {
	val, ok := m.findIntKey(key)
	if !ok {
		return nil, fmt.Errorf("missing %s (key %d)", fieldName, key)
	}
	if val.majorType != cborMajorBytes {
		return nil, fmt.Errorf("field %s (key %d) is not a byte string", fieldName, key)
	}
	return val.bytesVal, nil
}

func extractDigestFromMap(m cborValue, key int64, fieldName string) ([]byte, error) {
	val, ok := m.findIntKey(key)
	if !ok {
		return nil, fmt.Errorf("missing %s (key %d)", fieldName, key)
	}
	if val.majorType == cborMajorBytes {
		return val.bytesVal, nil
	}
	if val.majorType == cborMajorArray && len(val.arrayVal) == 2 && val.arrayVal[1].majorType == cborMajorBytes {
		return val.arrayVal[1].bytesVal, nil
	}
	return nil, fmt.Errorf("field %s (key %d) is not a valid CoRIM digest tuple", fieldName, key)
}

func extractSVNFromMap(m cborValue, key int64, fieldName string) ([]byte, error) {
	val, ok := m.findIntKey(key)
	if !ok {
		return nil, fmt.Errorf("missing %s (key %d)", fieldName, key)
	}
	if val.majorType == cborMajorBytes {
		return val.bytesVal, nil
	}
	if val.majorType == cborMajorArray {
		svn := make([]byte, len(val.arrayVal))
		for i, elem := range val.arrayVal {
			if elem.majorType != cborMajorUint || elem.intVal < 0 || elem.intVal > 0xff {
				return nil, fmt.Errorf("invalid SVN byte element at index %d in %s", i, fieldName)
			}
			svn[i] = byte(elem.intVal)
		}
		return svn, nil
	}
	return nil, fmt.Errorf("field %s (key %d) is not a valid SVN array or byte string", fieldName, key)
}

func checkDiceQuote(quote *pb.DiceQuote) error {
	if quote == nil {
		return ErrDiceQuoteNil
	}
	if len(quote.GetProtectedHeader()) == 0 {
		return fmt.Errorf("DiceQuote protectedHeader is empty")
	}
	if quote.GetAlgorithm() != coseAlgES384 {
		return fmt.Errorf("DiceQuote algorithm %d not supported, expected %d", quote.GetAlgorithm(), coseAlgES384)
	}
	if len(quote.GetCertChain()) == 0 {
		return fmt.Errorf("DiceQuote certChain is empty")
	}
	for i, cert := range quote.GetCertChain() {
		if len(cert) == 0 {
			return fmt.Errorf("DiceQuote certChain[%d] is empty", i)
		}
	}
	if len(quote.GetRawPayload()) == 0 {
		return fmt.Errorf("DiceQuote rawPayload is empty")
	}
	if quote.GetTdQuoteBody() == nil {
		return fmt.Errorf("DiceQuote TD Quote Body error: %v", ErrTDQuoteBodyNil)
	}
	if err := checkTDQuoteBodyV5(quote.GetTdQuoteBody(), tdxVersion15BodyType); err != nil {
		return fmt.Errorf("DiceQuote TD Quote Body error: %v", err)
	}
	if len(quote.GetSignature()) != DiceSignatureSize {
		return fmt.Errorf("DiceQuote signature size is %d bytes. Expected %d bytes", len(quote.GetSignature()), DiceSignatureSize)
	}
	return nil
}

func quoteToAbiBytesDICE(quote *pb.DiceQuote) ([]byte, error) {
	if err := CheckQuote(quote); err != nil {
		return nil, fmt.Errorf("DiceQuote invalid: %v", err)
	}
	if len(quote.GetRawQuote()) > 0 {
		return clone(quote.GetRawQuote()), nil
	}
	return encodeDiceQuoteCBOR(quote), nil
}

func encodeCBORHead(majorType uint8, arg uint64) []byte {
	prefix := majorType << 5
	switch {
	case arg < 24:
		return []byte{prefix | uint8(arg)}
	case arg <= 0xff:
		return []byte{prefix | 24, uint8(arg)}
	case arg <= 0xffff:
		b := []byte{prefix | 25, 0, 0}
		binary.BigEndian.PutUint16(b[1:], uint16(arg))
		return b
	case arg <= 0xffffffff:
		b := []byte{prefix | 26, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(b[1:], uint32(arg))
		return b
	default:
		b := make([]byte, 9)
		b[0] = prefix | 27
		binary.BigEndian.PutUint64(b[1:], arg)
		return b
	}
}

func encodeCBORBytes(b []byte) []byte {
	return append(encodeCBORHead(cborMajorBytes, uint64(len(b))), b...)
}

func encodeCBORText(s string) []byte {
	return append(encodeCBORHead(cborMajorText, uint64(len(s))), s...)
}

func encodeDiceQuoteCBOR(quote *pb.DiceQuote) []byte {
	var out []byte
	// Tag 61 (CWT) + Tag 18 (COSE_Sign1) + 4-element array.
	out = append(out, encodeCBORHead(cborMajorTag, cborTagCWT)...)
	out = append(out, encodeCBORHead(cborMajorTag, cborTagCOSESign1)...)
	out = append(out, encodeCBORHead(cborMajorArray, 4)...)

	// 1. Protected header bstr.
	out = append(out, encodeCBORBytes(quote.GetProtectedHeader())...)

	// 2. Unprotected header map.
	mapEntries := uint64(1) // certChain is always present
	if len(quote.GetKeyId()) > 0 {
		mapEntries++
	}
	if quote.GetContentType() != "" {
		mapEntries++
	}
	out = append(out, encodeCBORHead(cborMajorMap, mapEntries)...)
	if len(quote.GetKeyId()) > 0 {
		out = append(out, encodeCBORHead(cborMajorUint, coseHeaderKid)...)
		out = append(out, encodeCBORBytes(quote.GetKeyId())...)
	}
	if quote.GetContentType() != "" {
		out = append(out, encodeCBORHead(cborMajorUint, coseHeaderContentType)...)
		out = append(out, encodeCBORText(quote.GetContentType())...)
	}
	out = append(out, encodeCBORHead(cborMajorUint, coseHeaderX5Bag)...)
	out = append(out, encodeCBORHead(cborMajorArray, uint64(len(quote.GetCertChain())))...)
	for _, cert := range quote.GetCertChain() {
		out = append(out, encodeCBORBytes(cert)...)
	}

	// 3. Payload bstr.
	out = append(out, encodeCBORBytes(quote.GetRawPayload())...)

	// 4. Signature bstr.
	out = append(out, encodeCBORBytes(quote.GetSignature())...)
	return out
}
