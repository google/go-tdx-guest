// Copyright 2023 Google LLC
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

// Package pcs defines values specified for the Intel's Provisioning Certification Service
package pcs

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

const (
	pckCertExtensionSize = 6
	sgxExtensionMinSize  = 4
	tcbExtensionSize     = 18
	ppidSize             = 16
	cpuSvnSize           = 16
	fmspcSize            = 6
	pceIDSize            = 2
	tcbComponentSize     = 16
	// sgxPckCrlIssuerChainHeaderKey retrieves the issuer chain from the Intel PCS API:
	// https://api.portal.trustedservices.intel.com/content/documentation.html#pcs-revocation-v4
	sgxPckCrlIssuerChainHeaderKey = "SGX-PCK-CRL-Issuer-Chain"
	// sgxQeIdentityIssuerChainHeaderKey retrieves the issuer chain from the Intel PCS API:
	// https://api.portal.trustedservices.intel.com/content/documentation.html#pcs-enclave-identity-v4
	sgxQeIdentityIssuerChainHeaderKey = "SGX-Enclave-Identity-Issuer-Chain"
	// tcbInfoIssuerChainHeaderKey retrieves the issuer chain from the Intel PCS API:
	// https://api.portal.trustedservices.intel.com/content/documentation.html#pcs-tcb-info-tdx-v4
	tcbInfoIssuerChainHeaderKey = "TCB-Info-Issuer-Chain"
	// SgxBaseURL is the base URL for fetching SGX related info from the Intel PCS API.
	SgxBaseURL = "https://api.trustedservices.intel.com/sgx/certification/v4"
	// TdxBaseURL is the base URL for fetching TDX related info from the Intel PCS API.
	TdxBaseURL = "https://api.trustedservices.intel.com/tdx/certification/v4"
)

var (
	sgxTcbComponentOidPrefix = []int{1, 2, 840, 113741, 1, 13, 1, 2}

	// SgxPckCrlIssuerChainPhrase conforms to the canonicalized header key format used by Go's net/http package.
	SgxPckCrlIssuerChainPhrase = http.CanonicalHeaderKey(sgxPckCrlIssuerChainHeaderKey)
	// SgxQeIdentityIssuerChainPhrase conforms to the canonicalized header key format used by Go's net/http package.
	SgxQeIdentityIssuerChainPhrase = http.CanonicalHeaderKey(sgxQeIdentityIssuerChainHeaderKey)
	// TcbInfoIssuerChainPhrase conforms to the canonicalized header key format used by Go's net/http package.
	TcbInfoIssuerChainPhrase = http.CanonicalHeaderKey(tcbInfoIssuerChainHeaderKey)

	// OidSgxExtension is the x509v3 extension for PCK certificate's SGX Extension.
	OidSgxExtension = asn1.ObjectIdentifier([]int{1, 2, 840, 113741, 1, 13, 1})
	// OidPPID is the x509v3 extension for PCK certificate's SGX Extensions PPID value.
	OidPPID = asn1.ObjectIdentifier([]int{1, 2, 840, 113741, 1, 13, 1, 1})
	// OidTCB is the x509v3 extension for PCK certificate's SGX Extensions TCB struct.
	OidTCB = asn1.ObjectIdentifier([]int{1, 2, 840, 113741, 1, 13, 1, 2})
	// OidPCESvn is the x509v3 extension for PCK certificate's SGX Extensions PCESVN component in TCB struct.
	OidPCESvn = asn1.ObjectIdentifier([]int{1, 2, 840, 113741, 1, 13, 1, 2, 17})
	// OidCPUSvn is the x509v3 extension for PCK certificate's SGX Extensions CPUSVN component in TCB struct.
	OidCPUSvn = asn1.ObjectIdentifier([]int{1, 2, 840, 113741, 1, 13, 1, 2, 18})
	// OidPCEID is the x509v3 extension for PCK certificate's SGX Extensions PCEID value.
	OidPCEID = asn1.ObjectIdentifier([]int{1, 2, 840, 113741, 1, 13, 1, 3})
	// OidFMSPC  is the x509v3 extension for PCK certificate's SGX Extensions FMSPC value.
	OidFMSPC = asn1.ObjectIdentifier([]int{1, 2, 840, 113741, 1, 13, 1, 4})

	// ErrPckExtInvalid error returned when parsing PCK certificate's extension returns leftover bytes
	ErrPckExtInvalid = errors.New("unexpected leftover bytes for PCK certificate's extension")
	// ErrTcbExtInvalid error returned when parsing of TCB in SGX Extension returns leftover bytes
	ErrTcbExtInvalid = errors.New("unexpected leftover bytes for TCB extension inside SGX extension field")
	// ErrTcbCompInvalid error returned when parsing of TCB components in SGX Extension returns leftover bytes
	ErrTcbCompInvalid = errors.New("unexpected leftover bytes for TCB components in TCB Extension inside SGX extension field")
	// ErrSgxExtInvalid  error returned when parsing SGX extensions returns leftover bytes
	ErrSgxExtInvalid = errors.New("unexpected leftover bytes when parsing SGX extensions")
)

// TdxTcbInfo struct is used to map response from tcbInfo PCS API Service
type TdxTcbInfo struct {
	TcbInfo   TcbInfo `json:"tcbInfo"`
	Signature string  `json:"signature"`
}

// TcbInfo struct is used to map response from tcbInfo field
type TcbInfo struct {
	ID                      string              `json:"id"`
	Version                 byte                `json:"version"`
	IssueDate               time.Time           `json:"issueDate"`
	NextUpdate              time.Time           `json:"nextUpdate"`
	Fmspc                   string              `json:"fmspc"`
	PceID                   string              `json:"pceId"`
	TcbType                 byte                `json:"tcbType"`
	TcbEvaluationDataNumber int                 `json:"tcbEvaluationDataNumber"`
	TdxModule               TdxModule           `json:"tdxModule"`
	TdxModuleIdentities     []TdxModuleIdentity `json:"tdxModuleIdentities"`
	TcbLevels               []TcbLevel          `json:"tcbLevels"`
}

// TdxModule struct is used to map response from tcbInfo for tdxModule field
type TdxModule struct {
	Mrsigner       HexBytes `json:"mrsigner"`
	Attributes     HexBytes `json:"attributes"`
	AttributesMask HexBytes `json:"attributesMask"`
}

// TdxModuleIdentity struct is used to map response from tcbInfo for TdxModuleIdentity field
type TdxModuleIdentity struct {
	ID             string     `json:"id"`
	Mrsigner       HexBytes   `json:"mrsigner"`
	Attributes     HexBytes   `json:"attributes"`
	AttributesMask HexBytes   `json:"attributesMask"`
	TcbLevels      []TcbLevel `json:"tcbLevels"`
}

// TcbLevel struct is used to map TCB Level field
type TcbLevel struct {
	Tcb         Tcb                `json:"tcb"`
	TcbDate     string             `json:"tcbDate"`
	TcbStatus   TcbComponentStatus `json:"tcbStatus"`
	AdvisoryIDs []string           `json:"advisoryIDs"`
}

// Tcb struct is used to map TCB field
type Tcb struct {
	SgxTcbcomponents []TcbComponent `json:"sgxtcbcomponents"`
	Pcesvn           uint16         `json:"pcesvn"`
	TdxTcbcomponents []TcbComponent `json:"tdxtcbcomponents"`
	Isvsvn           uint32         `json:"isvsvn"`
}

// TcbComponent struct is used to map sgx/tdx tcb components
type TcbComponent struct {
	Svn      byte   `json:"svn"`
	Category string `json:"category"`
	Type     string `json:"type"`
}

// QeIdentity struct is used to map response from enclaveIdentity PCS API Call
type QeIdentity struct {
	EnclaveIdentity EnclaveIdentity `json:"enclaveIdentity"`
	Signature       string          `json:"signature"`
}

// EnclaveIdentity struct is used to map enclave identity field
type EnclaveIdentity struct {
	ID                      string     `json:"id"`
	Version                 byte       `json:"version"`
	IssueDate               time.Time  `json:"issueDate"`
	NextUpdate              time.Time  `json:"nextUpdate"`
	TcbEvaluationDataNumber int        `json:"tcbEvaluationDataNumber"`
	Miscselect              HexBytes   `json:"miscselect"`
	MiscselectMask          HexBytes   `json:"miscselectMask"`
	Attributes              HexBytes   `json:"attributes"`
	AttributesMask          HexBytes   `json:"attributesMask"`
	Mrsigner                HexBytes   `json:"mrsigner"`
	IsvProdID               uint16     `json:"isvprodid"`
	TcbLevels               []TcbLevel `json:"tcbLevels"`
}

// PckCertTCB represents struct that store information related to TCB components
type PckCertTCB struct {
	PCESvn           uint16
	CPUSvn           []byte
	CPUSvnComponents []byte
}

// PckExtensions represents the information stored in the x509 extensions of a PCK certificate which
// will be required for verification
type PckExtensions struct {
	PPID  string
	TCB   PckCertTCB
	PCEID string
	FMSPC string
}

// HexBytes struct contains hex decoded string to bytes value
type HexBytes struct {
	Bytes []byte
}

// UnmarshalJSON for hex bytes converts hex encoded string to bytes
func (hb *HexBytes) UnmarshalJSON(s []byte) error {
	unquoted, err := strconv.Unquote(string(s))
	if err != nil {
		return err
	}
	val, err := hex.DecodeString(unquoted)
	if err != nil {
		return err
	}
	hb.Bytes = val
	return nil
}

// TcbComponentStatus represents the status of corresponding TCB field
type TcbComponentStatus string

const (
	// TcbComponentStatusUpToDate denotes tcb status as UpToDate
	TcbComponentStatusUpToDate TcbComponentStatus = "UpToDate"
	// TcbComponentStatusSwHardeningNeeded denotes tcb status as SWHardeningNeeded
	TcbComponentStatusSwHardeningNeeded TcbComponentStatus = "SWHardeningNeeded"
	// TcbComponentStatusConfigurationNeeded denotes tcb status as ConfigurationNeeded
	TcbComponentStatusConfigurationNeeded TcbComponentStatus = "ConfigurationNeeded"
	// TcbComponentStatusConfigurationAndSWHardeningNeeded denotes tcb status as ConfigurationAndSWHardeningNeeded
	TcbComponentStatusConfigurationAndSWHardeningNeeded TcbComponentStatus = "ConfigurationAndSWHardeningNeeded"
	// TcbComponentStatusOutOfDate denotes tcb status as OutOfDate
	TcbComponentStatusOutOfDate TcbComponentStatus = "OutOfDate"
	// TcbComponentStatusOutOfDateConfigurationNeeded denotes tcb status as OutOfDateConfigurationNeeded
	TcbComponentStatusOutOfDateConfigurationNeeded TcbComponentStatus = "OutOfDateConfigurationNeeded"
	// TcbComponentStatusRevoked denotes tcb status as Revoked
	TcbComponentStatusRevoked TcbComponentStatus = "Revoked"
)

// UnmarshalJSON for TcbComponentStatus maps tcb status to corresponding valid strings
func (st *TcbComponentStatus) UnmarshalJSON(s []byte) error {
	unquotedStatus, err := strconv.Unquote(string(s))
	if err != nil {
		return err
	}
	val := TcbComponentStatus(unquotedStatus)
	switch val {
	case TcbComponentStatusUpToDate, TcbComponentStatusSwHardeningNeeded, TcbComponentStatusConfigurationNeeded,
		TcbComponentStatusConfigurationAndSWHardeningNeeded, TcbComponentStatusOutOfDate, TcbComponentStatusOutOfDateConfigurationNeeded, TcbComponentStatusRevoked:
		*st = val

	default:
		return fmt.Errorf("unexpected tcb status found: %q", val)
	}
	return nil
}

func sgxTcbComponentOid(component int) asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier(append(sgxTcbComponentOidPrefix, component))
}

func asn1U8(ext *pkix.AttributeTypeAndValue, field string, out *byte) error {
	if ext == nil {
		return fmt.Errorf("no extension for field %s", field)
	}
	val, ok := ext.Value.(int64)
	if !ok {
		return fmt.Errorf("%s extension is of type %T, expected int64", field, ext.Value)
	}

	if val < 0 || val > 255 {
		return fmt.Errorf("int value for field %s isn't a byte: %d", field, val)
	}
	*out = byte(val)
	return nil
}

func asn1U16(ext *pkix.AttributeTypeAndValue, field string, out *uint16) error {
	if ext == nil {
		return fmt.Errorf("no extension for field %s", field)
	}
	val, ok := ext.Value.(int64)
	if !ok {
		return fmt.Errorf("%s extension is of type %T, expected int64", field, ext.Value)
	}

	if val < 0 || val > 65535 {
		return fmt.Errorf("int value for field %s isn't a uint16: %d", field, val)
	}
	*out = uint16(val)
	return nil
}

func asn1OctetString(ext *pkix.Extension, field string, size int) ([]byte, error) {
	if ext == nil {
		return nil, fmt.Errorf("no extension for field %s", field)
	}

	if len(ext.Value) == size {
		return ext.Value, nil
	}

	var octet []byte
	rest, err := asn1.Unmarshal(ext.Value, &octet)
	if err != nil {
		return nil, fmt.Errorf("could not parse %v extension as an octet string %v (value %v): %v", field, *ext, ext.Value, err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("expected leftover bytes in extension value for field %v", field)
	}
	// Check the expected length.
	if size >= 0 && len(octet) != size {
		return nil, fmt.Errorf("%v extension's value size is %d, expected %d", field, len(octet), size)
	}
	return octet, nil
}

func extractTcbExtension(tcbExtension []asn1.RawValue, tcb *PckCertTCB) error {
	tcbComponents := make([]byte, tcbComponentSize)
	for _, ext := range tcbExtension {
		var tcbValue pkix.AttributeTypeAndValue
		rest, err := asn1.Unmarshal(ext.FullBytes, &tcbValue)
		if err != nil {
			return fmt.Errorf("could not parse TCB component inside the TCB extension in the PCK certificate: %v", err)
		}
		if len(rest) != 0 {
			return ErrTcbCompInvalid
		}
		for i := 0; i < tcbComponentSize; i++ {
			tcbComponentOid := sgxTcbComponentOid(i + 1)
			if tcbValue.Type.Equal(tcbComponentOid) {
				phrase := fmt.Sprintf("sgxTcbComponent%d", i+1)
				var val byte
				if err := asn1U8(&tcbValue, phrase, &val); err != nil {
					return err
				}
				tcbComponents[i] = val
				break
			}
		}

		if tcbValue.Type.Equal(OidPCESvn) {
			if err := asn1U16(&tcbValue, "PCESvn", &tcb.PCESvn); err != nil {
				return err
			}
		}

		if tcbValue.Type.Equal(OidCPUSvn) {
			val, ok := tcbValue.Value.([]byte)
			if !ok {
				return fmt.Errorf("CPUSVN component in TCB extension is of type %T, expected []byte", tcbValue.Value)
			}
			if len(tcbValue.Value.([]byte)) != cpuSvnSize {
				return fmt.Errorf("CPUSVN component in TCB extension is of size %d, expected %d", len(tcbValue.Value.([]byte)), cpuSvnSize)
			}
			tcb.CPUSvn = val
		}
	}
	tcb.CPUSvnComponents = tcbComponents
	return nil
}

func extractAsn1SequenceTcbExtension(ext asn1.RawValue) (*PckCertTCB, error) {
	tcb := &PckCertTCB{}
	var sExtension []asn1.RawValue
	rest, err := asn1.Unmarshal(ext.FullBytes, &sExtension)
	if err != nil {
		return nil, fmt.Errorf("could not parse TCB extension present inside the SGX extension in PCK certificate: %v", err)
	}
	if len(rest) != 0 {
		return nil, ErrTcbExtInvalid
	}
	if len(sExtension) != 2 {
		return nil, fmt.Errorf("TCB extension when unmarshalled is of size %d, expected 2", len(sExtension))
	}

	var tcbExtension []asn1.RawValue
	rest, err = asn1.Unmarshal(sExtension[1].FullBytes, &tcbExtension)
	if err != nil {
		return nil, fmt.Errorf("could not parse TCB components present inside the SGX extension in PCK certificate: %v", err)
	}
	if len(rest) != 0 {
		return nil, ErrTcbCompInvalid
	}
	if len(tcbExtension) != tcbExtensionSize {
		return nil, fmt.Errorf("TCB extension is of size %d, expected %d", len(tcbExtension), tcbExtensionSize)
	}
	if err := extractTcbExtension(tcbExtension, tcb); err != nil {
		return nil, err
	}

	return tcb, nil
}

func extractAsn1OctetStringExtension(name string, extension asn1.RawValue, size int) (string, error) {
	var sExtension pkix.Extension
	rest, err := asn1.Unmarshal(extension.FullBytes, &sExtension)
	if err != nil {
		return "", fmt.Errorf("could not parse %s present inside the SGX extension in PCK certificate: %v", name, err)
	}
	if len(rest) != 0 {
		return "", fmt.Errorf("unexpected leftover bytes for %s extension inside SGX extension field", name)
	}
	val, err := asn1OctetString(&sExtension, name, size)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(val), nil
}

func extractSgxExtensions(extensions []asn1.RawValue) (*PckExtensions, error) {
	pckExtension := &PckExtensions{}
	if len(extensions) < sgxExtensionMinSize {
		return nil, fmt.Errorf("SGX Extension has length %d. It should have a minimum length of %d", len(extensions), sgxExtensionMinSize)
	}

	for i, ext := range extensions {
		var sExtension pkix.AttributeTypeAndValue
		rest, err := asn1.Unmarshal(ext.FullBytes, &sExtension)
		if err != nil {
			return nil, fmt.Errorf("could not parse SGX extension's in PCK certificate: %v", err)
		}
		if len(rest) != 0 {
			return nil, ErrSgxExtInvalid
		}
		if sExtension.Type.Equal(OidPPID) {
			pckExtension.PPID, err = extractAsn1OctetStringExtension("PPID", extensions[i], ppidSize)
			if err != nil {
				return nil, err
			}
		}
		if sExtension.Type.Equal(OidTCB) {
			tcb, err := extractAsn1SequenceTcbExtension(extensions[i])
			if err != nil {
				return nil, err
			}
			pckExtension.TCB = *tcb
		}
		if sExtension.Type.Equal(OidPCEID) {
			pckExtension.PCEID, err = extractAsn1OctetStringExtension("PCEID", extensions[i], pceIDSize)
			if err != nil {
				return nil, err
			}
		}
		if sExtension.Type.Equal(OidFMSPC) {
			pckExtension.FMSPC, err = extractAsn1OctetStringExtension("FMSPC", extensions[i], fmspcSize)
			if err != nil {
				return nil, err
			}
		}
	}
	return pckExtension, nil
}

func findMatchingExtension(extns []pkix.Extension, oid asn1.ObjectIdentifier) (*pkix.Extension, error) {
	for _, ext := range extns {
		if ext.Id.Equal(oid) {
			return &ext, nil
		}
	}
	return nil, fmt.Errorf("unable to find extension with OID %v in PCK Certificate", oid)
}

// PckCertificateExtensions returns only those x509v3 extensions from the PCK certificate into a
// struct type which will be required in verification purpose.
func PckCertificateExtensions(cert *x509.Certificate) (*PckExtensions, error) {
	if len(cert.Extensions) != pckCertExtensionSize {
		return nil, fmt.Errorf("PCK certificate extensions length found %d. Expected %d", len(cert.Extensions), pckCertExtensionSize)
	}

	sgxExt, err := findMatchingExtension(cert.Extensions, OidSgxExtension)
	if err != nil {
		return nil, fmt.Errorf("could not find SGX extension present in the PCK certificate: %v", err)
	}
	var sgxExtensions []asn1.RawValue
	rest, err := asn1.Unmarshal(sgxExt.Value, &sgxExtensions)
	if err != nil {
		return nil, fmt.Errorf("could not parse SGX extension present in the PCK certificate: %v", err)
	}
	if len(rest) != 0 {
		return nil, ErrPckExtInvalid
	}
	return extractSgxExtensions(sgxExtensions)
}

// PckCrlURL  returns the Intel PCS URL for retrieving PCK CRL
func PckCrlURL(ca string) string {
	return fmt.Sprintf("%s/pckcrl?ca=%s&encoding=der", SgxBaseURL, ca)
}

// TcbInfoURL returns the Intel PCS URL for retrieving TCB Info
func TcbInfoURL(fmspc string) string {
	return fmt.Sprintf("%s/tcb?fmspc=%s", TdxBaseURL, fmspc)
}

// QeIdentityURL returns the Intel PCS URL for retrieving QE identity
func QeIdentityURL() string {
	return fmt.Sprintf("%s/qe/identity", TdxBaseURL)
}
