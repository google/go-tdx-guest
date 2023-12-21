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

package verify

import (
	"crypto/x509"
	"encoding/hex"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/google/go-tdx-guest/abi"
	"github.com/google/go-tdx-guest/pcs"
	pb "github.com/google/go-tdx-guest/proto/tdx"
	testcases "github.com/google/go-tdx-guest/testing"
	"github.com/google/go-tdx-guest/testing/testdata"
	"github.com/google/logger"
)

var (
	// Adjust currentTime to compare against so that the validity with respect to time is always true.
	currentTime = time.Date(2023, time.July, 1, 1, 0, 0, 0, time.UTC)

	// Adjust futureTime to compare against so that the validity with respect to time fails.
	futureTime = time.Date(2053, time.July, 1, 1, 0, 0, 0, time.UTC)
)

func setTcbSvnValues(sgxSvn byte, tdxSvn byte, tdxTcbcomponents *[]pcs.TcbComponent, sgxTcbcomponents *[]pcs.TcbComponent) {
	sgxComponents := *sgxTcbcomponents
	tdxComponents := *tdxTcbcomponents
	for i := 0; i < len(sgxComponents); i++ {
		sgxComponents[i].Svn = sgxSvn
		tdxComponents[i].Svn = tdxSvn
	}
}

func TestMain(m *testing.M) {
	logger.Init("VerifyTestLog", false, false, os.Stderr)
	os.Exit(m.Run())
}

func TestParsePckChain(t *testing.T) {
	quote, err := abi.QuoteToProto(testdata.RawQuote)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := extractChainFromQuote(quote); err != nil {
		t.Fatal(err)
	}
}

func TestPckCertificateExtensions(t *testing.T) {

	quote, err := abi.QuoteToProto(testdata.RawQuote)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := extractChainFromQuote(quote)
	if err != nil {
		t.Fatal(err)
	}
	pckExt := &pcs.PckExtensions{}
	ppidBytes := []byte{8, 157, 223, 219, 156, 3, 89, 200, 42, 59, 199, 113, 146, 57, 87, 78}
	fmspcBytes := []byte{80, 128, 111, 0, 0, 0}
	pceIDBytes := []byte{0, 0}
	pckExt.PPID = hex.EncodeToString(ppidBytes)
	pckExt.FMSPC = hex.EncodeToString(fmspcBytes)
	pckExt.PCEID = hex.EncodeToString(pceIDBytes)
	pckExtTcb := &pcs.PckCertTCB{
		PCESvn:           11,
		CPUSvn:           []byte{3, 3, 2, 2, 2, 1, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0},
		CPUSvnComponents: []byte{3, 3, 2, 2, 2, 1, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0},
	}
	pckExt.TCB = *pckExtTcb
	ext, err := pcs.PckCertificateExtensions(chain.PCKCertificate)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(ext, pckExt) {
		t.Errorf("PCK certificate's extension(%v), does not match with expected extension(%v)", ext, pckExt)
	}
}

func TestVerifyPckChainWithoutRevocation(t *testing.T) {
	quote, err := abi.QuoteToProto(testdata.RawQuote)
	if err != nil {
		t.Fatal(err)
	}
	pckChain, err := extractChainFromQuote(quote)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyEvidence(quote, &Options{CheckRevocations: false, GetCollateral: false, chain: pckChain, Now: currentTime}); err != nil {
		t.Error(err)
	}
}

func TestNegativeVerifyPckChainWithoutRevocation(t *testing.T) {
	quote, err := abi.QuoteToProto(testdata.RawQuote)
	if err != nil {
		t.Fatal(err)
	}
	pckChain, err := extractChainFromQuote(quote)
	if err != nil {
		t.Fatal(err)
	}
	wantErr := "error verifying PCK Certificate: x509: certificate has expired or is not yet valid: current time 2053-07-01T01:00:00Z is after 2029-09-20T13:20:31Z (true)"
	if err := verifyEvidence(quote, &Options{CheckRevocations: false, GetCollateral: false, chain: pckChain, Now: futureTime}); err == nil || err.Error() != wantErr {
		t.Errorf("Certificates Expired: verifyEvidence() = %v. Want error: %v.", err, wantErr)
	}
}

func TestVerifyPckLeafCertificate(t *testing.T) {
	quote, err := abi.QuoteToProto(testdata.RawQuote)
	if err != nil {
		t.Fatal(err)
	}
	pckChain, err := extractChainFromQuote(quote)
	if err != nil {
		t.Fatal(err)
	}
	pckLeafCert := pckChain.PCKCertificate
	opts := &Options{CheckRevocations: false, GetCollateral: false, TrustedRoots: nil, chain: pckChain}
	chains, err := pckLeafCert.Verify(x509Options(opts.TrustedRoots, pckChain.IntermediateCertificate, opts.Now))

	if err != nil {
		t.Fatal(err)
	}
	if len(chains) != 1 {
		t.Fatalf("x509 verification returned %d chains, want 1", len(chains))
	}
	if len(chains[0]) != 3 {
		t.Fatalf("x509 verification returned a chain of length %d, want length 3", len(chains[0]))
	}
	if !chains[0][0].Equal(pckChain.PCKCertificate) {
		t.Errorf("PCK verification chain did not start with the PCK Leaf certificate: %v", chains[0][0])
	}
	if !chains[0][1].Equal(pckChain.IntermediateCertificate) {
		t.Errorf("PCK verification chain did not step to with the Intermediate CA certificate: %v", chains[0][1])
	}
	if !chains[0][2].Equal(trustedRootCertificate) {
		t.Errorf("PCK verification chain did not end with the Trusted Root certificate: %v", chains[0][2])
	}
}

func TestValidateX509Certificate(t *testing.T) {
	quote, err := abi.QuoteToProto(testdata.RawQuote)
	if err != nil {
		t.Fatal(err)
	}
	pckChain, err := extractChainFromQuote(quote)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateX509Cert(pckChain.PCKCertificate, 3, x509.ECDSAWithSHA256, x509.ECDSA, "P-256"); err != nil {
		t.Error(err)
	}
}

func TestNegativeValidateX509Certificate(t *testing.T) {
	quote, err := abi.QuoteToProto(testdata.RawQuote)
	if err != nil {
		t.Fatal(err)
	}
	pckChain, err := extractChainFromQuote(quote)
	if err != nil {
		t.Fatal(err)
	}

	type input struct {
		cert               *x509.Certificate
		version            int
		signatureAlgorithm x509.SignatureAlgorithm
		publicKeyAlgorithm x509.PublicKeyAlgorithm
		curve              string
	}
	tests := []struct {
		name    string
		input   input
		wantErr string
	}{
		{
			name: "Version Invalid",
			input: input{
				cert:               pckChain.PCKCertificate,
				version:            4,
				signatureAlgorithm: x509.ECDSAWithSHA256,
				publicKeyAlgorithm: x509.ECDSA,
				curve:              "P-256",
			},
			wantErr: "certificate's version found 3. Expected 4",
		},
		{
			name: "Signature Algorithm Invalid",
			input: input{
				cert:               pckChain.PCKCertificate,
				version:            3,
				signatureAlgorithm: x509.ECDSAWithSHA1,
				publicKeyAlgorithm: x509.ECDSA,
				curve:              "P-256",
			},
			wantErr: "certificate's signature algorithm found ECDSA-SHA256. Expected ECDSA-SHA1",
		},
		{
			name: "Public Key Algorithm Invalid",
			input: input{
				cert:               pckChain.PCKCertificate,
				version:            3,
				signatureAlgorithm: x509.ECDSAWithSHA256,
				publicKeyAlgorithm: x509.Ed25519,
				curve:              "P-256",
			},
			wantErr: "certificate's public Key algorithm found ECDSA. Expected Ed25519",
		},
		{
			name: "Public Key Curve Invalid",
			input: input{
				cert:               pckChain.PCKCertificate,
				version:            3,
				signatureAlgorithm: x509.ECDSAWithSHA256,
				publicKeyAlgorithm: x509.ECDSA,
				curve:              "P-300",
			},
			wantErr: `certificate's public key curve is "P-256". Expected "P-300"`,
		},
	}

	for _, tc := range tests {
		if err := validateX509Cert(tc.input.cert, tc.input.version, tc.input.signatureAlgorithm, tc.input.publicKeyAlgorithm, tc.input.curve); err == nil || err.Error() != tc.wantErr {
			t.Errorf("%s: validateX509Cert() = %v. Want error %v", tc.name, err, tc.wantErr)
		}
	}
}

func TestRawQuoteVerifyWithoutCollateral(t *testing.T) {
	options := &Options{CheckRevocations: false, GetCollateral: false, Now: currentTime}
	if err := RawTdxQuote(testdata.RawQuote, options); err != nil {
		t.Error(err)
	}
}
func TestVerifyQuoteV4(t *testing.T) {
	anyQuote, err := abi.QuoteToProto(testdata.RawQuote)
	if err != nil {
		t.Fatal(err)
	}
	quote, ok := anyQuote.(*pb.QuoteV4)
	if !ok {
		t.Fatal("Quote is not a QuoteV4")
	}
	pckChain, err := extractChainFromQuote(anyQuote)
	if err != nil {
		t.Fatal(err)
	}
	options := &Options{CheckRevocations: false, GetCollateral: false, chain: pckChain, Now: currentTime}
	if err := verifyQuote(quote, options); err != nil {
		t.Error(err)
	}
}

func TestNegativeVerification(t *testing.T) {
	tests := []struct {
		name        string
		changeIndex int
		changeValue byte
		wantErr     string
	}{
		{
			name:        "Version byte Changed",
			changeIndex: 0x00,
			changeValue: 3,
			wantErr:     "could not convert raw bytes to QuoteV4: Quote format not supported",
		},
		{
			name:        "Signed data size byte Changed",
			changeIndex: 0x278,
			changeValue: 0x10,
			wantErr:     "could not convert raw bytes to QuoteV4: size of certificate data is 0xf8a. Expected size 0x1045",
		},
		{
			name:        "Certificate chain byte Changed",
			changeIndex: 0x1343,
			changeValue: 0x32,
			wantErr:     ErrPCKCertChainInvalid.Error(),
		},
		{
			name:        "Root Certificate byte Changed",
			changeIndex: 0x1329,
			changeValue: 0x32,
			wantErr:     "unable to validate root cert: certificate signature verification using parent certificate failed: x509: ECDSA verification failure",
		},
		{
			name:        "Intermediate Certificate byte Changed",
			changeIndex: 0xF5F,
			changeValue: 0x32,
			wantErr:     `unable to validate Intermediate CA certificate: certificate signature verification using parent certificate failed: x509: ECDSA verification failure`,
		},
		{
			name:        "PCK Certificate byte Changed",
			changeIndex: 0xB77,
			changeValue: 0x32,
			wantErr:     `unable to validate PCK leaf certificate: certificate signature verification using parent certificate failed: x509: ECDSA verification failure`,
		},
		{
			name:        "Header Byte Changed",
			changeIndex: 0x1E,
			changeValue: 0x32,
			wantErr:     "unable to verify message digest using quote's signature and ecdsa attestation key",
		},
		{
			name:        "TD Quote Body Changed",
			changeIndex: 0x3C,
			changeValue: 0x32,
			wantErr:     "unable to verify message digest using quote's signature and ecdsa attestation key",
		},
	}
	options := &Options{CheckRevocations: false, GetCollateral: false, TrustedRoots: nil, Now: currentTime}
	rawQuote := make([]byte, len(testdata.RawQuote))

	for _, tc := range tests {
		copy(rawQuote, testdata.RawQuote)
		rawQuote[tc.changeIndex] = tc.changeValue
		if err := RawTdxQuote(rawQuote, options); err == nil || err.Error() != tc.wantErr {
			t.Errorf("%s: RawTdxQuote() = %v. Want error %v", tc.name, err, tc.wantErr)
		}
	}
}

func TestGetPckCrl(t *testing.T) {
	getter := testcases.TestGetter
	ca := platformIssuerID
	collateral := &Collateral{}
	if err := getPckCrl(ca, getter, collateral); err != nil {
		t.Error(err)
	}
}

func TestGetTcbInfo(t *testing.T) {
	getter := testcases.TestGetter
	fmspcBytes := []byte{80, 128, 111, 0, 0, 0}
	fmspc := hex.EncodeToString(fmspcBytes)

	collateral := &Collateral{}
	if err := getTcbInfo(fmspc, getter, collateral); err != nil {
		t.Error(err)
	}
}

func TestGetQeIdentity(t *testing.T) {
	getter := testcases.TestGetter
	collateral := &Collateral{}
	if err := getQeIdentity(getter, collateral); err != nil {
		t.Error(err)
	}
}

func TestGetRootCRL(t *testing.T) {
	getter := testcases.TestGetter
	collateral := &Collateral{}
	if err := getQeIdentity(getter, collateral); err != nil {
		t.Fatal(err)
	}

	if err := getRootCrl(getter, collateral); err != nil {
		t.Error(err)
	}
}

func TestExtractFmspcAndCaFromPckCert(t *testing.T) {
	quote, err := abi.QuoteToProto(testdata.RawQuote)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := extractChainFromQuote(quote)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := extractCaFromPckCert(chain.PCKCertificate)
	if err != nil {
		t.Fatal(err)
	}
	if ca != platformIssuerID {
		t.Errorf("ca extracted from PCK certificate (%q), does not match with expected ca (%q)", ca, platformIssuerID)
	}
	fmspcBytes := []byte{80, 128, 111, 0, 0, 0}
	fmspc := hex.EncodeToString(fmspcBytes)

	exts, err := pcs.PckCertificateExtensions(chain.PCKCertificate)
	if err != nil {
		t.Fatal(err)
	}
	if exts.FMSPC != fmspc {
		t.Errorf("fmspc extracted from PCK cert(%v), does not match with expected fmspc(%v)", exts.FMSPC, fmspc)
	}
}

func TestObtainAndVerifyCollateral(t *testing.T) {
	getter := testcases.TestGetter

	ca := platformIssuerID
	fmspcBytes := []byte{80, 128, 111, 0, 0, 0}
	fmspc := hex.EncodeToString(fmspcBytes)
	options := &Options{GetCollateral: true, CheckRevocations: true, Getter: getter, Now: currentTime}
	collateral, err := obtainCollateral(fmspc, ca, options)
	if err != nil {
		t.Fatal(err)
	}
	options.collateral = collateral
	if err := verifyCollateral(options); err != nil {
		t.Error(err)
	}
}

func TestNegativeObtainAndVerifyCollateral(t *testing.T) {
	getter := testcases.TestGetter
	ca := platformIssuerID
	fmspcBytes := []byte{80, 128, 111, 0, 0, 0}
	fmspc := hex.EncodeToString(fmspcBytes)

	options := &Options{GetCollateral: true, CheckRevocations: true, Getter: getter, Now: futureTime}
	collateral, err := obtainCollateral(fmspc, ca, options)
	if err != nil {
		t.Fatal(err)
	}
	options.collateral = collateral
	wantErr := "tcbInfo has expired"
	if err := verifyCollateral(options); err == nil || err.Error() != wantErr {
		t.Errorf("Collaterals Expired: verifyCollateral() = %v. Want error %v", err, wantErr)
	}
}

func TestVerifyUsingTcbInfoV4(t *testing.T) {
	getter := testcases.TestGetter

	fmspcBytes := []byte{80, 128, 111, 0, 0, 0}
	fmspc := hex.EncodeToString(fmspcBytes)

	collateral := &Collateral{}
	if err := getTcbInfo(fmspc, getter, collateral); err != nil {
		t.Fatal(err)
	}
	anyQuote, err := abi.QuoteToProto(testdata.RawQuote)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := extractChainFromQuote(anyQuote)
	if err != nil {
		t.Fatal(err)
	}
	ext, err := pcs.PckCertificateExtensions(chain.PCKCertificate)
	if err != nil {
		t.Fatal(err)
	}

	tcbInfo := collateral.TdxTcbInfo.TcbInfo

	// Due to updated SVN values in the sample response, it will result in TCB status failure,
	// when compared to the TD Quote Body's TeeTcbSvn value.
	// For the purpose of testing, converting all SVNs value to 0
	setTcbSvnValues(0, 0, &tcbInfo.TcbLevels[0].Tcb.TdxTcbcomponents, &tcbInfo.TcbLevels[0].Tcb.SgxTcbcomponents)
	quote, ok := anyQuote.(*pb.QuoteV4)
	if !ok {
		t.Fatal("quote is not a QuoteV4")
	}
	if err := verifyTdQuoteBody(quote.GetTdQuoteBody(), &tdQuoteBodyOptions{tcbInfo: tcbInfo, pckCertExtensions: ext}); err != nil {
		t.Error(err)
	}
}

func TestNegativeVerifyUsingTcbInfoV4(t *testing.T) {
	getter := testcases.TestGetter

	fmspcBytes := []byte{80, 128, 111, 0, 0, 0}
	fmspc := hex.EncodeToString(fmspcBytes)

	collateral := &Collateral{}
	if err := getTcbInfo(fmspc, getter, collateral); err != nil {
		t.Fatal(err)
	}
	anyQuote, err := abi.QuoteToProto(testdata.RawQuote)
	if err != nil {
		t.Fatal(err)
	}
	quote, ok := anyQuote.(*pb.QuoteV4)
	if !ok {
		t.Fatal("quote is not a QuoteV4")
	}
	chain, err := extractChainFromQuote(quote)
	if err != nil {
		t.Fatal(err)
	}
	ext, err := pcs.PckCertificateExtensions(chain.PCKCertificate)
	if err != nil {
		t.Fatal(err)
	}

	tcbInfo := collateral.TdxTcbInfo.TcbInfo
	var sampleTcbInfo pcs.TdxTcbInfo

	sampleTcbInfo.TcbInfo = tcbInfo
	sampleTcbInfo.TcbInfo.Fmspc = "11111f000000"
	wantErr := `FMSPC from PCK Certificate("50806f000000") is not equal to FMSPC value from Intel PCS's reported TDX TCB info("11111f000000")`
	if err := verifyTdQuoteBody(quote.GetTdQuoteBody(), &tdQuoteBodyOptions{tcbInfo: sampleTcbInfo.TcbInfo, pckCertExtensions: ext}); err == nil || err.Error() != wantErr {
		t.Errorf("FMSPC value changed: VerifyTdQuoteBody() = %v. Want error %v", err, wantErr)
	}

	sampleTcbInfo.TcbInfo = tcbInfo
	sampleTcbInfo.TcbInfo.PceID = "1111"
	wantErr = `PCEID from PCK Certificate("0000") is not equal to PCEID from Intel PCS's reported TDX TCB info("1111")`
	if err := verifyTdQuoteBody(quote.GetTdQuoteBody(), &tdQuoteBodyOptions{tcbInfo: sampleTcbInfo.TcbInfo, pckCertExtensions: ext}); err == nil || err.Error() != wantErr {
		t.Errorf("PCEID value changed: verifyUsingTcbInfo() = %v. Want error %v", err, wantErr)
	}

	sampleTcbInfo.TcbInfo = tcbInfo
	sampleTcbInfo.TcbInfo.TdxModule.Mrsigner.Bytes = []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	wantErr = `MRSIGNERSEAM value from TD Quote Body("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000") is not equal to TdxModule.Mrsigner field in Intel PCS's reported TDX TCB info("0102030405060708090a")`
	if err := verifyTdQuoteBody(quote.GetTdQuoteBody(), &tdQuoteBodyOptions{tcbInfo: sampleTcbInfo.TcbInfo, pckCertExtensions: ext}); err == nil || err.Error() != wantErr {
		t.Errorf("Mrsigner value changed: verifyUsingTcbInfo() = %v. Want error %v", err, wantErr)
	}

	sampleTcbInfo.TcbInfo = tcbInfo
	sampleTcbInfo.TcbInfo.TdxModule.Attributes.Bytes = []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	wantErr = `AttributesMask value("0000000000000000") is not equal to TdxModule.Attributes field in Intel PCS's reported TDX TCB info("0102030405060708090a")`
	if err := verifyTdQuoteBody(quote.GetTdQuoteBody(), &tdQuoteBodyOptions{tcbInfo: sampleTcbInfo.TcbInfo, pckCertExtensions: ext}); err == nil || err.Error() != wantErr {
		t.Errorf("Attributes value changed: verifyUsingTcbInfo() = %v. Want error %v", err, wantErr)
	}
}

func TestVerifyUsingQeIdentityV4(t *testing.T) {
	getter := testcases.TestGetter

	collateral := &Collateral{}
	if err := getQeIdentity(getter, collateral); err != nil {
		t.Fatal(err)
	}
	anyQuote, err := abi.QuoteToProto(testdata.RawQuote)
	if err != nil {
		t.Fatal(err)
	}
	quote, ok := anyQuote.(*pb.QuoteV4)
	if !ok {
		t.Fatal("Quote is not a QuoteV4")
	}

	qeIdentity := collateral.QeIdentity.EnclaveIdentity
	qeReport := quote.GetSignedData().GetCertificationData().GetQeReportCertificationData().GetQeReport()

	if err := verifyQeReport(qeReport, &qeReportOptions{qeIdentity: &qeIdentity}); err != nil {
		t.Error(err)
	}
}

func TestNegativeVerifyUsingQeIdentityV4(t *testing.T) {
	getter := testcases.TestGetter

	collateral := &Collateral{}
	if err := getQeIdentity(getter, collateral); err != nil {
		t.Fatal(err)
	}
	anyQuote, err := abi.QuoteToProto(testdata.RawQuote)
	if err != nil {
		t.Fatal(err)
	}
	quote, ok := anyQuote.(*pb.QuoteV4)
	if !ok {
		t.Fatal("quote is not a QuoteV4")
	}

	qeIdentity := collateral.QeIdentity.EnclaveIdentity
	qeReport := quote.GetSignedData().GetCertificationData().GetQeReportCertificationData().GetQeReport()

	var sampleQeIdentity pcs.QeIdentity

	sampleQeIdentity.EnclaveIdentity = qeIdentity
	sampleQeIdentity.EnclaveIdentity.Miscselect.Bytes = []byte{1, 2, 3, 4}
	wantErr := "MISCSELECT value(67305985) from Intel PCS's reported QE Identity is not equal to MISCSELECTMask value(0)"
	if err := verifyQeReport(qeReport, &qeReportOptions{qeIdentity: &sampleQeIdentity.EnclaveIdentity}); err == nil || err.Error() != wantErr {
		t.Errorf("Miscselect value changed: verifyUsingQeIdentity() = %v. Want error %v", err, wantErr)
	}

	sampleQeIdentity.EnclaveIdentity = qeIdentity
	sampleQeIdentity.EnclaveIdentity.Attributes.Bytes = []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	wantErr = "AttributesMask value([17 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]) is not equal to Attributes value({[1 2 3 4 5 6 7 8 9 10]}) in Intel PCS's reported QE Identity"
	if err := verifyQeReport(qeReport, &qeReportOptions{qeIdentity: &sampleQeIdentity.EnclaveIdentity}); err == nil || err.Error() != wantErr {
		t.Errorf("Attributes value changed: verifyUsingQeIdentity() = %v. Want error %v", err, wantErr)
	}

	sampleQeIdentity.EnclaveIdentity = qeIdentity
	sampleQeIdentity.EnclaveIdentity.Mrsigner.Bytes = []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	wantErr = `MRSIGNER value("dc9e2a7c6f948f17474e34a7fc43ed030f7c1563f1babddf6340c82e0e54a8c5") in QE Report is not equal to MRSIGNER value({"\x01\x02\x03\x04\x05\x06\a\b\t\n"}) in Intel PCS's reported QE Identity`
	if err := verifyQeReport(qeReport, &qeReportOptions{qeIdentity: &sampleQeIdentity.EnclaveIdentity}); err == nil || err.Error() != wantErr {
		t.Errorf("Mrsigner value changed: verifyUsingQeIdentity() = %v. Want error %v", err, wantErr)
	}

	sampleQeIdentity.EnclaveIdentity = qeIdentity
	sampleQeIdentity.EnclaveIdentity.IsvProdID = 5
	wantErr = "ISV PRODID value(2) in QE Report is not equal to ISV PRODID value(5) in Intel PCS's reported QE Identity"
	if err := verifyQeReport(qeReport, &qeReportOptions{qeIdentity: &sampleQeIdentity.EnclaveIdentity}); err == nil || err.Error() != wantErr {
		t.Errorf("IsvProdID value changed: verifyUsingQeIdentity() = %v. Want error %v", err, wantErr)
	}
}

func TestNegativeTcbInfoTcbStatusV4(t *testing.T) {
	getter := testcases.TestGetter

	fmspcBytes := []byte{80, 128, 111, 0, 0, 0}
	fmspc := hex.EncodeToString(fmspcBytes)

	collateral := &Collateral{}
	if err := getTcbInfo(fmspc, getter, collateral); err != nil {
		t.Fatal(err)
	}
	anyQuote, err := abi.QuoteToProto(testdata.RawQuote)
	if err != nil {
		t.Fatal(err)
	}
	quote, ok := anyQuote.(*pb.QuoteV4)
	if !ok {
		t.Fatal("quote is not a QuoteV4")
	}
	chain, err := extractChainFromQuote(quote)
	if err != nil {
		t.Fatal(err)
	}
	ext, err := pcs.PckCertificateExtensions(chain.PCKCertificate)
	if err != nil {
		t.Fatal(err)
	}
	tcbInfo := collateral.TdxTcbInfo.TcbInfo

	setTcbSvnValues(10, 0, &tcbInfo.TcbLevels[0].Tcb.TdxTcbcomponents, &tcbInfo.TcbLevels[0].Tcb.SgxTcbcomponents)
	wantErr := "no matching TCB level found"
	if err := checkTcbInfoTcbStatus(tcbInfo.TcbLevels, quote.GetTdQuoteBody(), ext); err == nil || err.Error() != wantErr {
		t.Errorf("SgxTcbComponents values greater: checkTcbInfoTcbStatus() = %v. Want error %v", err, wantErr)
	}

	setTcbSvnValues(0, 10, &tcbInfo.TcbLevels[0].Tcb.TdxTcbcomponents, &tcbInfo.TcbLevels[0].Tcb.SgxTcbcomponents)
	if err := checkTcbInfoTcbStatus(tcbInfo.TcbLevels, quote.GetTdQuoteBody(), ext); err == nil || err.Error() != wantErr {
		t.Errorf("TdxTcbComponents values greater: checkTcbInfoTcbStatus() = %v. Want error %v", err, wantErr)
	}

	tcbInfo.TcbLevels[0].Tcb.Pcesvn = 20
	setTcbSvnValues(0, 0, &tcbInfo.TcbLevels[0].Tcb.TdxTcbcomponents, &tcbInfo.TcbLevels[0].Tcb.SgxTcbcomponents)
	if err := checkTcbInfoTcbStatus(tcbInfo.TcbLevels, quote.GetTdQuoteBody(), ext); err == nil || err.Error() != wantErr {
		t.Errorf("PCESvn value greater: checkTcbInfoTcbStatus() = %v. Want error %v", err, wantErr)
	}

	tcbInfo.TcbLevels[0].Tcb.Pcesvn = 0
	tcbInfo.TcbLevels[0].TcbStatus = "OutOfDate"
	wantErr = `TCB Status is not "UpToDate", found "OutOfDate"`
	if err := checkTcbInfoTcbStatus(tcbInfo.TcbLevels, quote.GetTdQuoteBody(), ext); err == nil || err.Error() != wantErr {
		t.Errorf("TCB status expired: checkTcbInfoTcbStatus() = %v. Want error %v", err, wantErr)
	}
}

func TestNegativeCheckQeStatusV4(t *testing.T) {
	getter := testcases.TestGetter

	collateral := &Collateral{}
	if err := getQeIdentity(getter, collateral); err != nil {
		t.Fatal(err)
	}
	anyQuote, err := abi.QuoteToProto(testdata.RawQuote)
	if err != nil {
		t.Fatal(err)
	}
	quote, ok := anyQuote.(*pb.QuoteV4)
	if !ok {
		t.Fatal("quote is not a QuoteV4")
	}

	qeIdentity := collateral.QeIdentity.EnclaveIdentity
	qeReport := quote.GetSignedData().GetCertificationData().GetQeReportCertificationData().GetQeReport()

	qeIdentity.TcbLevels[0].Tcb.Isvsvn = 10
	wantErr := "unable to find latest status of TCB, it is now OutOfDate"
	if err := checkQeTcbStatus(qeIdentity.TcbLevels, qeReport.GetIsvSvn()); err == nil || err.Error() != wantErr {
		t.Errorf("No matching TCB level: verifyUsingQeIdentity() = %v. Want error %v", err, wantErr)
	}

	qeIdentity.TcbLevels[0].Tcb.Isvsvn = 0
	qeIdentity.TcbLevels[0].TcbStatus = "OutOfDate"
	wantErr = `TCB Status is not "UpToDate", found "OutOfDate"`
	if err := checkQeTcbStatus(qeIdentity.TcbLevels, qeReport.GetIsvSvn()); err == nil || err.Error() != wantErr {
		t.Errorf("TCB status expired: verifyUsingQeIdentity() = %v. Want error %v", err, wantErr)
	}
}

func TestValidateCRL(t *testing.T) {
	getter := testcases.TestGetter

	quote, err := abi.QuoteToProto(testdata.RawQuote)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := extractChainFromQuote(quote)
	if err != nil {
		t.Fatal(err)
	}
	ca := platformIssuerID
	collateral := &Collateral{}
	if err := getPckCrl(ca, getter, collateral); err != nil {
		t.Fatal(err)
	}
	if err := getQeIdentity(getter, collateral); err != nil {
		t.Fatal(err)
	}
	if err := getRootCrl(getter, collateral); err != nil {
		t.Fatal(err)
	}

	if err := validateCRL(collateral.RootCaCrl, chain.RootCertificate); err != nil {
		t.Error(err)
	}

	if err := validateCRL(collateral.PckCrl, chain.IntermediateCertificate); err != nil {
		t.Error(err)
	}
}

func TestNegativeRawQuoteVerifyWithCollateral(t *testing.T) {
	getter := testcases.TestGetter
	options := &Options{CheckRevocations: true, GetCollateral: true, Getter: getter, Now: currentTime}
	wantErr := "TDX TCB info reported by Intel PCS failed TCB status check: no matching TCB level found"
	// Due to updated SVN values in the sample response, it will result in TCB status failure,
	// when compared to the TD Quote Body's TeeTcbSvn value.
	if err := RawTdxQuote(testdata.RawQuote, options); err == nil || err.Error() != wantErr {
		t.Errorf("No matching TCB: RawTdxQuote() = %v. Want error %v", err, wantErr)
	}
}

func TestNegativeCheckRevocation(t *testing.T) {
	getter := testcases.TestGetter
	options := &Options{CheckRevocations: true, GetCollateral: false, Getter: getter}
	wantErr := "unable to check for certificate revocation as GetCollateral parameter in the options is set to false"
	if err := RawTdxQuote(testdata.RawQuote, options); err == nil || err.Error() != wantErr {
		t.Errorf("Check Revocation Without GetCollateral: RawTdxQuote() = %v. Want error %v", err, wantErr)
	}
}
