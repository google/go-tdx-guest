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

// Package testing defines the mock tdx-guest device
package testing

import (
	labi "github.com/google/go-tdx-guest/client/linuxabi"
	"github.com/google/go-tdx-guest/pcs"
	"github.com/google/go-tdx-guest/testing/testdata"
)

var pckCrlIssuerChain = []string{
	"-----BEGIN%20CERTIFICATE-----%0AMIICljCCAj2gAwIBAgIVAJVvXc29G%2BHpQEnJ1PQzzgFXC95UMAoGCCqGSM49BAMC%0AMGgxGjAYBgNVBAMMEUludGVsIFNHWCBSb290IENBMRowGAYDVQQKDBFJbnRlbCBD%0Ab3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNBMQsw%0ACQYDVQQGEwJVUzAeFw0xODA1MjExMDUwMTBaFw0zMzA1MjExMDUwMTBaMHAxIjAg%0ABgNVBAMMGUludGVsIFNHWCBQQ0sgUGxhdGZvcm0gQ0ExGjAYBgNVBAoMEUludGVs%0AIENvcnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0Ex%0ACzAJBgNVBAYTAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENSB%2F7t21lXSO%0A2Cuzpxw74eJB72EyDGgW5rXCtx2tVTLq6hKk6z%2BUiRZCnqR7psOvgqFeSxlmTlJl%0AeTmi2WYz3qOBuzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBS%0ABgNVHR8ESzBJMEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2Vy%0AdmljZXMuaW50ZWwuY29tL0ludGVsU0dYUm9vdENBLmRlcjAdBgNVHQ4EFgQUlW9d%0Azb0b4elAScnU9DPOAVcL3lQwDgYDVR0PAQH%2FBAQDAgEGMBIGA1UdEwEB%2FwQIMAYB%0AAf8CAQAwCgYIKoZIzj0EAwIDRwAwRAIgXsVki0w%2Bi6VYGW3UF%2F22uaXe0YJDj1Ue%0AnA%2BTjD1ai5cCICYb1SAmD5xkfTVpvo4UoyiSYxrDWLmUR4CI9NKyfPN%2B%0A-----END%20CERTIFICATE-----%0A-----BEGIN%20CERTIFICATE-----%0AMIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw%0AaDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv%0AcnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ%0ABgNVBAYTAlVTMB4XDTE4MDUyMTEwNDUxMFoXDTQ5MTIzMTIzNTk1OVowaDEaMBgG%0AA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0%0AaW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT%0AAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj%2FiPWsCzaEKi7%0A1OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlKOB%0AuzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJ%0AMEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50%0AZWwuY29tL0ludGVsU0dYUm9vdENBLmRlcjAdBgNVHQ4EFgQUImUM1lqdNInzg7SV%0AUr9QGzknBqwwDgYDVR0PAQH%2FBAQDAgEGMBIGA1UdEwEB%2FwQIMAYBAf8CAQEwCgYI%0AKoZIzj0EAwIDSQAwRgIhAOW%2F5QkR%2BS9CiSDcNoowLuPRLsWGf%2FYi7GSX94BgwTwg%0AAiEA4J0lrHoMs%2BXo5o%2FsX6O9QWxHRAvZUGOdRQ7cvqRXaqI%3D%0A-----END%20CERTIFICATE-----%0A"}

var tcbInfoIssuerChain = []string{
	"-----BEGIN%20CERTIFICATE-----%0AMIICizCCAjKgAwIBAgIUfjiC1ftVKUpASY5FhAPpFJG99FUwCgYIKoZIzj0EAwIw%0AaDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv%0AcnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ%0ABgNVBAYTAlVTMB4XDTE4MDUyMTEwNTAxMFoXDTI1MDUyMTEwNTAxMFowbDEeMBwG%0AA1UEAwwVSW50ZWwgU0dYIFRDQiBTaWduaW5nMRowGAYDVQQKDBFJbnRlbCBDb3Jw%0Ab3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNBMQswCQYD%0AVQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABENFG8xzydWRfK92bmGv%0AP%2BmAh91PEyV7Jh6FGJd5ndE9aBH7R3E4A7ubrlh%2FzN3C4xvpoouGlirMba%2BW2lju%0AypajgbUwgbIwHwYDVR0jBBgwFoAUImUM1lqdNInzg7SVUr9QGzknBqwwUgYDVR0f%0ABEswSTBHoEWgQ4ZBaHR0cHM6Ly9jZXJ0aWZpY2F0ZXMudHJ1c3RlZHNlcnZpY2Vz%0ALmludGVsLmNvbS9JbnRlbFNHWFJvb3RDQS5kZXIwHQYDVR0OBBYEFH44gtX7VSlK%0AQEmORYQD6RSRvfRVMA4GA1UdDwEB%2FwQEAwIGwDAMBgNVHRMBAf8EAjAAMAoGCCqG%0ASM49BAMCA0cAMEQCIB9C8wOAN%2FImxDtGACV246KcqjagZOR0kyctyBrsGGJVAiAj%0AftbrNGsGU8YH211dRiYNoPPu19Zp%2Fze8JmhujB0oBw%3D%3D%0A-----END%20CERTIFICATE-----%0A-----BEGIN%20CERTIFICATE-----%0AMIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw%0AaDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv%0AcnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ%0ABgNVBAYTAlVTMB4XDTE4MDUyMTEwNDUxMFoXDTQ5MTIzMTIzNTk1OVowaDEaMBgG%0AA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0%0AaW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT%0AAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj%2FiPWsCzaEKi7%0A1OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlKOB%0AuzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJ%0AMEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50%0AZWwuY29tL0ludGVsU0dYUm9vdENBLmRlcjAdBgNVHQ4EFgQUImUM1lqdNInzg7SV%0AUr9QGzknBqwwDgYDVR0PAQH%2FBAQDAgEGMBIGA1UdEwEB%2FwQIMAYBAf8CAQEwCgYI%0AKoZIzj0EAwIDSQAwRgIhAOW%2F5QkR%2BS9CiSDcNoowLuPRLsWGf%2FYi7GSX94BgwTwg%0AAiEA4J0lrHoMs%2BXo5o%2FsX6O9QWxHRAvZUGOdRQ7cvqRXaqI%3D%0A-----END%20CERTIFICATE-----%0A",
}

var qeIdentityIssuerChain = []string{
	"-----BEGIN%20CERTIFICATE-----%0AMIICizCCAjKgAwIBAgIUfjiC1ftVKUpASY5FhAPpFJG99FUwCgYIKoZIzj0EAwIw%0AaDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv%0AcnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ%0ABgNVBAYTAlVTMB4XDTE4MDUyMTEwNTAxMFoXDTI1MDUyMTEwNTAxMFowbDEeMBwG%0AA1UEAwwVSW50ZWwgU0dYIFRDQiBTaWduaW5nMRowGAYDVQQKDBFJbnRlbCBDb3Jw%0Ab3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNBMQswCQYD%0AVQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABENFG8xzydWRfK92bmGv%0AP%2BmAh91PEyV7Jh6FGJd5ndE9aBH7R3E4A7ubrlh%2FzN3C4xvpoouGlirMba%2BW2lju%0AypajgbUwgbIwHwYDVR0jBBgwFoAUImUM1lqdNInzg7SVUr9QGzknBqwwUgYDVR0f%0ABEswSTBHoEWgQ4ZBaHR0cHM6Ly9jZXJ0aWZpY2F0ZXMudHJ1c3RlZHNlcnZpY2Vz%0ALmludGVsLmNvbS9JbnRlbFNHWFJvb3RDQS5kZXIwHQYDVR0OBBYEFH44gtX7VSlK%0AQEmORYQD6RSRvfRVMA4GA1UdDwEB%2FwQEAwIGwDAMBgNVHRMBAf8EAjAAMAoGCCqG%0ASM49BAMCA0cAMEQCIB9C8wOAN%2FImxDtGACV246KcqjagZOR0kyctyBrsGGJVAiAj%0AftbrNGsGU8YH211dRiYNoPPu19Zp%2Fze8JmhujB0oBw%3D%3D%0A-----END%20CERTIFICATE-----%0A-----BEGIN%20CERTIFICATE-----%0AMIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw%0AaDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv%0AcnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ%0ABgNVBAYTAlVTMB4XDTE4MDUyMTEwNDUxMFoXDTQ5MTIzMTIzNTk1OVowaDEaMBgG%0AA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0%0AaW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT%0AAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj%2FiPWsCzaEKi7%0A1OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlKOB%0AuzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJ%0AMEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50%0AZWwuY29tL0ludGVsU0dYUm9vdENBLmRlcjAdBgNVHQ4EFgQUImUM1lqdNInzg7SV%0AUr9QGzknBqwwDgYDVR0PAQH%2FBAQDAgEGMBIGA1UdEwEB%2FwQIMAYBAf8CAQEwCgYI%0AKoZIzj0EAwIDSQAwRgIhAOW%2F5QkR%2BS9CiSDcNoowLuPRLsWGf%2FYi7GSX94BgwTwg%0AAiEA4J0lrHoMs%2BXo5o%2FsX6O9QWxHRAvZUGOdRQ7cvqRXaqI%3D%0A-----END%20CERTIFICATE-----%0A",
}

// PckCrlHeader is the response header for pck crl
var PckCrlHeader = map[string][]string{
	pcs.SgxPckCrlIssuerChainPhrase: pckCrlIssuerChain,
}

// TcbInfoHeader is the response header for pck crl
var TcbInfoHeader = map[string][]string{
	pcs.TcbInfoIssuerChainPhrase: tcbInfoIssuerChain,
}

// QeIdentityHeader is the response header for pck crl
var QeIdentityHeader = map[string][]string{
	pcs.SgxQeIdentityIssuerChainPhrase: qeIdentityIssuerChain,
}

// TestGetter is a local getter tied to the included sample quote
var TestGetter = &Getter{
	Responses: map[string]HTTPResponse{
		"https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity": {
			Header: QeIdentityHeader,
			Body:   testdata.QeIdentityBody,
		},
		"https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=50806f000000": {
			Header: TcbInfoHeader,
			Body:   testdata.TcbInfoBody,
		},
		"https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=platform&encoding=der": {
			Header: PckCrlHeader,
			Body:   testdata.PckCrlBody,
		},
		"https://certificates.trustedservices.intel.com/IntelSGXRootCA.der": {
			Header: nil,
			Body:   testdata.RootCrlBody,
		},
	},
}

// reportdata  defines a ReportData example that is all zeros except the last byte is 1.
var reportdata = [64]byte{
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 1}

// TestCase represents a get_quote input/output test case.
type TestCase struct {
	Name     string
	Input    [labi.TdReportDataSize]uint8
	Report   [labi.TdReportSize]uint8
	Quote    []uint8
	EsResult labi.EsResult
	WantErr  string
}

// TestCases returns common test cases for get_report.
func TestCases() []TestCase {
	var report [1024]byte
	copy(report[:], testdata.RawReport)
	return []TestCase{
		{
			Name:   "zeros",
			Input:  reportdata,
			Report: report,
			Quote:  testdata.RawQuote,
		},
	}
}

// TcQuoteProvider returns a mock quote provider populated from test cases inputs and expected outputs.
func TcQuoteProvider(tcs []TestCase) (*TdxQuoteProvider, error) {
	rawQuoteResponses := map[[labi.TdReportDataSize]byte][]uint8{}
	for _, tc := range tcs {
		rawQuoteResponses[tc.Input] = tc.Quote
	}
	return &TdxQuoteProvider{
		isSupported:      true,
		rawQuoteResponse: rawQuoteResponses,
	}, nil
}

// TcDevice returns a mock device populated from test cases inputs and expected outputs.
func TcDevice(tcs []TestCase) (*Device, error) {
	reportResponses := map[[labi.TdReportDataSize]byte]any{}
	quoteResponses := map[[labi.TdReportSize]byte]any{}
	for _, tc := range tcs {
		reportResponses[tc.Input] = &GetReportResponse{
			Resp: labi.TdxReportReq{
				TdReport: tc.Report,
			},
			EsResult: tc.EsResult,
		}
		var idQuote [labi.ReqBufSize]byte
		copy(idQuote[:], tc.Quote)
		quoteResponses[tc.Report] = &GetQuoteResponse{
			Resp: labi.TdxQuoteHdr{
				Status: labi.GetQuoteSuccess,
				OutLen: uint32(len(tc.Quote)),
				Data:   idQuote,
			},
			EsResult: tc.EsResult,
		}
	}
	return &Device{
		reportResponse: reportResponses,
		quoteResponse:  quoteResponses,
	}, nil
}
