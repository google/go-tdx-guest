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
	"fmt"
	"strings"

	labi "github.com/google/go-tdx-guest/client/linuxabi"
)

// GetReportResponse represents a mocked response to a command request.
type GetReportResponse struct {
	Resp     labi.TdxReportReq
	EsResult labi.EsResult
}

// GetQuoteResponse represents a mocked response to a command request.
type GetQuoteResponse struct {
	Resp     labi.TdxQuoteHdr
	EsResult labi.EsResult
}

// Device represents a fake tdx-guest device with pre-programmed responses.
type Device struct {
	isOpen         bool
	reportResponse map[[labi.TdReportDataSize]byte]any
	quoteResponse  map[[labi.TdReportSize]byte]any
}

// Match returns true if both errors match expectations closely enough
func Match(got error, want string) bool {
	if got == nil {
		return want == ""
	}
	return strings.Contains(got.Error(), want)
}

// Open changes the mock device's state to open.
func (d *Device) Open(_ string) error {
	if d.isOpen {
		return fmt.Errorf("device is already open")
	}
	d.isOpen = true
	return nil
}

// Close changes the mock device's state to close.
func (d *Device) Close() error {
	if !d.isOpen {
		return fmt.Errorf("device is already closed")
	}
	d.isOpen = false
	return nil
}

func (d *Device) getReport(req *labi.TdxReportReq) (uintptr, error) {
	tdReportRespI, ok := d.reportResponse[req.ReportData]
	if !ok {
		return 0, fmt.Errorf("test error: no response for %v", req.ReportData)
	}
	tdReportResp, ok := tdReportRespI.(*GetReportResponse)
	if !ok {
		return 0, fmt.Errorf("test error: incorrect response for %v", tdReportRespI)
	}
	esResult := uintptr(tdReportResp.EsResult)
	req.TdReport = tdReportResp.Resp.TdReport
	return esResult, nil
}

func (d *Device) getQuote(req *labi.TdxQuoteHdr) (uintptr, error) {
	var report [labi.TdReportSize]byte
	copy(report[:], req.Data[:])
	quoteRespI, ok := d.quoteResponse[report]
	if !ok {
		return 0, fmt.Errorf("test error: no response for %v", report)
	}

	quoteResp, ok := quoteRespI.(*GetQuoteResponse)
	if !ok {
		return 0, fmt.Errorf("test error: incorrect response for %v", quoteRespI)
	}
	esResult := uintptr(quoteResp.EsResult)
	copy(req.Data[:], quoteResp.Resp.Data[:])
	req.OutLen = quoteResp.Resp.OutLen
	return esResult, nil
}

// Ioctl mocks commands with pre-specified responses for a finite number of requests.
func (d *Device) Ioctl(command uintptr, req any) (uintptr, error) {
	switch sreq := req.(type) {
	case *labi.TdxQuoteReq:
		switch command {
		case labi.IocTdxGetQuote:
			return d.getQuote(sreq.Buffer.(*labi.TdxQuoteHdr))
		default:
			return 0, fmt.Errorf("unexpected request value: %v", req)
		}
	case *labi.TdxReportReq:
		switch command {
		case labi.IocTdxGetReport:
			return d.getReport(sreq)
		default:
			return 0, fmt.Errorf("unexpected request value: %v", req)
		}
	}
	return 0, fmt.Errorf("unexpected request value: %v", req)
}

// HTTPResponse represents structure for containing header and body
type HTTPResponse struct {
	Header map[string][]string
	Body   []byte
}

// Getter represents a static server for request/respond url -> body contents.
type Getter struct {
	Responses map[string]HTTPResponse
}

// Get returns a registered response for a given URL.
func (g *Getter) Get(url string) (map[string][]string, []byte, error) {
	v, ok := g.Responses[url]
	if !ok {
		return nil, nil, fmt.Errorf("404: %s", url)
	}
	return v.Header, v.Body, nil
}
