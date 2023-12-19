// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package client provides the library functions to get a TDX quote
// from the TDX guest device
package client

import (
	"flag"
	"fmt"

	"github.com/google/go-tdx-guest/abi"
	labi "github.com/google/go-tdx-guest/client/linuxabi"
	pb "github.com/google/go-tdx-guest/proto/tdx"
)

var tdxGuestPath = flag.String("tdx_guest_device_path", "default",
	"Path to TDX guest device. If \"default\", uses platform default or a fake if testing.")

// Device encapsulates the possible commands to the TDX guest device.
type Device interface {
	Open(path string) error
	Close() error
	Ioctl(command uintptr, argument any) (uintptr, error)
}

// QuoteProvider encapsulates calls to attestation quote.
type QuoteProvider interface {
	IsSupported() error
	GetRawQuote(reportData [64]byte) ([]uint8, error)
}

// UseDefaultTdxGuestDevice returns true if tdxGuestPath=default.
func UseDefaultTdxGuestDevice() bool {
	return *tdxGuestPath == "default"
}

// getReport requests for tdx report by making an ioctl call.
func getReport(d Device, reportData [64]byte) ([]uint8, error) {
	tdxReportReq := labi.TdxReportReq{}
	copy(tdxReportReq.ReportData[:], reportData[:])
	result, err := d.Ioctl(labi.IocTdxGetReport, &tdxReportReq)
	if err != nil {
		return nil, err
	}
	if result != uintptr(labi.TdxAttestSuccess) {
		return nil, fmt.Errorf("unable to get the report: %d", result)
	}
	return tdxReportReq.TdReport[:], nil
}

// GetRawQuote call getReport for report and convert it to quote using an ioctl call.
func GetRawQuote(d Device, reportData [64]byte) ([]uint8, uint32, error) {
	tdReport, err := getReport(d, reportData)
	if err != nil {
		return nil, 0, err
	}
	tdxHdr := &labi.TdxQuoteHdr{
		Status:  0,
		Version: 1,
		InLen:   labi.TdReportSize,
		OutLen:  0,
	}
	copy(tdxHdr.Data[:], tdReport[:labi.TdReportSize])
	tdxReq := labi.TdxQuoteReq{
		Buffer: tdxHdr,
		Length: labi.ReqBufSize,
	}
	result, err := d.Ioctl(labi.IocTdxGetQuote, &tdxReq)
	if err != nil {
		return nil, 0, err
	}
	if result != uintptr(labi.TdxAttestSuccess) {
		return nil, 0, fmt.Errorf("unable to get the quote")
	}
	if tdxHdr.Status != 0 {
		if labi.GetQuoteInFlight == tdxHdr.Status {
			return nil, 0, fmt.Errorf("the device driver return busy")
		} else if labi.GetQuoteServiceUnavailable == tdxHdr.Status {
			return nil, 0, fmt.Errorf("request feature is not supported")
		} else if tdxHdr.OutLen == 0 || tdxHdr.OutLen > labi.ReqBufSize {
			return nil, 0, fmt.Errorf("invalid Quote size: %v. It must be > 0 and <= : %v", tdxHdr.OutLen, labi.ReqBufSize)
		}

		return nil, 0, fmt.Errorf("unexpected error: %v", tdxHdr.Status)
	}

	return tdxHdr.Data[:tdxHdr.OutLen], tdxHdr.OutLen, nil
}

// GetQuote call GetRawQuote to get the quote in byte array and convert it into proto.
func GetQuote(d Device, reportData [64]byte) (*pb.QuoteV4, error) {
	quotebytes, size, err := GetRawQuote(d, reportData)
	if err != nil {
		return nil, err
	}
	if len(quotebytes) > int(size) {
		quotebytes = quotebytes[:size]
	}
	return convertRawQuoteToProto(quotebytes)
}

// GetRawQuoteViaProvider use QuoteProvider to fetch quote in byte array format.
func GetRawQuoteViaProvider(qp QuoteProvider, reportData [64]byte) ([]uint8, error) {
	if err := qp.IsSupported(); err == nil {
		return qp.GetRawQuote(reportData)
	}
	return fallbackToDeviceForRawQuote(reportData)
}

// GetQuoteViaProvider use QuoteProvider to fetch attestation quote.
func GetQuoteViaProvider(qp QuoteProvider, reportData [64]byte) (*pb.QuoteV4, error) {
	bytes, err := GetRawQuoteViaProvider(qp, reportData)
	if err != nil {
		return nil, err
	}
	return convertRawQuoteToProto(bytes)
}

// convertRawQuoteToProto converts raw quote in byte array format to proto.
func convertRawQuoteToProto(rawQuote []byte) (*pb.QuoteV4, error) {
	quote, err := abi.QuoteToProto(rawQuote)
	if err != nil {
		return nil, err
	}
	return quote, nil
}

// fallbackToDeviceForRawQuote opens tdx_guest device to fetch raw quote.
func fallbackToDeviceForRawQuote(reportData [64]byte) ([]uint8, error) {
	// Fall back to TDX device driver.
	device, err := OpenDevice()
	if err != nil {
		return nil, fmt.Errorf("neither tdx device, nor configFs is available to fetch attestation quote")
	}
	bytes, _, err := GetRawQuote(device, reportData)
	device.Close()
	return bytes, err
}
