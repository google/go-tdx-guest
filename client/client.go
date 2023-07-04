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
	"bytes"
	"encoding/binary"
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

// UseDefaultTdxGuestDevice returns true if tdxGuestPath=default.
func UseDefaultTdxGuestDevice() bool {
	return *tdxGuestPath == "default"
}

// getReport requests for tdx report by making an ioctl call.
func getReport(d Device, reportData [64]byte) ([]uint8, error) {
	tdxReportData := labi.TdxReportDataABI{
		Data: reportData,
	}
	var tdxReport labi.TdxReportABI
	tdxReportReq := labi.TdxReportReq{
		ReportData: tdxReportData.Data,
		TdReport:   tdxReport.Data,
	}
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
	tdxReport := labi.TdxReportABI{
		Data: [labi.TdReportSize]uint8{},
	}
	tdReport, err := getReport(d, reportData)
	if err != nil {
		return nil, 0, err
	}
	copy(tdxReport.Data[:labi.TdReportSize], tdReport[:labi.TdReportSize])
	//get serialized quote request.
	msgSize := uint32(labi.GetQuotesReqSize + labi.TdReportSize)
	req := labi.SerializedGetQuoteReq{
		Header: labi.MsgHeader{
			MajorVersion: labi.MsgLibMajorVer,
			MinorVersion: labi.MsgLibMinorVer,
			MsgType:      labi.GetQuoteReq,
			Size:         msgSize,
			ErrorCode:    0,
		},
		IDListSize:   0,
		ReportSize:   labi.TdReportSize,
		ReportIDList: tdxReport.Data,
	}
	reportIDSize := new(bytes.Buffer)
	err = binary.Write(reportIDSize, binary.LittleEndian, msgSize)
	if err != nil {
		return nil, 0, err
	}
	reportID := new(bytes.Buffer)
	err = binary.Write(reportID, binary.LittleEndian, req)
	if err != nil {
		return nil, 0, err
	}
	data := append(reportIDSize.Bytes(), reportID.Bytes()...)
	tdxHdr := &labi.TdxQuoteHdr{
		Status:  0,
		Version: 1,
		InLen:   labi.HeaderSize + msgSize,
		OutLen:  0,
	}
	copy(tdxHdr.Data[:], data[0:])
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
	if tdxHdr.Status != 0 || tdxHdr.OutLen <= labi.HeaderSize {
		if labi.GetQuoteInFlight == tdxHdr.Status {
			return nil, 0, fmt.Errorf("the device driver return busy")
		} else if labi.GetQuoteServiceUnavailable == tdxHdr.Status {
			return nil, 0, fmt.Errorf("request feature is not supported")
		} else {
			return nil, 0, fmt.Errorf("unexpected error")
		}
	}
	inMsgSize := binary.LittleEndian.Uint32(tdxHdr.Data[0:])
	if inMsgSize != tdxHdr.OutLen-labi.HeaderSize {
		return nil, 0, fmt.Errorf("unexpected error")
	}
	// sanity check, the size shouldn't smaller than SerializedGetQuoteReq
	if inMsgSize < labi.GetQuoteRespSize {
		return nil, 0, fmt.Errorf("unexpected error")
	}
	resp := labi.SerializedGetQuoteResp{}
	buff := bytes.NewReader(tdxHdr.Data[4:])
	err = binary.Read(buff, binary.LittleEndian, &resp)
	if err != nil {
		return nil, 0, err
	}
	// Only major version is checked, minor change is deemed as compatible.
	if resp.Header.MajorVersion != labi.MsgLibMajorVer {
		return nil, 0, fmt.Errorf("unrecognized version of serialized data")
	}
	if resp.Header.MsgType != labi.GetQuoteResp {
		return nil, 0, fmt.Errorf("invalid message type found")
	}
	if resp.Header.Size != inMsgSize {
		return nil, 0, fmt.Errorf("invalid message size found")
	}
	if resp.Header.ErrorCode == labi.TdxAttestSuccess {
		return resp.IDQuote[:resp.QuoteSize], resp.QuoteSize, nil
	}
	return []uint8{}, 0, nil
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
	quote, err := abi.QuoteToProto(quotebytes)
	if err != nil {
		return nil, err
	}
	return quote, nil
}
