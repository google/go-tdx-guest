// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.

// Package rtmr provides the library functions:
// 1. extend and read TDX rtmr registers and their tcg maps.
// 2. replay the event log with the TDX quote.
package rtmr

import (
	"fmt"

	"github.com/google/go-eventlog/ccel"
	"github.com/google/go-eventlog/extract"
	"github.com/google/go-eventlog/proto/state"
	"github.com/google/go-eventlog/register"
	"github.com/google/go-tdx-guest/abi"
	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/go-tdx-guest/validate"
	"github.com/google/go-tdx-guest/verify"
)

// ParseTdxCcelOpts allows for customizing the functionality of VerifyAttestation's TDX verification.
type ParseTdxCcelOpts struct {
	Validation   *validate.Options
	Verification *verify.Options
	ExtractOpt   *extract.Opts
}

func getRtmrsFromTdQuoteV4(quote *tdxpb.QuoteV4) (*register.RTMRBank, error) {
	bank := register.RTMRBank{}
	rtmrs := quote.TdQuoteBody.Rtmrs
	for index, rtmr := range rtmrs {
		bank.RTMRs = append(bank.RTMRs, register.RTMR{
			Index:  int(index),
			Digest: rtmr,
		})
		// Tdx Quote V4 has a maximum of 4 RTMRs
		if index > 3 {
			return nil, fmt.Errorf("too many RTMRs in quote")
		}
	}
	return &bank, nil
}

// GetRtmrsFromTdQuote extracts the RTMRs from a TDX attestation quote.
// It is the caller's responsibility to verify the quote before calling this function.
func GetRtmrsFromTdQuote(quote interface{}) (*register.RTMRBank, error) {
	switch q := quote.(type) {
	case *tdxpb.QuoteV4:
		rtmrs, err := getRtmrsFromTdQuoteV4(q)
		if err != nil {
			return nil, err
		}
		return rtmrs, nil
	default:
		return nil, fmt.Errorf("unsupported quote type: %T", quote)
	}
}

// TdxDefaultOpts returns a default validation policy and verification options for TDX
// attestation quote on GCE.
func TdxDefaultOpts(tdxNonce []byte) ParseTdxCcelOpts {
	policy := &validate.Options{HeaderOptions: validate.HeaderOptions{},
		TdQuoteBodyOptions: validate.TdQuoteBodyOptions{}}
	policy.TdQuoteBodyOptions.ReportData = make([]byte, abi.ReportDataSize)
	copy(policy.TdQuoteBodyOptions.ReportData, tdxNonce)
	return ParseTdxCcelOpts{
		Validation:   policy,
		Verification: verify.DefaultOptions(),
		ExtractOpt:   &extract.Opts{Loader: extract.GRUB},
	}
}

// ParseCcelWithTdQuote verify the TD quote, parses the CCEL, and replays the
// events against the RTMR values from the TD quote..
// It returns the corresponding FirmwareLogState containing the events verified
// by particular RTMR indexes/digests.
// It returns an error on failing to replay the events against the RTMR bank or
// on failing to parse malformed events.
func ParseCcelWithTdQuote(ccelBytes []byte, tableBytes []byte, tdxAttestationQuote any, opts *ParseTdxCcelOpts) (*state.FirmwareLogState, error) {
	// Check that the quote contains valid signature and certificates.
	if err := verify.TdxQuote(tdxAttestationQuote, opts.Verification); err != nil {
		return nil, err
	}
	// Check that the fields of the quote are acceptable.
	if err := validate.TdxQuote(tdxAttestationQuote, opts.Validation); err != nil {
		return nil, err
	}
	// Read the RTMRs from the quote.
	rtmrBank, err := GetRtmrsFromTdQuote(tdxAttestationQuote)
	if err != nil {
		return nil, err
	}
	// Parse the event log and replay the event log with the RTMR values.
	return ccel.ReplayAndExtract(tableBytes, ccelBytes, *rtmrBank, *opts.ExtractOpt)
}
