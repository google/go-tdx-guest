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

// Package validate provides the library functions to validate a TDX quote
package validate

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/google/go-tdx-guest/abi"
	cpb "github.com/google/go-tdx-guest/proto/check"
	pb "github.com/google/go-tdx-guest/proto/tdx"
	"go.uber.org/multierr"
)

var (
	// ErrOptionsNil error returned when options parameter is empty.
	ErrOptionsNil = errors.New("options parameter is empty")
)

// Options represents validation options for a TDX attestation Quote.
type Options struct {
	HeaderOptions HeaderOptions

	TdQuoteBodyOptions TdQuoteBodyOptions
}

// HeaderOptions represents validation options for a TDX attestation Quote Header.
type HeaderOptions struct {
	// MinimumQeSvn is the minimum QE security version number.
	MinimumQeSvn []byte
	// MinimumPceSvn is the minimum PCE security version number.
	MinimumPceSvn []byte
	// QeVendorID is the expected QE_VENDOR_ID field. Must be nil or 16 bytes long. Not checked if nil.
	QeVendorID []byte
}

// TdQuoteBodyOptions represents validation options for a TDX attestation Quote's TD Quote body.
type TdQuoteBodyOptions struct {
	// MinimumTeeTcbSvn is the minimum TEE_TCB security version number.
	MinimumTeeTcbSvn []byte
	// MrSeam is the expected MR_SEAM field. Must be nil or 48 bytes long. Not checked if nil.
	MrSeam []byte
	// TdAttributes is the expected TD_ATTRIBUTES field. Must be nil or 8 bytes long. Not checked if nil.
	TdAttributes []byte
	// Xfam is the expected XFAM field. Must be nil or 8 bytes long. Not checked if nil.
	Xfam []byte
	// MrTd is the expected MR_TD field. Must be nil or 48 bytes long. Not checked if nil.
	MrTd []byte
	// MrConfigID is the expected MR_CONFIG_ID field. Must be nil or 48 bytes long. Not checked if nil.
	MrConfigID []byte
	// MrOwner is the expected MR_OWNER field. Must be nil or 48 bytes long. Not checked if nil.
	MrOwner []byte
	// MrOwnerConfig is the expected MR_OWNER_CONFIG field. Must be nil or 48 bytes long. Not checked if nil.
	MrOwnerConfig []byte
	// RtMr0 is the expected RT_MR0 field. Must be nil or 48 bytes long. Not checked if nil.
	RtMr0 []byte
	// RtMr1 is the expected RT_MR1 field. Must be nil or 48 bytes long. Not checked if nil.
	RtMr1 []byte
	// RtMr2 is the expected RT_MR2 field. Must be nil or 48 bytes long. Not checked if nil.
	RtMr2 []byte
	// RtMr3 is the expected RT_MR3 field. Must be nil or 48 bytes long. Not checked if nil.
	RtMr3 []byte
	// ReportData is the expected REPORT_DATA field. Must be nil or 64 bytes long. Not checked if nil.
	ReportData []byte
}

func lengthCheck(name string, length int, value []byte) error {
	if value != nil && len(value) != length {
		return fmt.Errorf("option %q length is %d. Want %d", name, len(value), length)
	}

	return nil
}

func checkOptionsLengths(opts *Options) error {
	return multierr.Combine(
		lengthCheck("mr_seam", abi.MrSeamSize, opts.TdQuoteBodyOptions.MrSeam),
		lengthCheck("td_attributes", abi.TdAttributesSize, opts.TdQuoteBodyOptions.TdAttributes),
		lengthCheck("Xfam", abi.XfamSize, opts.TdQuoteBodyOptions.Xfam),
		lengthCheck("mr_td", abi.MrTdSize, opts.TdQuoteBodyOptions.MrTd),
		lengthCheck("mr_config_id", abi.MrConfigIDSize, opts.TdQuoteBodyOptions.MrConfigID),
		lengthCheck("mr_owner", abi.MrOwnerSize, opts.TdQuoteBodyOptions.MrOwner),
		lengthCheck("mr_owner_config", abi.MrOwnerConfigSize, opts.TdQuoteBodyOptions.MrOwnerConfig),
		lengthCheck("rt_mr0", abi.RtMr0Size, opts.TdQuoteBodyOptions.RtMr0),
		lengthCheck("rt_mr1", abi.RtMr1Size, opts.TdQuoteBodyOptions.RtMr1),
		lengthCheck("rt_mr2", abi.RtMr2Size, opts.TdQuoteBodyOptions.RtMr2),
		lengthCheck("rt_mr3", abi.RtMr3Size, opts.TdQuoteBodyOptions.RtMr3),
		lengthCheck("report_data", abi.ReportDataSize, opts.TdQuoteBodyOptions.ReportData),
		lengthCheck("qe_vendor_id", abi.QeVendorIDSize, opts.HeaderOptions.QeVendorID),
	)
}

// PolicyToOptions returns an Options object that is represented by a Policy message.
func PolicyToOptions(policy *cpb.Policy) (*Options, error) {

	opts := &Options{

		HeaderOptions: HeaderOptions{
			MinimumQeSvn:  policy.GetHeaderPolicy().GetMinmumQeSvn(),
			MinimumPceSvn: policy.GetHeaderPolicy().GetMinimumPceSvn(),
			QeVendorID:    policy.GetHeaderPolicy().GetQeVendorId(),
		},

		TdQuoteBodyOptions: TdQuoteBodyOptions{
			MinimumTeeTcbSvn: policy.GetTdQuoteBodyPolicy().GetMinimumTeeTcbSvn(),
			MrSeam:           policy.GetTdQuoteBodyPolicy().GetMrSeam(),
			TdAttributes:     policy.GetTdQuoteBodyPolicy().GetTdAttributes(),
			Xfam:             policy.GetTdQuoteBodyPolicy().GetXfam(),
			MrTd:             policy.GetTdQuoteBodyPolicy().GetMrTd(),
			MrConfigID:       policy.GetTdQuoteBodyPolicy().GetMrConfigId(),
			MrOwner:          policy.GetTdQuoteBodyPolicy().GetMrOwner(),
			MrOwnerConfig:    policy.GetTdQuoteBodyPolicy().GetMrOwnerConfig(),
			RtMr0:            policy.GetTdQuoteBodyPolicy().GetRtMr0(),
			RtMr1:            policy.GetTdQuoteBodyPolicy().GetRtMr1(),
			RtMr2:            policy.GetTdQuoteBodyPolicy().GetRtMr2(),
			RtMr3:            policy.GetTdQuoteBodyPolicy().GetRtMr3(),
			ReportData:       policy.GetTdQuoteBodyPolicy().GetReportData(),
		},
	}

	if err := checkOptionsLengths(opts); err != nil {
		return nil, err
	}

	return opts, nil
}

func byteCheck(option, field string, size int, given, required []byte) error {

	if len(required) == 0 {
		return nil
	}

	if len(required) != size {
		return fmt.Errorf("option %v must be nil or %d bytes", option, size)
	}

	if !bytes.Equal(required, given) {
		return fmt.Errorf("Quote field %s is %s. Expect %s",
			field, hex.EncodeToString(given), hex.EncodeToString(required))
	}

	return nil
}

func exactByteMatch(quote *pb.QuoteV4, opts *Options) error {

	return multierr.Combine(
		byteCheck("MrSeam", "MR_SEAM", abi.MrSeamSize, quote.GetTdQuoteBody().GetMrSeam(), opts.TdQuoteBodyOptions.MrSeam),
		byteCheck("TdAttributes", "TD_ATTRIBUTES", abi.TdAttributesSize, quote.GetTdQuoteBody().GetTdAttributes(), opts.TdQuoteBodyOptions.TdAttributes),
		byteCheck("Xfam", "XFAM", abi.XfamSize, quote.GetTdQuoteBody().GetXfam(), opts.TdQuoteBodyOptions.Xfam),
		byteCheck("MrTd", "MR_TD", abi.MrTdSize, quote.GetTdQuoteBody().GetMrTd(), opts.TdQuoteBodyOptions.MrTd),
		byteCheck("MrConfigID", "MR_CONFIG_ID", abi.MrConfigIDSize, quote.GetTdQuoteBody().GetMrConfigId(), opts.TdQuoteBodyOptions.MrConfigID),
		byteCheck("MrOwner", "MR_OWNER", abi.MrOwnerSize, quote.GetTdQuoteBody().GetMrOwner(), opts.TdQuoteBodyOptions.MrOwner),
		byteCheck("MrOwnerConfig", "MR_OWNER_CONFIG", abi.MrOwnerConfigSize, quote.GetTdQuoteBody().GetMrOwnerConfig(), opts.TdQuoteBodyOptions.MrOwnerConfig),
		byteCheck("RtMr0", "RT_MR0", abi.RtMr0Size, quote.GetTdQuoteBody().GetRtMr0(), opts.TdQuoteBodyOptions.RtMr0),
		byteCheck("RtMr1", "RT_MR1", abi.RtMr0Size, quote.GetTdQuoteBody().GetRtMr1(), opts.TdQuoteBodyOptions.RtMr1),
		byteCheck("RtMr2", "RT_MR2", abi.RtMr0Size, quote.GetTdQuoteBody().GetRtMr2(), opts.TdQuoteBodyOptions.RtMr2),
		byteCheck("RtMr3", "RT_MR3", abi.RtMr0Size, quote.GetTdQuoteBody().GetRtMr3(), opts.TdQuoteBodyOptions.RtMr3),
		byteCheck("ReportData", "REPORT_DATA", abi.ReportDataSize, quote.GetTdQuoteBody().GetReportData(), opts.TdQuoteBodyOptions.ReportData),
		byteCheck("QeVendorID", "QE_VENDOR_ID", abi.QeVendorIDSize, quote.GetHeader().GetQeVendorId(), opts.HeaderOptions.QeVendorID),
	)
}

func isSvnHigherOrEqual(quoteSvn []byte, optionSvn []byte) bool {
	if optionSvn == nil {
		return true
	}
	for i := range quoteSvn {
		if quoteSvn[i] < optionSvn[i] {

			return false
		}
	}
	return true
}

func minVersionCheck(quote *pb.QuoteV4, opts *Options) error {

	if !isSvnHigherOrEqual(quote.GetTdQuoteBody().GetTeeTcbSvn(), opts.TdQuoteBodyOptions.MinimumTeeTcbSvn) {
		return fmt.Errorf("Tee Tcb security-version number %d is less than the required minimum %d",
			quote.GetTdQuoteBody().GetTeeTcbSvn(), opts.TdQuoteBodyOptions.MinimumTeeTcbSvn)
	}

	if !isSvnHigherOrEqual(quote.GetHeader().GetQeSvn(), opts.HeaderOptions.MinimumQeSvn) {
		return fmt.Errorf("Qe security-version number %d is less than the required minimum %d",
			quote.GetHeader().GetQeSvn(), opts.HeaderOptions.MinimumQeSvn)
	}

	if !isSvnHigherOrEqual(quote.GetHeader().GetPceSvn(), opts.HeaderOptions.MinimumPceSvn) {
		return fmt.Errorf("PCE security-version number %d is less than the required minimum %d",
			quote.GetHeader().GetPceSvn(), opts.HeaderOptions.MinimumPceSvn)
	}

	return nil
}

// TdxAttestation validates fields of the protobuf representation of an attestation Quote against
// expectations. Does not check the attestation certificates or signature.
func TdxAttestation(quote *pb.QuoteV4, options *Options) error {

	if options == nil {
		return ErrOptionsNil
	}

	if err := abi.CheckQuoteV4(quote); err != nil {
		return fmt.Errorf("QuoteV4 invalid: %v", err)
	}

	return multierr.Combine(
		exactByteMatch(quote, options),
		minVersionCheck(quote, options),
	)

}

// RawTdxQuoteValidate checks the raw bytes representation of an attestation quote.
func RawTdxQuoteValidate(raw []byte, options *Options) error {

	quote, err := abi.QuoteToProto(raw)
	if err != nil {
		return fmt.Errorf("could not convert raw bytes to QuoteV4: %v", err)
	}

	return TdxAttestation(quote, options)
}
