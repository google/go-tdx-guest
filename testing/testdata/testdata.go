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

// Package testdata defines sample responses of the collaterals
package testdata

import (
	_ "embed"
)

// RawQuote contains raw bytes of quote. To be used only for testing
//
//go:embed "tdx_prod_quote_SPR_E4.dat"
var RawQuote []byte

// RawReport contains raw bytes of report. To be used only for testing
//
//go:embed "report.dat"
var RawReport []byte

// PckCrlBody contains sample PCK CRL. To be used only for testing
//
//go:embed "pckcrl"
var PckCrlBody []byte

// RootCrlBody contains sample Root CA CRL. To be used only for testing
//
//go:embed "rootcrl.der"
var RootCrlBody []byte

// TcbInfoBody contains sample TCBInfo response. To be used only for testing
//
//go:embed "sample_tcbInfo_response"
var TcbInfoBody []byte

// QeIdentityBody  contains sample QeIdentity response. To be used only for testing
//
//go:embed "sample_qeIdentity_response"
var QeIdentityBody []byte
