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

// Package dice provides the library functions to verify a DICE-based TDX quote.
package dice

import (
	"crypto/x509"
	_ "embed"
	"encoding/pem"
)

var (
	// Embedded certificate used when trusted root is nil for DICE quotes.
	// Source: https://tsci.intel.com/content/DICE/RootCA/DCP_DICE_Global_Root_CA.cer
	//go:embed trusted_dice_root.pem
	defaultDiceRootCertByte []byte

	trustedDiceRootCertificate *x509.Certificate
)

// Parse root certificate from the embedded trusted_dice_root certificate file.
func init() {
	diceRoot, _ := pem.Decode(defaultDiceRootCertByte)
	if diceRoot != nil {
		trustedDiceRootCertificate, _ = x509.ParseCertificate(diceRoot.Bytes)
	}
}
