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

package rtmr

import (
	"os"
	"testing"

	"github.com/google/go-tdx-guest/abi"
)

func TestReplayCcelWithTdQuote(t *testing.T) {
	ccelBytes, err := os.ReadFile("../testing/testdata/ccel/ccel_data.dat")
	if err != nil {
		t.Fatal(err)
	}
	tableBytes, err := os.ReadFile("../testing/testdata/ccel/ccel_table.dat")
	if err != nil {
		t.Fatal(err)
	}
	quoteBytes, err := os.ReadFile("../testing/testdata/ccel/cos-113-tdx-quote.dat")
	if err != nil {
		t.Fatal(err)
	}
	nonceBytes, err := os.ReadFile("../testing/testdata/ccel/nonce.dat")
	if err != nil {
		t.Fatal(err)
	}
	option := TdxDefaultOpts(nonceBytes)
	quote, err := abi.QuoteToProto(quoteBytes)
	if err != nil {
		t.Fatal(err)
	}
	ccel, err := ParseCcelWithTdQuote(ccelBytes, tableBytes, quote, &option)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(ccel)
}
