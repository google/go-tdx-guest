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
package client

import (
	"bytes"
	"fmt"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-tdx-guest/abi"
	test "github.com/google/go-tdx-guest/testing"
	"google.golang.org/protobuf/testing/protocmp"
)

var devMu sync.Once
var device Device
var quoteProvider QuoteProvider
var tests []test.TestCase

const defaultTDXDevicePath = "/dev/tdx-guest"

func initialize() {
	for _, tc := range test.TestCases() {
		// Don't test faked errors when running real hardware tests.
		if !UseDefaultTdxGuestDevice() && tc.WantErr != "" {
			continue
		}
		tests = append(tests, tc)
	}
	tdxTestQuoteProvider, err := test.TcQuoteProvider(tests)
	if err != nil {
		panic(fmt.Sprintf("failed to create test quote provider: %v", err))
	}
	quoteProvider = tdxTestQuoteProvider
	// Choose a mock device or a real device depending on the --tdx_guest_device_path flag.
	if UseDefaultTdxGuestDevice() {
		tdxTestDevice, err := test.TcDevice(tests)
		if err != nil {
			panic(fmt.Sprintf("failed to create test device: %v", err))
		}
		if err := tdxTestDevice.Open(defaultTDXDevicePath); err != nil {
			panic(err)
		}
		device = tdxTestDevice
		return
	}
	client, err := OpenDevice()
	if err != nil {
		panic(err)
	}
	device = client
}
func TestGetReport(t *testing.T) {
	devMu.Do(initialize)
	for _, tc := range test.TestCases() {
		t.Run(tc.Name, func(t *testing.T) {
			got, err := getReport(device, tc.Input)
			if err != nil {
				t.Errorf("failed to get the report: %v", err)
			}
			if tc.WantErr == "" {
				want := tc.Report
				if !bytes.Equal(got[:], want[:]) {
					t.Errorf("Got %v want %v", got, want)
				}
			}
		})
	}
}
func TestGetRawQuote(t *testing.T) {
	devMu.Do(initialize)
	for _, tc := range test.TestCases() {
		t.Run(tc.Name, func(t *testing.T) {
			got, err := GetRawQuote(device, tc.Input)
			if !test.Match(err, tc.WantErr) {
				t.Fatalf("GetRawQuote(device, %v) = %v, %v. Want err: %q", tc.Input, got, err, tc.WantErr)
			}
			if tc.WantErr == "" {
				want := tc.Quote
				if !bytes.Equal(got, want) {
					t.Errorf("GetRawQuote(device, %v) = %v want %v", tc.Input, got, want)
				}
			}
		})
	}
}
func TestGetQuote(t *testing.T) {
	devMu.Do(initialize)
	for _, tc := range test.TestCases() {
		t.Run(tc.Name, func(t *testing.T) {
			got, err := GetQuote(device, tc.Input)
			if !test.Match(err, tc.WantErr) {
				t.Fatalf("Expected %v got err: %v", err, tc.WantErr)
			}
			if tc.WantErr == "" {
				quote, err := abi.QuoteToProto(tc.Quote)
				if err != nil {
					t.Error(err)
				}
				if diff := cmp.Diff(got, quote, protocmp.Transform()); diff != "" {
					t.Errorf("Difference in quote: %s", diff)
				}
			}
		})
	}
}
func TestGetRawQuoteViaProvider(t *testing.T) {
	devMu.Do(initialize)
	for _, tc := range test.TestCases() {
		t.Run(tc.Name, func(t *testing.T) {
			got, err := GetRawQuote(quoteProvider, tc.Input)
			if !test.Match(err, tc.WantErr) {
				t.Fatalf("GetRawQuoteViaProvider(quoteProvider, %v) = %v, %v. Want err: %q", tc.Input, got, err, tc.WantErr)
			}
			if tc.WantErr == "" {
				want := tc.Quote
				if !bytes.Equal(got, want) {
					t.Errorf("GetRawQuoteViaProvider(quoteProvider, %v) = %v want %v", tc.Input, got, want)
				}
			}
		})
	}
}
func TestGetQuoteViaProvider(t *testing.T) {
	devMu.Do(initialize)
	for _, tc := range test.TestCases() {
		t.Run(tc.Name, func(t *testing.T) {
			got, err := GetQuote(quoteProvider, tc.Input)
			if !test.Match(err, tc.WantErr) {
				t.Fatalf("Expected %v got err: %v", err, tc.WantErr)
			}
			if tc.WantErr == "" {
				quote, err := abi.QuoteToProto(tc.Quote)
				if err != nil {
					t.Error(err)
				}
				if diff := cmp.Diff(got, quote, protocmp.Transform()); diff != "" {
					t.Errorf("Difference in quote: %s", diff)
				}
			}
		})
	}
}
