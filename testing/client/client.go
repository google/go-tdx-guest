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

// Package client (in testing) allows tests to get a fake or real tdx-guest device.
package client

import (
	"testing"

	"github.com/google/go-tdx-guest/client"
	test "github.com/google/go-tdx-guest/testing"
)

// GetTdxGuest is a testing helper function that retrieves the
// appropriate TDX-guest device from the flags passed into "go test".
//
// If using a test guest device, this will also produce a fake Device.
func GetTdxGuest(tcs []test.TestCase, tb testing.TB) client.Device {
	tb.Helper()
	if client.UseDefaultTdxGuestDevice() {
		tdxTestDevice, err := test.TcDevice(tcs)
		if err != nil {
			tb.Fatalf("failed to create test device: %v", err)
		}
		return tdxTestDevice
	}
	client, err := client.OpenDevice()
	if err != nil {
		tb.Fatalf("Failed to open TDX guest device: %v", err)
	}
	return client
}

// GetMockTdxQuoteProvider is a testing helper function that produces a fake TDX quote provider.
func GetMockTdxQuoteProvider(tcs []test.TestCase, tb testing.TB) client.QuoteProvider {
	tb.Helper()
	tdxTestQuoteProvider, err := test.TcQuoteProvider(tcs)
	if err != nil {
		tb.Fatalf("Failed to create test quote provider: %v", err)
	}
	return tdxTestQuoteProvider
}
