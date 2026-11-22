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

//go:build !linux

// Package client provides an interface to the Intel TDX guest device commands.
package client

import (
	"fmt"
)

// unsupportedOsDevice implements the Device interface with Linux ioctls.
type unsupportedOsDevice struct{}

// Open is not supported on non-linux.
func (*unsupportedOsDevice) Open(_ string) error {
	return fmt.Errorf("not unsupported")
}

// OpenDevice fails on non-linux.
func OpenDevice() (*unsupportedOsDevice, error) {
	return nil, fmt.Errorf("not unsupported")
}

// Close is not supported on non-linux.
func (*unsupportedOsDevice) Close() error {
	return fmt.Errorf("not unsupported")
}

// Ioctl is not supported on non-linux.
func (*unsupportedOsDevice) Ioctl(_ uintptr, _ any) (uintptr, error) {
	return 0, fmt.Errorf("not unsupported")
}

// unsupporterConfigFsQuoteProvider implements the QuoteProvider interface to fetch attestation quote via ConfigFS.
type unsupporterConfigFsQuoteProvider struct{}

// IsSupported is not supported on non-linux.
func (p *unsupporterConfigFsQuoteProvider) IsSupported() error {
	return fmt.Errorf("not unsupported")
}

// GetRawQuote is not supported on non-linux.
func (p *unsupporterConfigFsQuoteProvider) GetRawQuote(reportData [64]byte) ([]uint8, error) {
	return nil, fmt.Errorf("not unsupported")
}

// GetQuoteProvider is not supported on non-linux.
func GetQuoteProvider() (*unsupporterConfigFsQuoteProvider, error) {
	return nil, fmt.Errorf("not unsupported")
}
