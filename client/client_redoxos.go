// Copyright 2026 Google LLC
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
	"errors"
)

var ErrRedoxOSUnsupported = errors.New("RedoxOS is unsupported")

// RedoxOSDevice implements the Device interface with Linux ioctls.
type RedoxOSDevice struct{}

// Open is not supported on RedoxOS.
func (*RedoxOSDevice) Open(_ string) error {
	return ErrRedoxOSUnsupported
}

// OpenDevice fails on RedoxOS.
func OpenDevice() (*RedoxOSDevice, error) {
	return nil, ErrRedoxOSUnsupported
}

// Close is not supported on RedoxOS.
func (*RedoxOSDevice) Close() error {
	return ErrRedoxOSUnsupported
}

// Ioctl is not supported on RedoxOS.
func (*RedoxOSDevice) Ioctl(_ uintptr, _ any) (uintptr, error) {
	return 0, ErrRedoxOSUnsupported
}

// RedoxOSConfigFsQuoteProvider implements the QuoteProvider interface to fetch attestation quote via ConfigFS.
type RedoxOSConfigFsQuoteProvider struct{}

// IsSupported is not supported on RedoxOS.
func (p *RedoxOSConfigFsQuoteProvider) IsSupported() error {
	return ErrRedoxOSUnsupported
}

// GetRawQuote is not supported on RedoxOS.
func (p *RedoxOSConfigFsQuoteProvider) GetRawQuote(reportData [64]byte) ([]uint8, error) {
	return nil, ErrRedoxOSUnsupported
}

// GetQuoteProvider is not supported on RedoxOS.
func GetQuoteProvider() (*RedoxOSConfigFsQuoteProvider, error) {
	return nil, ErrRedoxOSUnsupported
}
