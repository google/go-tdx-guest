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

var ErrFreeBSDUnsupported = errors.New("FreeBSD is unsupported")

// FreeBSDDevice implements the Device interface with Linux ioctls.
type FreeBSDDevice struct{}

// Open is not supported on FreeBSD.
func (*FreeBSDDevice) Open(_ string) error {
	return ErrFreeBSDUnsupported
}

// OpenDevice fails on FreeBSD.
func OpenDevice() (*FreeBSDDevice, error) {
	return nil, ErrFreeBSDUnsupported
}

// Close is not supported on FreeBSD.
func (*FreeBSDDevice) Close() error {
	return ErrFreeBSDUnsupported
}

// Ioctl is not supported on FreeBSD.
func (*FreeBSDDevice) Ioctl(_ uintptr, _ any) (uintptr, error) {
	return 0, ErrFreeBSDUnsupported
}

// FreeBSDConfigFsQuoteProvider implements the QuoteProvider interface to fetch attestation quote via ConfigFS.
type FreeBSDConfigFsQuoteProvider struct{}

// IsSupported is not supported on FreeBSD.
func (p *FreeBSDConfigFsQuoteProvider) IsSupported() error {
	return ErrFreeBSDUnsupported
}

// GetRawQuote is not supported on FreeBSD.
func (p *FreeBSDConfigFsQuoteProvider) GetRawQuote(reportData [64]byte) ([]uint8, error) {
	return nil, ErrFreeBSDUnsupported
}

// GetQuoteProvider is not supported on FreeBSD.
func GetQuoteProvider() (*FreeBSDConfigFsQuoteProvider, error) {
	return nil, ErrFreeBSDUnsupported
}
