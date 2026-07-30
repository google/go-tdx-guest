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

package gce

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"

	"github.com/google/go-tdx-guest/abi"
	pb "github.com/google/go-tdx-guest/proto/tdx"
)

// PZIDPayload returns the canonical ASCII JSON payload used to bind GCE project,
// zone, and instance identity into TD quote MR_OWNER.
func PZIDPayload(info *InstanceInfo) (string, error) {
	if info == nil {
		return "", errors.New("instance info is nil")
	}
	if err := validateZone(info.Zone); err != nil {
		return "", fmt.Errorf("instance info %w", err)
	}
	// Zone validation keeps strconv.Quote equivalent to JSON string
	// encoding for the canonical PZID payload.
	return fmt.Sprintf(
		`{"instanceId":%d,"numericalProjectId":%d,"zone":%s}`,
		info.InstanceID,
		info.ProjectNumber,
		strconv.Quote(info.Zone),
	), nil
}

// PZIDDigest returns the SHA-384 digest that the GCE infrastructure writes to
// TD quote MR_OWNER.
func PZIDDigest(info *InstanceInfo) ([]byte, string, error) {
	payload, err := PZIDPayload(info)
	if err != nil {
		return nil, "", err
	}
	digest := sha512.Sum384([]byte(payload))
	return digest[:], payload, nil
}

// MROwnerFromQuote returns the MR_OWNER bytes from a supported TDX quote.
func MROwnerFromQuote(quote any) ([]byte, error) {
	var mrOwner []byte
	switch q := quote.(type) {
	case *pb.QuoteV4:
		if q.GetTdQuoteBody() == nil {
			return nil, errors.New("QuoteV4 TD quote body is nil")
		}
		mrOwner = q.GetTdQuoteBody().GetMrOwner()
	case *pb.QuoteV5:
		if q.GetTdQuoteBodyDescriptor() == nil {
			return nil, errors.New("QuoteV5 TD quote body descriptor is nil")
		}
		if q.GetTdQuoteBodyDescriptor().GetTdQuoteBodyV5() == nil {
			return nil, errors.New("QuoteV5 TD quote body is nil")
		}
		mrOwner = q.GetTdQuoteBodyDescriptor().GetTdQuoteBodyV5().GetMrOwner()
	default:
		return nil, fmt.Errorf("GCE provenance supports QuoteV4 and QuoteV5 only, got %T", quote)
	}
	if len(mrOwner) != abi.MrOwnerSize {
		return nil, fmt.Errorf("MR_OWNER length is %d bytes, want %d", len(mrOwner), abi.MrOwnerSize)
	}
	return mrOwner, nil
}

// PZIDVerification contains the values used while comparing GCE PZID identity
// against TD quote MR_OWNER.
type PZIDVerification struct {
	Payload           string
	ExpectedMROwner   []byte
	AttestedMROwner   []byte
	ExpectedMROwnerHX string
	AttestedMROwnerHX string
}

// VerifyPZID compares the SHA-384 PZID digest with TD quote MR_OWNER.
func VerifyPZID(quote any, info *InstanceInfo) (*PZIDVerification, error) {
	expected, payload, err := PZIDDigest(info)
	if err != nil {
		return nil, err
	}
	actual, err := MROwnerFromQuote(quote)
	if err != nil {
		return nil, err
	}
	result := &PZIDVerification{
		Payload:           payload,
		ExpectedMROwner:   expected,
		AttestedMROwner:   actual,
		ExpectedMROwnerHX: hex.EncodeToString(expected),
		AttestedMROwnerHX: hex.EncodeToString(actual),
	}
	if !bytes.Equal(actual, expected) {
		return result, fmt.Errorf("MR_OWNER does not match PZID digest: got %s, want %s", result.AttestedMROwnerHX, result.ExpectedMROwnerHX)
	}
	return result, nil
}
