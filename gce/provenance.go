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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/google/go-tdx-guest/abi"
	tg "github.com/google/go-tdx-guest/client"
	"github.com/google/go-tdx-guest/pcs"
	pb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/go-tdx-guest/verify"
)

// GCSBaseURL is the base URL for Google Cloud Storage APIs.
const GCSBaseURL = "https://storage.googleapis.com"

var (
	validPPID   = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)
	validBucket = regexp.MustCompile(`^[a-z0-9_.-]{3,63}$`)
)

// PPIDFromQuote extracts the PPID from the PCK certificate embedded in a TDX
// quote.
func PPIDFromQuote(quote any) (string, error) {
	if err := requireSupportedQuote(quote); err != nil {
		return "", err
	}
	chain, err := verify.ExtractChainFromQuote(quote)
	if err != nil {
		return "", fmt.Errorf("could not extract PCK certificate chain from quote: %w", err)
	}
	if chain == nil || chain.PCKCertificate == nil {
		return "", errors.New("PCK certificate is missing in the quote")
	}
	exts, err := pcs.PckCertificateExtensions(chain.PCKCertificate)
	if err != nil {
		return "", fmt.Errorf("could not extract PCK extensions: %w", err)
	}
	if exts.PPID == "" {
		return "", errors.New("PPID is empty in PCK extensions")
	}
	return exts.PPID, nil
}

// ResolveRawQuote returns raw TDX quote bytes and the parsed quote from a raw
// binary quote file or the local quote provider when path is empty.
func ResolveRawQuote(path string, reportData [64]byte) ([]byte, any, error) {
	if path != "" {
		quoteBytes, err := os.ReadFile(path)
		if err != nil {
			return nil, nil, fmt.Errorf("read quote file at %s: %w", path, err)
		}
		quote, err := abi.QuoteToProto(quoteBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("parse quote bytes from %s: %w", path, err)
		}
		if err := requireSupportedQuote(quote); err != nil {
			return nil, nil, err
		}
		return quoteBytes, quote, nil
	}

	qp, err := tg.GetQuoteProvider()
	if err != nil {
		return nil, nil, fmt.Errorf("get quote provider: %w", err)
	}
	if err := qp.IsSupported(); err != nil {
		return nil, nil, fmt.Errorf("TDX quote provider not supported on this platform: %w", err)
	}
	quoteBytes, err := tg.GetRawQuote(qp, reportData)
	if err != nil {
		return nil, nil, fmt.Errorf("fetch local TDX quote: %w", err)
	}
	quote, err := abi.QuoteToProto(quoteBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse local TDX quote: %w", err)
	}
	if err := requireSupportedQuote(quote); err != nil {
		return nil, nil, err
	}
	return quoteBytes, quote, nil
}

func requireSupportedQuote(quote any) error {
	switch quote.(type) {
	case *pb.QuoteV4, *pb.QuoteV5:
		return nil
	default:
		return fmt.Errorf("GCE provenance supports QuoteV4 and QuoteV5 only, got %T", quote)
	}
}

// FetchProvenanceData fetches a provenance JSON object from the configured
// public GCS bucket by PPID.
func FetchProvenanceData(baseURL, ppid, bucket string, debugf func(string, ...any)) ([]byte, error) {
	if !validPPID.MatchString(ppid) {
		return nil, errors.New("invalid PPID format")
	}
	if !validBucket.MatchString(bucket) {
		return nil, errors.New("invalid bucket name format")
	}

	if debugf != nil {
		debugf("Using PPID: %s\n", ppid)
		debugf("Using GCS Bucket: %s\n", bucket)
	}

	url := fmt.Sprintf("%s/%s/%s", baseURL, bucket, ppid)
	if debugf != nil {
		debugf("Fetching from URL: %s\n", url)
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch from GCS: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, ParseGCSError(resp, bodyBytes, ppid, bucket)
	}
	if !json.Valid(bodyBytes) {
		return nil, errors.New("received invalid JSON from GCS")
	}
	return bodyBytes, nil
}

// ParseGCSError converts known GCS XML error bodies into compact CLI errors.
func ParseGCSError(resp *http.Response, bodyBytes []byte, ppid string, bucket string) error {
	bodyStr := string(bodyBytes)
	if strings.Contains(bodyStr, "NoSuchBucket") {
		return fmt.Errorf("gcs request failed: bucket '%s' not found", bucket)
	}
	if strings.Contains(bodyStr, "NoSuchKey") {
		return fmt.Errorf("gcs request failed: file '%s' not found in bucket '%s'", ppid, bucket)
	}
	if resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("gcs request failed: access denied to bucket '%s' (403 Forbidden); the bucket may be private or not exist", bucket)
	}
	return fmt.Errorf("gcs request failed with status: %s", resp.Status)
}
