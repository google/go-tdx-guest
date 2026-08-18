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
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-tdx-guest/abi"
	tg "github.com/google/go-tdx-guest/client"
	pb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/go-tdx-guest/testing/testdata"
)

type fakeQuoteProvider struct {
	raw            []byte
	reportData     [64]byte
	supportedErr   error
	getRawQuoteRan bool
}

func (p *fakeQuoteProvider) IsSupported() error { return p.supportedErr }

func (p *fakeQuoteProvider) GetRawQuote(reportData [64]byte) ([]byte, error) {
	p.reportData = reportData
	p.getRawQuoteRan = true
	return p.raw, nil
}

func TestFetchProvenanceData(t *testing.T) {
	const (
		ppid   = "abcdef1234567890abcdef1234567890"
		bucket = "test-bucket"
		body   = `{"location":"us-east1"}`
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wantPath := fmt.Sprintf("/%s/%s", bucket, ppid)
		if r.URL.Path != wantPath {
			t.Errorf("request path = %q, want %q", r.URL.Path, wantPath)
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, body)
	}))
	defer server.Close()

	got, err := FetchProvenanceData(server.URL, ppid, bucket, nil)
	if err != nil {
		t.Fatalf("FetchProvenanceData() failed: %v", err)
	}
	if string(got) != body {
		t.Errorf("FetchProvenanceData() = %s, want %s", got, body)
	}
}

func TestFetchProvenanceDataRejectsInvalidInputs(t *testing.T) {
	testCases := []struct {
		name   string
		ppid   string
		bucket string
	}{
		{
			name:   "Invalid PPID",
			ppid:   "not-a-ppid",
			bucket: "test-bucket",
		},
		{
			name:   "Invalid bucket",
			ppid:   "abcdef1234567890abcdef1234567890",
			bucket: "Invalid_Bucket",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := FetchProvenanceData("https://example.test", tc.ppid, tc.bucket, nil); err == nil {
				t.Fatal("FetchProvenanceData() succeeded, want error")
			}
		})
	}
}

func TestFetchProvenanceDataRejectsInvalidJSON(t *testing.T) {
	const (
		ppid   = "abcdef1234567890abcdef1234567890"
		bucket = "test-bucket"
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "not json")
	}))
	defer server.Close()

	if _, err := FetchProvenanceData(server.URL, ppid, bucket, nil); err == nil {
		t.Fatal("FetchProvenanceData() succeeded, want error")
	}
}

func TestFetchProvenanceDataReturnsGCSError(t *testing.T) {
	const (
		ppid   = "abcdef1234567890abcdef1234567890"
		bucket = "test-bucket"
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "NoSuchKey", http.StatusNotFound)
	}))
	defer server.Close()

	_, err := FetchProvenanceData(server.URL, ppid, bucket, nil)
	if err == nil {
		t.Fatal("FetchProvenanceData() succeeded, want error")
	}
	want := "gcs request failed: file 'abcdef1234567890abcdef1234567890' not found in bucket 'test-bucket'"
	if err.Error() != want {
		t.Errorf("FetchProvenanceData() error = %q, want %q", err, want)
	}
}

func TestResolveRawQuoteSupportsQuoteV5(t *testing.T) {
	path := filepath.Join(t.TempDir(), "quote-v5.bin")
	if err := os.WriteFile(path, testdata.RawQuoteV5, 0644); err != nil {
		t.Fatalf("WriteFile(%q) failed: %v", path, err)
	}
	var reportData [64]byte
	raw, quote, err := ResolveRawQuote(path, reportData)
	if err != nil {
		t.Fatalf("ResolveRawQuote() failed: %v", err)
	}
	if !bytes.Equal(raw, testdata.RawQuoteV5) {
		t.Error("ResolveRawQuote() did not preserve QuoteV5 bytes")
	}
	if _, ok := quote.(*pb.QuoteV5); !ok {
		t.Fatalf("ResolveRawQuote() quote type = %T, want *tdx.QuoteV5", quote)
	}
}

func TestResolveRawQuoteUsesLocalQuoteProvider(t *testing.T) {
	provider := &fakeQuoteProvider{raw: testdata.RawQuoteV5}
	originalGetQuoteProvider := getQuoteProvider
	getQuoteProvider = func() (tg.QuoteProvider, error) { return provider, nil }
	t.Cleanup(func() { getQuoteProvider = originalGetQuoteProvider })

	var reportData [64]byte
	reportData[0] = 0xab
	raw, quote, err := ResolveRawQuote("", reportData)
	if err != nil {
		t.Fatalf("ResolveRawQuote() failed: %v", err)
	}
	if !provider.getRawQuoteRan {
		t.Fatal("ResolveRawQuote() did not request a quote from the local provider")
	}
	if provider.reportData != reportData {
		t.Errorf("local quote provider report data = %x, want %x", provider.reportData, reportData)
	}
	if !bytes.Equal(raw, testdata.RawQuoteV5) {
		t.Error("ResolveRawQuote() did not preserve local QuoteV5 bytes")
	}
	if _, ok := quote.(*pb.QuoteV5); !ok {
		t.Fatalf("ResolveRawQuote() quote type = %T, want *tdx.QuoteV5", quote)
	}
}

func TestPPIDFromQuoteSupportsQuoteV5(t *testing.T) {
	quote, err := abi.QuoteToProto(testdata.RawQuoteV5)
	if err != nil {
		t.Fatalf("QuoteToProto(RawQuoteV5) failed: %v", err)
	}
	got, err := PPIDFromQuote(quote)
	if err != nil {
		t.Fatalf("PPIDFromQuote() failed: %v", err)
	}
	if want := "2734b654f553596897eaadfb5667a954"; got != want {
		t.Errorf("PPIDFromQuote() = %q, want %q", got, want)
	}
}

func TestParseGCSError(t *testing.T) {
	testCases := []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{
			name:   "No such bucket",
			status: http.StatusNotFound,
			body:   "NoSuchBucket",
			want:   "gcs request failed: bucket 'test-bucket' not found",
		},
		{
			name:   "No such key",
			status: http.StatusNotFound,
			body:   "NoSuchKey",
			want:   "gcs request failed: file 'abcdef1234567890abcdef1234567890' not found in bucket 'test-bucket'",
		},
		{
			name:   "Forbidden",
			status: http.StatusForbidden,
			body:   "forbidden",
			want:   "gcs request failed: access denied to bucket 'test-bucket' (403 Forbidden); the bucket may be private or not exist",
		},
		{
			name:   "Other status",
			status: http.StatusInternalServerError,
			body:   "internal error",
			want:   "gcs request failed with status: 500 Internal Server Error",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resp := &http.Response{StatusCode: tc.status, Status: http.StatusText(tc.status)}
			if resp.Status == "" {
				resp.Status = fmt.Sprintf("%d status code", tc.status)
			} else {
				resp.Status = fmt.Sprintf("%d %s", tc.status, resp.Status)
			}
			err := ParseGCSError(resp, []byte(tc.body), "abcdef1234567890abcdef1234567890", "test-bucket")
			if err == nil {
				t.Fatal("ParseGCSError() returned nil, want error")
			}
			if err.Error() != tc.want {
				t.Errorf("ParseGCSError() = %q, want %q", err.Error(), tc.want)
			}
		})
	}
}
