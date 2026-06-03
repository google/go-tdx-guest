// Package main implements a CLI tool to fetch provenance data from a GCS bucket using a PPID.
package main

import (
	"encoding/json"
	"errors"
	"flag"
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
	"github.com/google/go-tdx-guest/verify"
)

const gcsBaseURL = "https://storage.googleapis.com"

var (
	ppidFlag       = flag.String("ppid", "", "PPID as a 32-character hex string")
	quoteFileFlag  = flag.String("quote", "", "Path to a raw binary TDX quote file to extract PPID from")
	bucketNameFlag = flag.String("bucket", "confidential-host-registry", "The public GCS bucket name to fetch the provenance document from")
	outputFlag     = flag.String("out", "", "Path to output file to write provenance data to. Default is stdout.")
	verboseFlag    = flag.Bool("verbose", false, "Enable verbose output")

	validPPID   = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)
	validBucket = regexp.MustCompile(`^[a-z0-9_.-]{3,63}$`)
)

func debugf(format string, a ...any) {
	if *verboseFlag {
		fmt.Fprintf(os.Stderr, format, a...)
	}
}

// getPPIDFromQuote extracts the PPID from the PCK certificate embedded in the TDX quote.
// The quote must be a proto type accepted by verify.ExtractChainFromQuote (*pb.QuoteV4 or *pb.QuoteV5);
// raw bytes must be parsed via abi.QuoteToProto first.
func getPPIDFromQuote(quote any) (string, error) {
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

func resolvePPID() (string, error) {
	if *ppidFlag != "" {
		return *ppidFlag, nil
	}
	if *quoteFileFlag != "" {
		quoteBytes, err := os.ReadFile(*quoteFileFlag)
		if err != nil {
			return "", fmt.Errorf("failed to read quote file at %s: %w", *quoteFileFlag, err)
		}
		quoteProto, err := abi.QuoteToProto(quoteBytes)
		if err != nil {
			return "", fmt.Errorf("failed to parse quote bytes: %w", err)
		}
		ppid, err := getPPIDFromQuote(quoteProto)
		if err != nil {
			return "", fmt.Errorf("failed to extract PPID from quote file: %w", err)
		}
		return ppid, nil
	}

	qp, err := tg.GetQuoteProvider()
	if err != nil {
		return "", fmt.Errorf("failed to get quote provider: %w", err)
	}
	if err := qp.IsSupported(); err != nil {
		return "", fmt.Errorf("tdx quote provider not supported on this platform: %w", err)
	}

	var tdxNonce [64]byte
	quote, err := tg.GetQuote(qp, tdxNonce)
	if err != nil {
		return "", fmt.Errorf("failed to fetch local TDX quote: %w", err)
	}
	ppid, err := getPPIDFromQuote(quote)
	if err != nil {
		return "", fmt.Errorf("failed to extract PPID from local quote: %w", err)
	}
	return ppid, nil
}

func fetchProvenanceData(baseURL, ppid, bucket string) ([]byte, error) {
	if !validPPID.MatchString(ppid) {
		return nil, errors.New("invalid PPID format")
	}
	if !validBucket.MatchString(bucket) {
		return nil, errors.New("invalid bucket name format")
	}

	debugf("Using PPID: %s\n", ppid)
	debugf("Using GCS Bucket: %s\n", bucket)

	url := fmt.Sprintf("%s/%s/%s.json", baseURL, bucket, ppid)
	debugf("Fetching from URL: %s\n", url)

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
		return nil, parseGCSError(resp, bodyBytes, ppid, bucket)
	}

	if !json.Valid(bodyBytes) {
		return nil, errors.New("received invalid JSON from GCS")
	}

	return bodyBytes, nil
}

func parseGCSError(resp *http.Response, bodyBytes []byte, ppid string, bucket string) error {
	bodyStr := string(bodyBytes)
	if strings.Contains(bodyStr, "NoSuchBucket") {
		return fmt.Errorf("gcs request failed: bucket '%s' not found", bucket)
	}
	if strings.Contains(bodyStr, "NoSuchKey") {
		return fmt.Errorf("gcs request failed: file '%s.json' not found in bucket '%s'", ppid, bucket)
	}
	if resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("gcs request failed: access denied to bucket '%s' (403 Forbidden); the bucket may be private or not exist", bucket)
	}
	return fmt.Errorf("gcs request failed with status: %s", resp.Status)
}

func run(baseURL string) error {
	ppid, err := resolvePPID()
	if err != nil {
		return err
	}

	bodyBytes, err := fetchProvenanceData(baseURL, ppid, *bucketNameFlag)
	if err != nil {
		return err
	}

	out := os.Stdout
	if *outputFlag != "" {
		f, err := os.Create(*outputFlag)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer f.Close()
		out = f
	}

	if _, err := out.Write(bodyBytes); err != nil {
		return fmt.Errorf("failed to write output: %w", err)
	}

	return nil
}

func main() {
	flag.Parse()
	if err := run(gcsBaseURL); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
