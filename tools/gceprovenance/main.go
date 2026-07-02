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

// Package main implements the GCE TDX provenance CLI.
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-tdx-guest/abi"
	"github.com/google/go-tdx-guest/gce"
	"github.com/google/go-tdx-guest/validate"
	"github.com/google/go-tdx-guest/verify"
)

const (
	defaultBucketName          = "confidential-host-registry"
	defaultOutDir              = "."
	defaultQuoteOutName        = "tdx_quote.bin"
	defaultHostRegistryOutName = "host_registry.json"
)

type commandConfig struct {
	Quote           string
	Bucket          string
	Instance        string
	UseMetadata     bool
	Challenge       string
	OutDir          string
	QuoteOut        string
	HostRegistryOut string
	Verbose         bool
}

type quoteEvidence struct {
	Raw       []byte
	Quote     any
	Challenge []byte
}

type hostResult struct {
	PPID             string
	HostRegistryPath string
}

type instanceResult struct {
	Info *gce.InstanceInfo
	PZID *gce.PZIDVerification
}

type reportedError struct {
	err error
}

func (e *reportedError) Error() string {
	return e.err.Error()
}

func (e *reportedError) Unwrap() error {
	return e.err
}

func main() {
	if err := runCLI(os.Args[1:], gce.GCSBaseURL, os.Stdout, os.Stderr); err != nil {
		var reported *reportedError
		if !errors.As(err, &reported) {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		}
		os.Exit(1)
	}
}

func runCLI(args []string, baseURL string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		printUsage(stderr)
		return errors.New("missing command; use \"verify\", \"verify-host\", or \"verify-instance\"")
	}

	switch args[0] {
	case "verify":
		return runVerifyCLI(args[1:], baseURL, stdout, stderr)
	case "verify-host":
		return runVerifyHostCLI(args[1:], baseURL, stdout, stderr)
	case "verify-instance":
		return runVerifyInstanceCLI(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		printUsage(stdout)
		return nil
	default:
		if strings.HasPrefix(args[0], "-") {
			return fmt.Errorf("missing command before %q; use \"gceprovenance verify\", \"gceprovenance verify-host\", or \"gceprovenance verify-instance\"", args[0])
		}
		return fmt.Errorf("unknown command %q; use \"verify\", \"verify-host\", or \"verify-instance\"", args[0])
	}
}

func runVerifyCLI(args []string, baseURL string, stdout, stderr io.Writer) error {
	cfg, err := parseCommandFlags("gceprovenance verify", args, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	return runVerify(baseURL, cfg, stdout, stderr)
}

func runVerifyHostCLI(args []string, baseURL string, stdout, stderr io.Writer) error {
	cfg, err := parseCommandFlags("gceprovenance verify-host", args, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	return runVerifyHost(baseURL, cfg, stdout, stderr)
}

func runVerifyInstanceCLI(args []string, stdout, stderr io.Writer) error {
	cfg, err := parseCommandFlags("gceprovenance verify-instance", args, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	return runVerifyInstance(cfg, stdout, stderr)
}

func parseCommandFlags(name string, args []string, stderr io.Writer) (commandConfig, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfg := commandConfig{
		Bucket: defaultBucketName,
		OutDir: defaultOutDir,
	}
	fs.StringVar(&cfg.Quote, "quote", "", "Path to a raw binary TDX quote. If unset, fetches a local quote.")
	fs.StringVar(&cfg.Bucket, "bucket", defaultBucketName, "Public GCS bucket containing host registry documents.")
	fs.StringVar(&cfg.Instance, "instance", "", "GCE instance resource string projects/<project-number>/zones/<zone>/instances/<instance-id>.")
	fs.BoolVar(&cfg.UseMetadata, "MDS", false, "Use the metadata server to collect GCE instance identity. This is the default when -instance is unset.")
	fs.StringVar(&cfg.Challenge, "challenge", "", "Expected REPORT_DATA as 64 bytes encoded in 128 hex characters.")
	fs.StringVar(&cfg.OutDir, "out-dir", defaultOutDir, "Directory for default output files.")
	fs.StringVar(&cfg.QuoteOut, "quote-out", "", "Path to write the exact raw TDX quote used. Defaults to <out-dir>/tdx_quote.bin.")
	fs.StringVar(&cfg.HostRegistryOut, "host-registry-out", "", "Path to write fetched host registry JSON. Defaults to <out-dir>/host_registry.json.")
	fs.BoolVar(&cfg.Verbose, "verbose", false, "Enable verbose output.")
	if err := fs.Parse(args); err != nil {
		return cfg, err
	}
	if fs.NArg() != 0 {
		return cfg, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	return cfg, nil
}

func runVerify(baseURL string, cfg commandConfig, stdout, stderr io.Writer) error {
	evidence, err := resolveAndVerifyQuote(context.Background(), cfg)
	if err != nil {
		return err
	}
	quotePath, err := writeQuoteOutput(cfg, evidence.Raw)
	if err != nil {
		return err
	}
	host, err := verifyHost(baseURL, cfg, evidence, stderr)
	if err != nil {
		return err
	}
	instance, err := verifyInstance(cfg, evidence)
	if err != nil {
		if instance != nil && instance.PZID != nil {
			writeVerifyFailure(stderr, instance.Info, host.PPID, instance.PZID, cfg.Verbose)
			return &reportedError{err: err}
		}
		return err
	}
	writeVerifySuccess(stdout, instance.Info, host.PPID, quotePath, host.HostRegistryPath, evidence.Challenge != nil)
	return nil
}

func runVerifyHost(baseURL string, cfg commandConfig, stdout, stderr io.Writer) error {
	evidence, err := resolveAndVerifyQuote(context.Background(), cfg)
	if err != nil {
		return err
	}
	quotePath, err := writeQuoteOutput(cfg, evidence.Raw)
	if err != nil {
		return err
	}
	host, err := verifyHost(baseURL, cfg, evidence, stderr)
	if err != nil {
		return err
	}
	writeHostSuccess(stdout, host.PPID, quotePath, host.HostRegistryPath, evidence.Challenge != nil)
	return nil
}

func runVerifyInstance(cfg commandConfig, stdout, stderr io.Writer) error {
	evidence, err := resolveAndVerifyQuote(context.Background(), cfg)
	if err != nil {
		return err
	}
	quotePath, err := writeQuoteOutput(cfg, evidence.Raw)
	if err != nil {
		return err
	}
	instance, err := verifyInstance(cfg, evidence)
	if err != nil {
		if instance != nil && instance.PZID != nil {
			writeInstanceFailure(stderr, instance.Info, instance.PZID, cfg.Verbose)
			return &reportedError{err: err}
		}
		return err
	}
	writeInstanceSuccess(stdout, instance.Info, quotePath, evidence.Challenge != nil)
	return nil
}

func resolveAndVerifyQuote(ctx context.Context, cfg commandConfig) (*quoteEvidence, error) {
	challenge, reportData, err := parseChallenge(cfg.Challenge)
	if err != nil {
		return nil, err
	}
	raw, quote, err := gce.ResolveRawQuote(cfg.Quote, reportData)
	if err != nil {
		return nil, err
	}
	if err := verifyTDXQuote(ctx, quote); err != nil {
		return nil, fmt.Errorf("quote verification failed: %w", err)
	}
	if challenge != nil {
		if err := validateReportData(quote, challenge); err != nil {
			return nil, fmt.Errorf("REPORT_DATA challenge verification failed: %w", err)
		}
	}
	return &quoteEvidence{
		Raw:       raw,
		Quote:     quote,
		Challenge: challenge,
	}, nil
}

func verifyHost(baseURL string, cfg commandConfig, evidence *quoteEvidence, stderr io.Writer) (*hostResult, error) {
	ppid, err := gce.PPIDFromQuote(evidence.Quote)
	if err != nil {
		return nil, err
	}
	hostRegistry, err := gce.FetchProvenanceData(baseURL, ppid, cfg.Bucket, debugf(stderr, cfg.Verbose))
	if err != nil {
		return nil, fmt.Errorf("host registry document lookup failed: %w", err)
	}
	path := hostRegistryOutputPath(cfg)
	if err := writeOutputFile(path, hostRegistry); err != nil {
		return nil, fmt.Errorf("write host registry data to %s: %w", path, err)
	}
	return &hostResult{
		PPID:             ppid,
		HostRegistryPath: path,
	}, nil
}

func verifyInstance(cfg commandConfig, evidence *quoteEvidence) (*instanceResult, error) {
	info, err := gce.ResolveInstanceInfo(context.Background(), cfg.Instance, cfg.UseMetadata)
	if err != nil {
		return nil, err
	}
	pzid, err := gce.VerifyPZID(evidence.Quote, info)
	return &instanceResult{Info: info, PZID: pzid}, err
}

func verifyTDXQuote(ctx context.Context, quote any) error {
	return verify.TdxQuoteContext(ctx, quote, verify.DefaultOptions())
}

func validateReportData(quote any, challenge []byte) error {
	opts := &validate.Options{
		TdQuoteBodyOptions: validate.TdQuoteBodyOptions{
			ReportData: challenge,
		},
	}
	return validate.TdxQuote(quote, opts)
}

func parseChallenge(value string) ([]byte, [64]byte, error) {
	var reportData [64]byte
	if value == "" {
		return nil, reportData, nil
	}
	challenge, err := hex.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return nil, reportData, fmt.Errorf("-challenge must be 64 bytes encoded as 128 hex characters: %w", err)
	}
	if len(challenge) != abi.ReportDataSize {
		return nil, reportData, fmt.Errorf("-challenge must be 64 bytes encoded as 128 hex characters; got %d bytes", len(challenge))
	}
	copy(reportData[:], challenge)
	return challenge, reportData, nil
}

func writeQuoteOutput(cfg commandConfig, quoteBytes []byte) (string, error) {
	path := quoteOutputPath(cfg)
	if err := writeOutputFile(path, quoteBytes); err != nil {
		return "", fmt.Errorf("write raw quote to %s: %w", path, err)
	}
	return path, nil
}

func quoteOutputPath(cfg commandConfig) string {
	if cfg.QuoteOut != "" {
		return cfg.QuoteOut
	}
	return filepath.Join(outputDir(cfg), defaultQuoteOutName)
}

func hostRegistryOutputPath(cfg commandConfig) string {
	if cfg.HostRegistryOut != "" {
		return cfg.HostRegistryOut
	}
	return filepath.Join(outputDir(cfg), defaultHostRegistryOutName)
}

func outputDir(cfg commandConfig) string {
	if cfg.OutDir == "" {
		return defaultOutDir
	}
	return cfg.OutDir
}

func writeOutputFile(path string, contents []byte) error {
	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}
	return os.WriteFile(path, contents, 0644)
}

func writeVerifySuccess(out io.Writer, info *gce.InstanceInfo, ppid, quotePath, hostRegistryPath string, challengeChecked bool) {
	fmt.Fprintln(out, "GCE TDX provenance verification: OK")
	fmt.Fprintln(out)
	writeInstance(out, info)
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Checks")
	fmt.Fprintln(out, "  Quote verification: OK")
	writeChallengeCheck(out, challengeChecked)
	fmt.Fprintln(out, "  Host registry document: found")
	fmt.Fprintln(out, "  PZID binding: OK")
	fmt.Fprintln(out)
	fmt.Fprintf(out, "PPID: %s\n", ppid)
	fmt.Fprintf(out, "Quote: %s\n", quotePath)
	fmt.Fprintf(out, "Host registry: %s\n", hostRegistryPath)
}

func writeHostSuccess(out io.Writer, ppid, quotePath, hostRegistryPath string, challengeChecked bool) {
	fmt.Fprintln(out, "GCE TDX host verification: OK")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Checks")
	fmt.Fprintln(out, "  Quote verification: OK")
	writeChallengeCheck(out, challengeChecked)
	fmt.Fprintln(out, "  Host registry document: found")
	fmt.Fprintln(out)
	fmt.Fprintf(out, "PPID: %s\n", ppid)
	fmt.Fprintf(out, "Quote: %s\n", quotePath)
	fmt.Fprintf(out, "Host registry: %s\n", hostRegistryPath)
}

func writeInstanceSuccess(out io.Writer, info *gce.InstanceInfo, quotePath string, challengeChecked bool) {
	fmt.Fprintln(out, "GCE TDX instance verification: OK")
	fmt.Fprintln(out)
	writeInstance(out, info)
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Checks")
	fmt.Fprintln(out, "  Quote verification: OK")
	writeChallengeCheck(out, challengeChecked)
	fmt.Fprintln(out, "  PZID binding: OK")
	fmt.Fprintln(out)
	fmt.Fprintf(out, "Quote: %s\n", quotePath)
}

func writeChallengeCheck(out io.Writer, checked bool) {
	if checked {
		fmt.Fprintln(out, "  REPORT_DATA challenge: OK")
		return
	}
	fmt.Fprintln(out, "  REPORT_DATA challenge: not checked")
}

func writeInstanceFailure(out io.Writer, info *gce.InstanceInfo, result *gce.PZIDVerification, verbose bool) {
	fmt.Fprintln(out, "GCE TDX instance verification: FAILED")
	fmt.Fprintln(out)
	writeInstance(out, info)
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Checks")
	fmt.Fprintln(out, "  PZID binding: FAILED")
	writePZIDDetails(out, result, verbose)
}

func writeVerifyFailure(out io.Writer, info *gce.InstanceInfo, ppid string, result *gce.PZIDVerification, verbose bool) {
	fmt.Fprintln(out, "GCE TDX provenance verification: FAILED")
	fmt.Fprintln(out)
	writeInstance(out, info)
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Checks")
	fmt.Fprintln(out, "  Host registry document: found")
	fmt.Fprintln(out, "  PZID binding: FAILED")
	writePZIDDetails(out, result, verbose)
	fmt.Fprintln(out)
	fmt.Fprintf(out, "PPID: %s\n", ppid)
}

func writePZIDDetails(out io.Writer, result *gce.PZIDVerification, verbose bool) {
	fmt.Fprintln(out)
	fmt.Fprintln(out, "PZID binding")
	if result == nil {
		return
	}
	fmt.Fprintf(out, "  Quote MR_OWNER:    %s\n", result.AttestedMROwnerHX)
	fmt.Fprintf(out, "  Expected MR_OWNER: %s\n", result.ExpectedMROwnerHX)
	if verbose {
		fmt.Fprintf(out, "  Payload: %s\n", result.Payload)
	}
}

func writeInstance(out io.Writer, info *gce.InstanceInfo) {
	fmt.Fprintln(out, "Instance")
	if info == nil {
		fmt.Fprintln(out, "  <unknown>")
		return
	}
	if info.InstanceName != "" {
		fmt.Fprintf(out, "  Name: %s\n", info.InstanceName)
	}
	fmt.Fprintf(out, "  Zone: %s\n", info.Zone)
	if info.ProjectID != "" {
		fmt.Fprintf(out, "  Project: %s (%d)\n", info.ProjectID, info.ProjectNumber)
	} else {
		fmt.Fprintf(out, "  Project: %d\n", info.ProjectNumber)
	}
	fmt.Fprintf(out, "  Instance ID: %d\n", info.InstanceID)
}

func debugf(stderr io.Writer, verbose bool) func(string, ...any) {
	if !verbose {
		return nil
	}
	return func(format string, a ...any) {
		fmt.Fprintf(stderr, format, a...)
	}
}

func printUsage(out io.Writer) {
	fmt.Fprintln(out, "Usage:")
	fmt.Fprintln(out, "  gceprovenance verify [flags]            Verify quote, host registry, and GCE instance binding")
	fmt.Fprintln(out, "  gceprovenance verify-host [flags]       Verify quote and host registry lookup")
	fmt.Fprintln(out, "  gceprovenance verify-instance [flags]   Verify quote and GCE instance binding")
}
