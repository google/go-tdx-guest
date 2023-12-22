// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package main implements a CLI tool for checking Intel TDX quotes.
package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-sev-guest/tools/lib/cmdline"
	"github.com/google/go-tdx-guest/abi"
	ccpb "github.com/google/go-tdx-guest/proto/checkconfig"
	pb "github.com/google/go-tdx-guest/proto/tdx"
	testcases "github.com/google/go-tdx-guest/testing"
	"github.com/google/go-tdx-guest/validate"
	"github.com/google/go-tdx-guest/verify"
	"github.com/google/go-tdx-guest/verify/trust"
	"github.com/google/logger"
	"go.uber.org/multierr"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
)

const (
	defaultCheckCrl      = false
	defaultGetCollateral = false
	defaultTimeout       = 2 * time.Minute
	defaultMaxRetryDelay = 30 * time.Second
	defaultMinQeSvn      = 0
	defaultMinPceSvn     = 0

	// Exit code 1 - tool usage error.
	exitTool = 1
	// Exit code 2 - quote verification error.
	exitVerify = 2
	// Exit code 3 - network error while downloading collateral.
	exitNetwork = 3
	// Exit code 4 - the quote did not validate according to policy.
	exitPolicy = 4
)

var (
	infile = flag.String("in", "-", "Path to the TDX quote to check. Stdin is \"-\".")
	inform = flag.String("inform", "bin", "The input format for the TDX quote. One of \"bin\", \"proto\", \"textproto\".")

	configProto = flag.String("config", "",
		("A path to a serialized check.Config protobuf. Any individual field flags will" +
			" overwrite the message's associated field. By default, the file will be unmarshalled as binary," +
			" but if it ends in .textproto, it will be unmarshalled as prototext instead."))
	quiet   = flag.Bool("quiet", false, "If true, writes nothing the stdout or stderr. Success is exit code 0, failure exit code 1.")
	verbose = flag.Int("verbosity", 0, "The output verbosity. Higher number means more verbose output")

	qevendoridS    = flag.String("qe_vendor_id", "", "The expected QE_VENDOR_ID field as a hex string. Must encode 16 bytes. Unchecked if unset.")
	qevendorid     = cmdline.Bytes("-qe_vendor_id", abi.QeVendorIDSize, qevendoridS)
	mrseamS        = flag.String("mr_seam", "", "The expected MR_SEAM field as a hex string. Must encode 48 bytes. Unchecked if unset.")
	mrseam         = cmdline.Bytes("-mr_seam", abi.MrSeamSize, mrseamS)
	tdattributesS  = flag.String("td_attributes", "", "The expected TD_ATTRIBUTES field as a hex string. Must encode 8 bytes. Unchecked if unset.")
	tdattributes   = cmdline.Bytes("-td_attributes", abi.TdAttributesSize, tdattributesS)
	xfamS          = flag.String("xfam", "", "The expected XFAM field as a hex string. Must encode 8 bytes. Unchecked if unset.")
	xfam           = cmdline.Bytes("-xfam", abi.XfamSize, xfamS)
	mrtdS          = flag.String("mr_td", "", "The expected MR_TD field as a hex string. Must encode 48 bytes. Unchecked if unset.")
	mrtd           = cmdline.Bytes("-mr_td", abi.MrTdSize, mrtdS)
	mrconfigidS    = flag.String("mr_config_id", "", "The expected MR_CONFIG_ID field as a hex string. Must encode 48 bytes. Unchecked if unset.")
	mrconfigid     = cmdline.Bytes("-mr_config_id", abi.MrConfigIDSize, mrconfigidS)
	mrownerS       = flag.String("mr_owner", "", "The expected MR_OWNER field as a hex string. Must encode 48 bytes. Unchecked if unset.")
	mrowner        = cmdline.Bytes("-mr_owner", abi.MrOwnerSize, mrownerS)
	mrownerconfigS = flag.String("mr_owner_config", "", "The expected MR_OWNER_CONFIG field as a hex string. Must encode 48 bytes. Unchecked if unset.")
	mrownerconfig  = cmdline.Bytes("-mr_owner_config", abi.MrOwnerConfigSize, mrownerconfigS)
	reportdataS    = flag.String("report_data", "", "The expected REPORT_DATA field as a hex string. Must encode 64 bytes. Unchecked if unset.")
	reportdata     = cmdline.Bytes("-report_data", abi.ReportDataSize, reportdataS)
	minteetcbsvnS  = flag.String("minimum_tee_tcb_svn", "", "The minimum acceptable value for TEE_TCB_SVN field as a hex string. Must encode 16 bytes. Unchecked if unset.")
	minteetcbsvn   = cmdline.Bytes("-minimum_tee_tcb_svn", abi.TeeTcbSvnSize, minteetcbsvnS)

	rtmrs = flag.String("rtmrs", "",
		"Comma-separated hex strings representing expected values of RTMRS field. Expected 4 strings, either empty or each must encode 48 bytes. Unchecked if unset")

	cabundles = flag.String("trusted_roots", "",
		"Comma-separated paths to CA bundles for the Intel TDX. Must be in PEM format, Root CA certificate. If unset, uses embedded root certificate.")
	// Optional Uint16. We don't want 0 to override the policy message, so instead of parsing
	// as Uint16 up front, we keep the flag a string and parse later if given.
	minqesvn  = flag.String("minimum_qe_svn", "", "The minimum acceptable value for QE_SVN field.")
	minpcesvn = flag.String("minimum_pce_svn", "", "The minimum acceptable value for PCE_SVN field.")

	// Optional Bool
	checkcrl        = flag.String("check_crl", "", "Download and check the CRL for revoked certificates. -get_collateral must be true.")
	getcollateral   = flag.String("get_collateral", "", "If true, then permitted to download necessary collaterals for additional checks.")
	timeout         = flag.Duration("timeout", defaultTimeout, "Duration to continue to retry failed HTTP requests.")
	maxRetryDelay   = flag.Duration("max_retry_delay", defaultMaxRetryDelay, "Maximum Duration to wait between HTTP request retries.")
	testLocalGetter = flag.Bool("test_local_getter", false, "Use this flag only to test this CLI tool when network access is not available")

	// Assign the values of the flags to the corresponding proto fields
	config = &ccpb.Config{
		RootOfTrust: &ccpb.RootOfTrust{},
		Policy:      &ccpb.Policy{HeaderPolicy: &ccpb.HeaderPolicy{}, TdQuoteBodyPolicy: &ccpb.TDQuoteBodyPolicy{}},
	}
)

func parseQuoteBytes(b []byte) (any, error) {
	quote, err := abi.QuoteToProto(b)
	if err != nil {
		return nil, fmt.Errorf("could not parse the TDX Quote from %q: %v", *infile, err)
	}

	return quote, nil
}

func parseQuote(b []byte) (any, error) {
	switch *inform {
	case "bin":
		return parseQuoteBytes(b)
	case "proto":
		result := &pb.QuoteV4{}
		if err := proto.Unmarshal(b, result); err != nil {
			return nil, fmt.Errorf("could not parse %q as proto: %v", *infile, err)
		}
		return result, nil
	case "textproto":
		result := &pb.QuoteV4{}
		if err := prototext.Unmarshal(b, result); err != nil {
			return nil, fmt.Errorf("could not parse %q as textproto: %v", *infile, err)
		}
		return result, nil
	default:
		return nil, fmt.Errorf("unknown value -inform=%s", *inform)
	}
}

func parseUint(p string, bits int) (uint64, error) {
	base := 10
	prepped := p
	if strings.HasPrefix(strings.ToLower(p), "0x") {
		base = 16
		prepped = prepped[2:]
	} else if strings.HasPrefix(strings.ToLower(p), "0o") {
		base = 8
		prepped = prepped[2:]
	} else if strings.HasPrefix(strings.ToLower(p), "0b") {
		base = 2
		prepped = prepped[2:]
	}
	info64, err := strconv.ParseUint(prepped, base, bits)
	if err != nil {
		return 0, fmt.Errorf("%q must be empty or a %d-bit number: %v", p, bits, err)
	}
	return info64, nil
}

func readQuote() (any, error) {
	var in io.Reader
	var f *os.File
	if *infile == "-" {
		in = os.Stdin
	} else {
		file, err := os.Open(*infile)
		if err != nil {
			return nil, fmt.Errorf("could not open %q: %v", *infile, err)
		}
		f = file
		in = file
	}
	defer func() {
		if f != nil {
			f.Close()
		}
	}()

	contents, err := io.ReadAll(in)
	if err != nil {
		return nil, fmt.Errorf("could not read %q: %v", *infile, err)
	}
	return parseQuote(contents)
}

func dieWith(err error, exitCode int) {
	if !*quiet {
		fmt.Fprintf(os.Stderr, "FATAL: %v\n", err)
	}
	os.Exit(exitCode)
}

func die(err error) {
	dieWith(err, exitTool)
}

func parseConfig(path string) error {
	if path == "" {
		return nil
	}

	contents, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("could not read %q: %v", path, err)
	}
	if strings.HasSuffix(path, ".textproto") {
		err = prototext.Unmarshal(contents, config)
	} else {
		err = proto.Unmarshal(contents, config)
	}
	if err != nil {
		return fmt.Errorf("could not deserialize %q: %v", path, err)
	}
	// Populate fields that should not be nil
	if config.RootOfTrust == nil {
		config.RootOfTrust = &ccpb.RootOfTrust{}
	}
	if config.Policy == nil {
		config.Policy = &ccpb.Policy{HeaderPolicy: &ccpb.HeaderPolicy{}, TdQuoteBodyPolicy: &ccpb.TDQuoteBodyPolicy{}}
	}
	return nil
}

func parsePaths(s string) ([]string, error) {
	if s == "" {
		return nil, nil
	}
	paths := strings.Split(s, ",")
	var result []string
	for _, path := range paths {
		p := strings.TrimSpace(path)
		stat, err := os.Stat(p)
		if err != nil {
			return nil, fmt.Errorf("path error for %q: %v", p, err)
		}
		if stat.IsDir() {
			return nil, fmt.Errorf("path is not a file: %q", p)
		}
		result = append(result, p)
	}
	return result, nil
}

func parseRtmrs(s string) ([][]byte, error) {
	if s == "" {
		return nil, nil
	}
	hexstrings := strings.Split(s, ",")
	var result [][]byte
	for _, hexstring := range hexstrings {
		h, err := hex.DecodeString(strings.TrimSpace(hexstring))
		if err != nil {
			return nil, fmt.Errorf("could not parse RTMRS value as hex-encoded string: %q", hexstring)
		}
		result = append(result, h)
	}
	return result, nil
}

func setBool(value *bool, name, flag string, defaultValue bool) error {
	if flag == "" {
		if !configProtoPresent() {
			*value = defaultValue
		}
	} else if flag == "true" {
		*value = true
	} else if flag == "false" {
		*value = false
	} else {
		return fmt.Errorf("flag -%s=%s invalid. Must be one of unset, \"true\", or \"false\"",
			name, flag)
	}
	return nil
}

func setUint(value *uint64, bits int, name, flag string, defaultValue uint64) error {
	if flag == "" {
		if !configProtoPresent() {
			*value = defaultValue
		}
	} else {
		u, err := parseUint(flag, bits)
		if err != nil {
			return fmt.Errorf("invalid -%s=%s: %v", name, flag, err)
		}
		*value = u
	}
	return nil
}

func setUint32(value *uint32, name, flag string, defaultValue uint64) error {
	v := uint64(*value)
	if err := setUint(&v, 32, name, flag, defaultValue); err != nil {
		return err
	}
	*value = uint32(v)
	return nil
}

func configProtoPresent() bool {
	return *configProto != ""
}

func populateRootOfTrust() error {
	rot := config.RootOfTrust

	if err := setBool(&rot.CheckCrl, "check_crl", *checkcrl, defaultCheckCrl); err != nil {
		return err
	}
	if err := setBool(&rot.GetCollateral, "get_collateral", *getcollateral, defaultGetCollateral); err != nil {
		return err
	}
	paths, err := parsePaths(*cabundles)
	if err != nil {
		return err
	}
	if len(paths) > 0 {
		rot.CabundlePaths = paths
	}
	return nil
}

// Populate fields of the config proto from flags if they override.
func populateConfig() error {
	policy := config.Policy

	setNonNil := func(dest *[]byte, value []byte) {
		if value != nil {
			*dest = value
		}
	}
	setRtmrs := func(dest *[][]byte, name, flag string) error {
		if flag != "" {
			val, err := parseRtmrs(flag)
			if err != nil {
				return err
			}
			*dest = val
		}
		return nil
	}

	setNonNil(&policy.HeaderPolicy.QeVendorId, *qevendorid)
	setNonNil(&policy.TdQuoteBodyPolicy.MinimumTeeTcbSvn, *minteetcbsvn)
	setNonNil(&policy.TdQuoteBodyPolicy.MrSeam, *mrseam)
	setNonNil(&policy.TdQuoteBodyPolicy.TdAttributes, *tdattributes)
	setNonNil(&policy.TdQuoteBodyPolicy.Xfam, *xfam)
	setNonNil(&policy.TdQuoteBodyPolicy.MrTd, *mrtd)
	setNonNil(&policy.TdQuoteBodyPolicy.MrConfigId, *mrconfigid)
	setNonNil(&policy.TdQuoteBodyPolicy.MrOwner, *mrowner)
	setNonNil(&policy.TdQuoteBodyPolicy.MrOwnerConfig, *mrownerconfig)
	setNonNil(&policy.TdQuoteBodyPolicy.ReportData, *reportdata)

	return multierr.Combine(
		setUint32(&policy.HeaderPolicy.MinimumQeSvn, "minimum_qe_svn", *minqesvn, defaultMinQeSvn),
		setUint32(&policy.HeaderPolicy.MinimumPceSvn, "minimum_pce_svn", *minpcesvn, defaultMinPceSvn),
		setRtmrs(&policy.TdQuoteBodyPolicy.Rtmrs, "rtmrs", *rtmrs),
	)
}

func main() {
	logger.Init("", false, false, os.Stdout)
	flag.Parse()
	cmdline.Parse("auto")
	logger.SetLevel(logger.Level(*verbose))

	logger.V(1).Info("Parsing input parameters")
	if err := parseConfig(*configProto); err != nil {
		die(err)
	}
	if err := multierr.Combine(populateRootOfTrust(),
		populateConfig()); err != nil {
		die(err)
	}
	if config.RootOfTrust.CheckCrl && !config.RootOfTrust.GetCollateral {
		die(errors.New("cannot specify both -check_crl=true and -get_collateral=false"))
	}

	quote, err := readQuote()
	if err != nil {
		die(err)
	}
	logger.V(1).Info("TDX Quote parsed successfully")

	sopts, err := verify.RootOfTrustToOptions(config.RootOfTrust)
	if err != nil {
		die(err)
	}
	logger.V(1).Info("Input parameters parsed successfully")

	var getter trust.HTTPSGetter
	getter = &trust.SimpleHTTPSGetter{}
	if *testLocalGetter {
		getter = testcases.TestGetter
	}
	sopts.Getter = &trust.RetryHTTPSGetter{
		Timeout:       *timeout,
		MaxRetryDelay: *maxRetryDelay,
		Getter:        getter,
	}

	logger.V(1).Info("Verifying the TDX Quote from input")
	if err := verify.TdxQuote(quote, sopts); err != nil {
		// Make the exit code more helpful when there are network errors
		// that affected the result.
		exitCode := exitVerify
		clarify := func(err error) bool {
			if err == nil {
				return false
			}
			var crlNetworkErr *verify.CRLUnavailableErr
			var collateralNetworkErr *trust.AttestationRecreationErr
			if errors.As(err, &crlNetworkErr) || errors.As(err, &collateralNetworkErr) {
				exitCode = exitNetwork
				return true
			}

			return false
		}
		if !clarify(err) {
			clarify(errors.Unwrap(err))
		}
		dieWith(fmt.Errorf("could not verify the TDX Quote: %v", err), exitCode)
	}
	logger.Info("TDX Quote verified successfully")

	opts, err := validate.PolicyToOptions(config.Policy)
	if err != nil {
		die(err)
	}
	if err := validate.TdxQuote(quote, opts); err != nil {
		dieWith(fmt.Errorf("error validating the TDX Quote: %v", err), exitPolicy)
	}
	logger.V(1).Info("TDX Quote validated successfully")
}
