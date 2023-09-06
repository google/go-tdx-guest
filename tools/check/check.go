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
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/google/go-tdx-guest/abi"
	"github.com/google/go-tdx-guest/verify"
	"github.com/google/go-tdx-guest/verify/trust"
	"github.com/google/logger"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"

	pb "github.com/google/go-tdx-guest/proto/tdx"
	testcases "github.com/google/go-tdx-guest/testing"
)

const (
	defaultCheckCrl      = false
	defaultGetCollateral = false
	defaultTimeout       = 2 * time.Minute
	defaultMaxRetryDelay = 30 * time.Second

	// Exit code 1 - tool usage error.
	exitTool = 1
	// Exit code 2 - quote verification error.
	exitVerify = 2
	// Exit code 3 - network error while downloading collateral.
	exitNetwork = 3
)

var (
	infile = flag.String("in", "-", "Path to the TDX quote to check. Stdin is \"-\".")
	inform = flag.String("inform", "bin", "The input format for the TDX quote. One of \"bin\", \"proto\", \"textproto\".")

	quiet   = flag.Bool("quiet", false, "If true, writes nothing the stdout or stderr. Success is exit code 0, failure exit code 1.")
	verbose = flag.Bool("verbose", false, "Enable verbose logging.")

	checkcrl        = flag.Bool("check_crl", defaultCheckCrl, "Check the CRL for revoked certificates. -get_collateral must be true.")
	getcollateral   = flag.Bool("get_collateral", defaultGetCollateral, "Get the Collateral for additional checks.")
	timeout         = flag.Duration("timeout", defaultTimeout, "Duration to continue to retry failed HTTP requests.")
	maxRetryDelay   = flag.Duration("max_retry_delay", defaultMaxRetryDelay, "Maximum Duration to wait between HTTP request retries.")
	testLocalGetter = flag.Bool("test_local_getter", false, "Use this flag only to test this CLI tool when network access is not available")
)

func parseQuoteBytes(b []byte) (*pb.QuoteV4, error) {
	quote, err := abi.QuoteToProto(b)
	if err != nil {
		return nil, fmt.Errorf("could not parse the quote from %q: %v", *infile, err)
	}

	return quote, nil
}

func parseQuote(b []byte) (*pb.QuoteV4, error) {
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

func readQuote() (*pb.QuoteV4, error) {
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
		fmt.Fprintf(os.Stderr, "%v\n", err)
	}
	os.Exit(exitCode)
}

func die(err error) {
	dieWith(err, exitTool)
}

func main() {
	logger.Init("", *verbose, false, os.Stderr)
	flag.Parse()

	quote, err := readQuote()
	if err != nil {
		die(err)
	}

	var getter trust.HTTPSGetter
	getter = &trust.SimpleHTTPSGetter{}
	if *testLocalGetter {
		getter = testcases.TestGetter
	}

	verifyOpts := verify.Options{
		GetCollateral:    *getcollateral,
		CheckRevocations: *checkcrl,
		Getter: &trust.RetryHTTPSGetter{
			Timeout:       *timeout,
			MaxRetryDelay: *maxRetryDelay,
			Getter:        getter,
		},
		TrustedRoots: nil,
	}

	if err := verify.TdxQuote(quote, &verifyOpts); err != nil {
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
		dieWith(fmt.Errorf("could not verify the quote: %v", err), exitCode)
	}
}
