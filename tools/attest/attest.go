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

// Package main implements a CLI tool for collecting attestation reports.
package main

import (
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/google/go-tdx-guest/client"
	labi "github.com/google/go-tdx-guest/client/linuxabi"
	pb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/logger"
	"google.golang.org/protobuf/encoding/prototext"
)

var (
	outform = flag.String("outform", "bin",
		"The format of the output attestation report. "+
			"One of \"bin\", \"textproto\".")
	reportDataStr = flag.String("in", "",
		"A string of 64 bytes REPORT_DATA to include in the output attestation. "+
			"REPORT_DATA can be either in base64 or hex format. If -inform=auto, first check with base64, hex and last with auto.")
	inform = flag.String("inform", "auto", "The format of the reportData input. One of base64, hex and auto. "+
		"If -inform=auto, first check with base64 and last with hex.")
	out = flag.String("out", "", "Path to output file to write attestation report to. "+
		"If unset, outputs to stdout.")
	verbose   = flag.Bool("v", false, "Enable verbose logging.")
	verbosity = flag.Int("verbosity", 0, "The output verbosity. Higher number means more verbose output")
)

func outputReport(data [labi.TdReportDataSize]byte, out io.Writer) error {
	tdxQuoteProvider, err := client.GetQuoteProvider()
	if err != nil {
		return err
	}
	if *outform == "bin" {
		bytes, err := client.GetRawQuote(tdxQuoteProvider, data)
		if err != nil {
			return err
		}
		out.Write(bytes)
		return nil
	}
	quote, err := client.GetQuote(tdxQuoteProvider, data)
	if err != nil {
		return err
	}
	return marshalAndWriteBytes(quote, out)
}

func marshalAndWriteBytes(quote any, out io.Writer) error {
	switch q := quote.(type) {
	case *pb.QuoteV4:
		bytes, err := prototext.Marshal(q)
		if err != nil {
			return err
		}
		out.Write(bytes)
		return nil
	default:
		return fmt.Errorf("unsupported quote type: %T", quote)
	}
}

func outWriter() (io.Writer, *os.File, error) {
	if *out == "" {
		return os.Stdout, nil, nil
	}
	file, err := os.Create(*out)
	if err != nil {
		return nil, nil, err
	}
	return file, file, nil
}
func sizedBytes(flag, value string, byteSize int, decode func(string) ([]byte, error)) ([]byte, error) {
	bytes, err := decode(value)
	if err != nil {
		return nil, fmt.Errorf("%s=%s could not be decoded: %v", flag, value, err)
	}
	if len(bytes) > byteSize {
		return nil, fmt.Errorf("%s=%s (%v) is not representable in %d bytes", flag, value, bytes, byteSize)
	}
	sized := make([]byte, byteSize)
	copy(sized, bytes)
	return sized, nil
}
func parseBytes(name string, in io.Reader, inform string, byteSize int) ([]byte, error) {
	inbytes, err := io.ReadAll(in)
	if err != nil {
		return nil, err
	}
	if len(inbytes) == 0 {
		return nil, nil
	}
	inByteStr := strings.TrimSpace(string(inbytes))
	if !utf8.ValidString(inByteStr) {
		return nil, fmt.Errorf("could not decode %s contents as a UTF-8 string", name)
	}
	switch inform {
	case "base64":
		return sizedBytes(name, inByteStr, byteSize, base64.StdEncoding.DecodeString)
	case "hex":
		return sizedBytes(name, inByteStr, byteSize, hex.DecodeString)
	case "auto":
		// "auto" means to try base64 encoding first, then hex.
		if b, err := sizedBytes(name, inByteStr, byteSize, base64.StdEncoding.DecodeString); err == nil {
			return b, nil
		}
		return sizedBytes(name, inByteStr, byteSize, hex.DecodeString)
	default:
		return nil, fmt.Errorf("-inform should be either base64 or hex")
	}
}
func main() {
	flag.Parse()
	logger.Init("", *verbose, false, os.Stderr)
	logger.SetLevel(logger.Level(*verbosity))
	reportData, err := parseBytes("-in", strings.NewReader(*reportDataStr), *inform, labi.TdReportDataSize)
	if err != nil {
		logger.Fatal(err)
	}
	if !(*outform == "bin" || *outform == "textproto") {
		logger.Fatalf("-outform is %s. Expect \"bin\" or \"textproto\"", *outform)
	}
	outwriter, filetoclose, err := outWriter()
	if err != nil {
		logger.Fatalf("failed to open output file: %v", err)
	}
	defer func() {
		if filetoclose != nil {
			filetoclose.Close()
		}
	}()
	var reportData64 [labi.TdReportDataSize]byte
	copy(reportData64[:], reportData)
	if err := outputReport(reportData64, outwriter); err != nil {
		logger.Fatal(err)
	}
}
