// Copyright 2025 Google LLC, Takuma IMAMURA
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

// Package main implements a CLI tool for showing Intel TDX quotes.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/google/go-tdx-guest/abi"
	pb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/logger"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
)

var (
	infile = flag.String("in", "-", "Path to the TDX quote to show. Stdin is \"-\".")
	inform = flag.String("inform", "bin", "The input format for the TDX quote. One of \"bin\", \"proto\", \"textproto\".")
	out    = flag.String("out", "", "Path to output file to write attestation report to. "+
		"If unset, outputs to stdout.")
	outform   = flag.String("outform", "textproto", "The format of the output attestation report. Currently only  \"textproto\" is supported.")
	verbosity = flag.Int("verbosity", 0, "The output verbosity. Higher number means more verbose output.")
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
		resultV4 := &pb.QuoteV4{}
		if err := proto.Unmarshal(b, resultV4); err == nil && resultV4.GetHeader() != nil {
			return resultV4, nil
		}
		resultV5 := &pb.QuoteV5{}
		if err := proto.Unmarshal(b, resultV5); err != nil {
			return nil, fmt.Errorf("could not parse %q as proto: %v", *infile, err)
		}
		return resultV5, nil
	case "textproto":
		resultV4 := &pb.QuoteV4{}
		if err := prototext.Unmarshal(b, resultV4); err == nil && resultV4.GetHeader() != nil {
			return resultV4, nil
		}
		resultV5 := &pb.QuoteV5{}
		if err := prototext.Unmarshal(b, resultV5); err != nil {
			return nil, fmt.Errorf("could not parse %q as textproto: %v", *infile, err)
		}
		return resultV5, nil
	default:
		return nil, fmt.Errorf("unknown value -inform=%s", *inform)
	}
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

func marshalAndWriteBytes(quote any, out io.Writer) error {
	mo := prototext.MarshalOptions{
		Multiline: true,
		Indent:    "  ",
		EmitASCII: true,
	}
	switch q := quote.(type) {
	case *pb.QuoteV4:
		bytes, err := mo.Marshal(q)
		if err != nil {
			return err
		}
		if _, err := out.Write(bytes); err != nil {
			return err
		}
		return nil
	case *pb.QuoteV5:
		bytes, err := mo.Marshal(q)
		if err != nil {
			return err
		}
		if _, err := out.Write(bytes); err != nil {
			return err
		}
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

func writeQuote(quote any, out io.Writer) error {
	switch *outform {
	case "textproto":
		return marshalAndWriteBytes(quote, out)
	default:
		return fmt.Errorf("unknown value -outform=%s", *outform)
	}
}

func main() {
	logger.Init("", false, false, os.Stdout)
	flag.Parse()
	logger.SetLevel(logger.Level(*verbosity))

	quote, err := readQuote()
	if err != nil {
		logger.Fatal(err)
	}
	logger.V(1).Info("TDX Quote parsed successfully")

	outwriter, filetoclose, err := outWriter()
	if err != nil {
		logger.Fatalf("failed to open output file: %v", err)
	}
	defer func() {
		if filetoclose != nil {
			filetoclose.Close()
		}
	}()

	err2 := writeQuote(quote, outwriter)
	if err2 != nil {
		logger.Fatal(err2)
	}
}
