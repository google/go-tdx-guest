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

// Package main implements a CLI tool for parsing CCEL event logs in a human-readable format.
package main

import (
	"crypto"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/google/go-eventlog/register"
	"github.com/google/go-eventlog/tcg"
	"github.com/google/logger"
	"google.golang.org/protobuf/encoding/prototext"

	pb "github.com/google/go-eventlog/proto/state"
)

var (
	infile = flag.String("in", "/sys/firmware/acpi/tables/data/CCEL", "Path to the CCEL event log to parse.")
	out    = flag.String("out", "", "Path to output file to write parsed event logs to. The output file will be in a textproto format"+
		"If unset, outputs to stdout.")
	verbose   = flag.Bool("v", false, "Enable verbose logging.")
	verbosity = flag.Int("verbosity", 0, "The output verbosity. Higher number means more verbose output")
)

func readCCEL() ([]byte, error) {
	file, err := os.Open(*infile)
	if err != nil {
		return nil, fmt.Errorf("could not open %q: %v", *infile, err)
	}

	defer func() {
		if file != nil {
			file.Close()
		}
	}()

	contents, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("could not read %q: %v", *infile, err)
	}
	return contents, nil
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

func outputEventLog(events []*pb.Event, out io.Writer) error {
	mo := prototext.MarshalOptions{
		Multiline: true,
		Indent:    " ",
		EmitASCII: true,
	}

	var bytes []byte
	var err error
	for _, event := range events {
		bytes, err = mo.MarshalAppend(bytes, event)
		if err != nil {
			return err
		}
		bytes = append(bytes, []byte("\n")...)
	}
	out.Write(bytes)
	return nil
}

func main() {
	flag.Parse()
	logger.Init("", *verbose, false, os.Stderr)
	logger.SetLevel(logger.Level(*verbosity))

	rawEventLog, err := readCCEL()
	if err != nil {
		logger.Fatal(err)
	}

	eventlog, err := tcg.ParseEventLog(rawEventLog, tcg.ParseOpts{AllowPadding: true})
	if err != nil {
		logger.Fatalf("Failed to parse CCEL event log: %v", err)
	}

	// RTMR uses SHA384 to hash
	events := tcg.ConvertToPbEvents(crypto.SHA384, eventlog.Events(register.HashSHA384))

	outwriter, filetoclose, err := outWriter()
	if err != nil {
		logger.Fatalf("Failed to open output file: %v", err)
	}
	defer func() {
		if filetoclose != nil {
			filetoclose.Close()
		}
	}()

	if err := outputEventLog(events, outwriter); err != nil {
		logger.Fatal(err)
	}
}
