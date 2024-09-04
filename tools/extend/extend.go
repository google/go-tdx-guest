// Copyright 2024 Google LLC
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

// Package main implements a CLI tool for extending measurements into RTMR registers.
package main

import (
	"crypto"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/google/go-tdx-guest/rtmr"
	"github.com/google/logger"
)

const (
	// Exit code 1 - tool usage error.
	exitTool = 1
)

var (
	infile    = flag.String("in", "-", "Path to the input event log. Stdin is \"-\".")
	quiet     = flag.Bool("quiet", false, "If true, writes nothing the stdout or stderr. Success is exit code 0, failure exit code 1.")
	verbosity = flag.Int("verbosity", 0, "The output verbosity. Higher number means more verbose output.")
	index     = flag.Int("rtmr", 2, "The rtmr index. Must be 2 or 3. Defaults to 2.")
)

func dieWith(err error, exitCode int) {
	if !*quiet {
		fmt.Fprintf(os.Stderr, "FATAL: %v\n", err)
	}
	os.Exit(exitCode)
}

func die(err error) {
	dieWith(err, exitTool)
}

func readEventLog() ([]byte, error) {
	var in io.Reader
	if *infile == "-" {
		in = os.Stdin
	} else {
		f, err := os.Open(*infile)
		if err != nil {
			return nil, fmt.Errorf("could not open input file %q: %v", *infile, err)
		}
		defer f.Close()
		in = f
	}
	contents, err := io.ReadAll(in)
	if err != nil {
		return nil, fmt.Errorf("could not read %q: %v", *infile, err)
	}
	return contents, nil
}

func main() {
	logger.Init("", false, false, os.Stdout)
	flag.Parse()
	logger.SetLevel(logger.Level(*verbosity))

	eventLog, err := readEventLog()
	if err != nil {
		die(err)
	}
	err = rtmr.ExtendEventLog(*index, crypto.SHA384, eventLog)
	if err != nil {
		die(err)
	}
	if !*quiet {
		logger.V(1).Infof("Extended measurement into rtmr %d successfully", *index)
	}
}
