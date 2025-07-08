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
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
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
	verify    = flag.Bool("verify", false, "Runs a loop of 10 random extensions and verifies the result against a software simulation.")
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

// runVerificationLoop performs 10 rounds of extending an RTMR with random data,
// verifying that the hardware extension matches a software simulation.
func runVerificationLoop(filePath string, hashAlgo crypto.Hash, digestSize int) error {
	for i := 0; i < 10; i++ {
		// Read the digest before extension.
		initialData, err := ioutil.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("failed to read original digest from %s: %w", filePath, err)
		}
		fmt.Printf("read back original digest: %s\n", hex.EncodeToString(initialData))

		// Create the software hasher and prime it with the initial digest.
		hasher := hashAlgo.New()
		hasher.Write(initialData)

		// Create a random event to extend.
		eventData := make([]byte, digestSize)
		if _, err := rand.Read(eventData); err != nil {
			return fmt.Errorf("error generating random data: %w", err)
		}

		fmt.Printf("\nExtension #%d:\n", i+1)
		fmt.Printf("  - Random Event Data (hex): %s\n", hex.EncodeToString(eventData))

		// Perform the hardware extension by writing the event data to the device.
		if err := ioutil.WriteFile(filePath, eventData, 0644); err != nil {
			return fmt.Errorf("error writing to file %s: %w", filePath, err)
		}

		// Read the new digest back from the hardware.
		readDigest, err := ioutil.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("failed to read back from %s for verification: %w", filePath, err)
		}

		// Perform the software extension.
		hasher.Write(eventData)
		expectedDigest := hasher.Sum(nil)

		// Verify that the hardware result matches the software simulation.
		fmt.Printf("expected value: %s\n", hex.EncodeToString(expectedDigest))
		fmt.Printf("read back value: %s\n", hex.EncodeToString(readDigest))
		if !bytes.Equal(expectedDigest, readDigest) {
			return fmt.Errorf("verification failed: hardware and software digests do not match for %s", filePath)
		}
		fmt.Printf("Successfully verified extension for %s in test round %d\n", filePath, i+1)
	}
	return nil
}

func main() {
	logger.Init("", false, false, os.Stdout)
	flag.Parse()
	logger.SetLevel(logger.Level(*verbosity))

	if *verify {
		filePath := fmt.Sprintf("/sys/class/misc/tdx_guest/measurements/rtmr%d:sha384", *index)
		const hashAlgo = crypto.SHA384
		const digestSize = sha512.Size384
		fmt.Println("\n--- Looping 10 times with random value extensions, write and read back the digest for comparison---")
		if err := runVerificationLoop(filePath, hashAlgo, digestSize); err != nil {
			fmt.Fprintf(os.Stderr, "Verification failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("All verification rounds passed successfully.")
		return
	}
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
