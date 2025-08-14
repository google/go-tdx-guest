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
	_ "crypto/sha512" // To get SHA384 recognized by crypto.Hash.
	"encoding/hex"
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
	// Use the dev-mode-verify flag for developer-specific testing of rtmr sysfs interface.
	devModeVerify = flag.Bool("dev-mode-verify", false, "Enable developer mode to run the RTMR verification test suite. Intended for debugging purposes only.")
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

// runRtmrExtensionTestVerification performs multiple rounds of extending an rtmr and verifies the result.
// It reads the initial state, performs a hardware extension via the sysfs interface, and compares the new
// hardware state against a software-simulated extension to ensure they match.
func runRtmrExtensionTestVerification() {
	// Define test cases for each RTMR and its corresponding hash algorithm.
	testCases := []struct {
		name      string
		rtmrIndex int
		hashAlgo  crypto.Hash
	}{
		{"RTMR0_SHA384", 0, crypto.SHA384},
		{"RTMR1_SHA384", 1, crypto.SHA384},
		{"RTMR2_SHA384", 2, crypto.SHA384},
		{"RTMR3_SHA384", 3, crypto.SHA384},
	}

	overallResult := true // Track the overall success of all verification tests.

	fmt.Println("Starting RTMR extension verification...")

	for _, tc := range testCases {
		fmt.Printf("--- Running verification for %s ---\n", tc.name)
		filePath := fmt.Sprintf("/sys/class/misc/tdx_guest/measurements/rtmr%d:sha384", tc.rtmrIndex)
		digestSize := tc.hashAlgo.Size()

		// Check if the sysfs file for the rtmr exists before proceeding.
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			fmt.Printf("Skipping test: RTMR sysfs file not found at %s\n\n", filePath)
			continue
		}

		casePassed := true
		// Run 10 rounds of extend-and-verify for each rtmr to ensure robustness.
		for i := 0; i < 10; i++ {
			// 1. Read the initial RTMR value from the sysfs file.
			initialData, err := os.ReadFile(filePath)
			if err != nil {
				fmt.Printf("Round %d: failed to read original digest from %s: %v\n", i+1, filePath, err)
				os.Exit(1)
			}

			// 2. Validate the size of the initial data. For a SHA384-based rtmr,
			// the existing value must be a valid SHA384 digest.
			if len(initialData) != crypto.SHA384.Size() {
				fmt.Printf("Round %d: initial data from %s has incorrect size: got %d bytes, want %d bytes\n",
					i+1, filePath, len(initialData), crypto.SHA384.Size())
				os.Exit(1)
			}

			// 3. Start software calculation of the expected measurement.
			hasher := tc.hashAlgo.New()
			hasher.Write(initialData)

			// 4. Generate a random event digest to extend into the rtmr.
			eventDigest := make([]byte, digestSize)
			if _, err := rand.Read(eventDigest); err != nil {
				fmt.Printf("Round %d: error generating random data: %v\n", i+1, err)
				os.Exit(1)
			}

			hasher.Write(eventDigest)
			wantDigest := hasher.Sum(nil)

			// 5. Perform the hardware extension by writing the event digest to the sysfs node.
			if err := rtmr.ExtendDigestSysfs(tc.rtmrIndex, eventDigest); err != nil {
				fmt.Printf("Round %d: error extending RTMR via sysfs: %v\n", i+1, err)
				os.Exit(1)
			}

			// 6. Read the new rtmr value back from the hardware.
			gotDigest, err := os.ReadFile(filePath)
			if err != nil {
				fmt.Printf("Round %d: failed to read back from %s for verification: %v\n", i+1, filePath, err)
				os.Exit(1)
			}

			// 7. Compare the software-calculated value with the actual hardware value.
			if !bytes.Equal(wantDigest, gotDigest) {
				fmt.Printf("Round %d: VERIFICATION FAILED:\n  Expected: %s\n  Got:      %s\n",
					i+1, hex.EncodeToString(wantDigest), hex.EncodeToString(gotDigest))
				overallResult = false
				casePassed = false
			} else {
				fmt.Printf("Round %d: Verification PASSED\n", i+1)
			}
		}
		if casePassed {
			fmt.Printf("--- All rounds for %s PASSED ---\n\n", tc.name)
		} else {
			fmt.Printf("--- Verification for %s FAILED ---\n\n", tc.name)
		}
	}

	if overallResult {
		fmt.Println("=====================================")
		fmt.Println("✅ All verification test cases passed.")
		fmt.Println("=====================================")
		os.Exit(0)
	}

	fmt.Println("=====================================")
	fmt.Println("❌ One or more verification tests FAILED.")
	fmt.Println("=====================================")
	os.Exit(1)
}

func main() {
	logger.Init("", false, false, os.Stdout)
	flag.Parse()
	logger.SetLevel(logger.Level(*verbosity))

	if *devModeVerify {
		runRtmrExtensionTestVerification()
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
