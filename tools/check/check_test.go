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

package main

import (
	"fmt"
	"os"
	"os/exec"
	"testing"

	"github.com/google/logger"
)

type testCase struct {
	cmd []string
}

var check string

func TestMain(m *testing.M) {
	if output, err := exec.Command("go", "build", "-buildvcs=false", ".").CombinedOutput(); err != nil {
		die(fmt.Errorf("could not build check tool: %v, %s", err, output))
	}
	check = "./check"

	logger.Init("CheckTestLog", false, false, os.Stderr)
	os.Exit(m.Run())
}

func withBaseArgs(args []string) []string {
	base := []string{
		"-in", "../../testing/testdata/tdx_prod_quote_SPR_E4.dat",
		"-test_local_getter",
	}

	result := make([]string, len(args)+len(base))
	copy(result, base)
	copy(result[len(base):], args)
	return result
}

func goodTestCases() []testCase {
	return []testCase{
		{
			cmd: []string{},
		},
	}
}

func badTestCases() []testCase {
	return []testCase{
		{
			// -get_collateral is false (default value), but -check_crl is true
			cmd: []string{"-check_crl=true"},
		},
	}
}

func TestCheckGoodFlags(t *testing.T) {
	for _, tc := range goodTestCases() {
		// Singular good flag
		t.Run("", func(t *testing.T) {
			cmd := exec.Command(check, withBaseArgs(tc.cmd)...)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Errorf("%s failed unexpectedly: %v (%s)", cmd, err, output)
			}
		})
	}
}

func TestCheckBadFlags(t *testing.T) {
	for _, tc := range badTestCases() {
		// Singular bad flag
		t.Run("", func(t *testing.T) {
			cmd := exec.Command(check, withBaseArgs(tc.cmd)...)
			if output, err := cmd.CombinedOutput(); err == nil {
				t.Errorf("%s succeeded unexpectedly: %s", cmd, output)
			}
		})
	}
}
