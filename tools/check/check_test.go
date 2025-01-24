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
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"testing"

	ccpb "github.com/google/go-tdx-guest/proto/checkconfig"
	"github.com/google/logger"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// Returns true if the test should be skipped for the protobuf case since the field
// can't be set to the expected value.
type setterFn func(p *ccpb.Policy, value string, t *testing.T) bool

// Represents a test case that will set a flag or config field to a good or bad value.
// We use this data to check that
//
//   - flags alone lead to expected check success or failure,
//   - a config alone leads to expected check success or failure,
//   - a config set to a bad value and a flag set to a good value leads
//     to an expected override and success.
//   - a config set to a good value and a flag set to a bad value leads
//     to an expected override and failure.
type testCase struct {
	flag   string
	good   string
	bad    []string
	setter setterFn
}

var check string

func TestMain(m *testing.M) {
	if output, err := exec.Command("go", "build", "-buildvcs=false", ".").CombinedOutput(); err != nil {
		die(fmt.Errorf("could not build check tool: %v, %s", err, output))
	}
	check = "./check"

	logger.Init("CheckTestLog", false, false, os.Stderr)

	code := m.Run()
	// Cleanup `check` binary after all tests are done.
	os.Remove("check")
	os.Exit(code)
}

func withBaseArgs(config string, args ...string) []string {
	base := []string{
		"-in", "../../testing/testdata/tdx_prod_quote_SPR_E4.dat",
		"-test_local_getter",
	}

	if config != "" {
		base = append(base, fmt.Sprintf("-config=%s", config))
	}
	result := make([]string, len(args)+len(base))
	copy(result, base)
	copy(result[len(base):], args)
	return result
}

func setField(p *ccpb.Policy, policy string, name string, value any) {
	if policy == "header_policy" {
		s := p.HeaderPolicy
		r := s.ProtoReflect()
		ty := r.Descriptor()
		r.Set(ty.Fields().ByName(protoreflect.Name(name)), protoreflect.ValueOf(value))
	} else if policy == "td_quote_body_policy" {
		s := p.TdQuoteBodyPolicy
		r := s.ProtoReflect()
		ty := r.Descriptor()
		r.Set(ty.Fields().ByName(protoreflect.Name(name)), protoreflect.ValueOf(value))
	}
}

func bytesSetter(name string, policy string) setterFn {
	return func(p *ccpb.Policy, value string, _ *testing.T) bool {
		v, err := hex.DecodeString(value)
		if err != nil {
			return true
		}
		setField(p, policy, name, v)
		return false
	}
}

func uint32setter(name string, policy string) setterFn {
	return func(p *ccpb.Policy, value string, _ *testing.T) bool {
		u, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return true
		}
		setField(p, policy, name, uint32(u))
		return false
	}
}

func testCases() []testCase {
	return []testCase{
		{
			flag: "minimum_qe_svn",
			good: "0",
			bad: []string{
				"1",
				"21",
				"666666",
			},
			setter: uint32setter("minimum_qe_svn", "header_policy"),
		},
		{
			flag: "minimum_pce_svn",
			good: "0",
			bad: []string{
				"121",    // right size
				"666666", // wrong size
			},
			setter: uint32setter("minimum_pce_svn", "header_policy"),
		},
		{
			flag:   "qe_vendor_id",
			good:   "939a7233f79c4ca9940a0db3957f0607",
			bad:    []string{"00000000000000000000000000000001"},
			setter: bytesSetter("qe_vendor_id", "header_policy"),
		},
		{
			flag:   "minimum_tee_tcb_svn",
			good:   "03000400000000000000000000000000",
			bad:    []string{"03000400000000000000000000000011"},
			setter: bytesSetter("minimum_tee_tcb_svn", "td_quote_body_policy"),
		},
		{
			flag: "mr_seam",
			good: "2fd279c16164a93dd5bf373d834328d46008c2b693af9ebb865b08b2ced320c9a89b4869a9fab60fbe9d0c5a5363c656",
			bad: []string{
				"2fd279c16164a93dd5bf373d834328d46008c2b693af9ebb865b08b2ced320c9a89b4869a9fab60fbe9d0c5a5363c326"},
			setter: bytesSetter("mr_seam", "td_quote_body_policy"),
		},
		{
			flag:   "td_attributes",
			good:   "0000004000000000",
			bad:    []string{"0000004000000011"},
			setter: bytesSetter("td_attributes", "td_quote_body_policy"),
		},
		{
			flag:   "xfam",
			good:   "e71a060000000000",
			bad:    []string{},
			setter: bytesSetter("xfam", "td_quote_body_policy"),
		},
		{
			flag: "mr_td",
			good: "6363b8043668a3ad953278e10389574d326c6749fb78aa810ecd9336923db86f22fc00b8dcd404bc10d5e119d7215cbb",
			bad: []string{
				"6363b8043668a3ad953278e10389574d326c6749fb78aa810ecd9336923db86f22fc00b8dcd404bc10d5e119d1115cbb",
				"6363b8000000a3ad953278e10389574d326c6749fb78aa810ecd9336923db86f22fc00b8dcd404bc10d5e119d7215cbb",
			},
			setter: bytesSetter("mr_td", "td_quote_body_policy"),
		},
		{
			flag:   "mr_config_id",
			good:   "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			bad:    []string{"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000011"},
			setter: bytesSetter("mr_config_id", "td_quote_body_policy"),
		},
		{
			flag:   "mr_owner",
			good:   "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			bad:    []string{"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000022"},
			setter: bytesSetter("mr_owner", "td_quote_body_policy"),
		},
		{
			flag:   "mr_owner_config",
			good:   "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			bad:    []string{"0", "not a hex"},
			setter: bytesSetter("mr_owner_config", "td_quote_body_policy"),
		},
		{
			flag:   "report_data",
			good:   "6c62dec1b8191749a31dab490be532a35944dea47caef1f980863993d9899545eb7406a38d1eed313b987a467dacead6f0c87a6d766c66f6f29f8acb281f1113",
			bad:    []string{"6c62dec1b8191749a31dab490be532a35944dea47caef1f980863993d9899545eb7406a38d1eed313b987a467dacead6f0c87a6d766c66f6f29f8acb281f2213"},
			setter: bytesSetter("report_data", "td_quote_body_policy"),
		},
	}
}

// Writes contents to a file that the runner gets a path to and can use, then deletes the file.
func withTempFile(contents []byte, t *testing.T, runner func(path string)) {
	file, err := os.CreateTemp(".", "temp")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(file.Name())

	n, err := file.Write(contents)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(contents) {
		t.Fatalf("incomplete write to %q. Wrote %d, want %d", file.Name(), n, len(contents))
	}
	runner(file.Name())
}

func withTestConfig(p *ccpb.Policy, t *testing.T, runner func(path string)) {
	config := &ccpb.Config{Policy: p}

	out, err := proto.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	withTempFile(out, t, runner)
}

func TestCheckGoodFlags(t *testing.T) {
	for _, tc := range testCases() {
		// Singular good flag
		t.Run(tc.flag, func(t *testing.T) {
			cmd := exec.Command(check, withBaseArgs("", fmt.Sprintf("-%s=%s", tc.flag, tc.good))...)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Errorf("%s failed unexpectedly: %v (%s)", cmd, err, output)
			}
		})
	}
}

func TestCheckBadFlags(t *testing.T) {
	for _, tc := range testCases() {
		// Singular bad flags
		for i, bad := range tc.bad {
			t.Run(fmt.Sprintf("%s[%d]", tc.flag, i+1), func(t *testing.T) {
				cmd := exec.Command(check, withBaseArgs("", fmt.Sprintf("-%s=%s", tc.flag, bad))...)
				if output, err := cmd.CombinedOutput(); err == nil {
					t.Errorf("%s succeeded unexpectedly: %s", cmd, output)
				}
			})
		}
	}
}

func TestRtmrs(t *testing.T) {
	validRtmrs := []string{
		"2927da70461cd63266f43230cc1849c03ef25ebe490062a801d8fcc80af42976823adf08f833c1e50b51779c6593f32a,2c700b8ba9b85783f8be9fb9443647bdc0bb3c50747f06297cc6538c25a5f589c4b56d035c59107c6bc5800db2cacb61,8652f0caaba7e215ea442dc36a4499d8fec3362f3a0b2ca151cbe4b3e6466fe59c7368b3c2287fc7c3bf5c924eb4424e,000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		"2927da70461cd63266f43230cc1849c03ef25ebe490062a801d8fcc80af42976823adf08f833c1e50b51779c6593f32a,2c700b8ba9b85783f8be9fb9443647bdc0bb3c50747f06297cc6538c25a5f589c4b56d035c59107c6bc5800db2cacb61,,",
		",,,000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	}
	invalidRtmrs := []string{
		",", "0,0,0,0", "0,0,",
	}
	for _, tc := range validRtmrs {
		t.Run("valid_rtmrs", func(t *testing.T) {
			cmd := exec.Command(check, withBaseArgs("", fmt.Sprintf("-%s=%s", "rtmrs", tc))...)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Errorf("%s failed unexpectedly: %v (%s)", cmd, err, output)
			}
		})
	}

	for _, tc := range invalidRtmrs {
		t.Run("invalid_rtmrs", func(t *testing.T) {
			cmd := exec.Command(check, withBaseArgs("", fmt.Sprintf("-%s=%s", "rtmrs", tc))...)
			if output, err := cmd.CombinedOutput(); err == nil {
				t.Errorf("%s succeeded unexpectedly: %s", cmd, output)
			}
		})
	}
}

func TestCheckGoodFields(t *testing.T) {
	for _, tc := range testCases() {
		t.Run(tc.flag, func(t *testing.T) {
			p := &ccpb.Policy{HeaderPolicy: &ccpb.HeaderPolicy{}, TdQuoteBodyPolicy: &ccpb.TDQuoteBodyPolicy{}}
			if tc.setter(p, tc.good, t) {
				t.Fatal("unexpected parse failure")
			}
			withTestConfig(p, t, func(path string) {
				cmd := exec.Command(check, withBaseArgs(path)...)
				if output, err := cmd.CombinedOutput(); err != nil {
					t.Errorf("%s (%v) failed unexpectedly: %v, %s", cmd, p, err, output)
				}
			})
		})
	}
}

func TestCheckBadFields(t *testing.T) {
	for _, tc := range testCases() {
		for i, bad := range tc.bad {
			t.Run(fmt.Sprintf("%s_bad[%d]", tc.flag, i+1), func(t *testing.T) {
				p := &ccpb.Policy{HeaderPolicy: &ccpb.HeaderPolicy{}, TdQuoteBodyPolicy: &ccpb.TDQuoteBodyPolicy{}}
				if tc.setter(p, bad, t) {
					return
				}
				withTestConfig(p, t, func(path string) {
					cmd := exec.Command(check, withBaseArgs(path)...)
					if output, err := cmd.CombinedOutput(); err == nil {
						t.Errorf("%s (%v) succeeded unexpectedly: %s", cmd, p, output)
					}
				})
			})
		}
	}
}

func TestCheckGoodFlagOverridesBadField(t *testing.T) {
	for _, tc := range testCases() {
		for i, bad := range tc.bad {
			t.Run(fmt.Sprintf("%s_bad[%d]", tc.flag, i+1), func(t *testing.T) {
				p := &ccpb.Policy{HeaderPolicy: &ccpb.HeaderPolicy{}, TdQuoteBodyPolicy: &ccpb.TDQuoteBodyPolicy{}}
				if tc.setter(p, bad, t) {
					return
				}
				withTestConfig(p, t, func(path string) {
					cmd := exec.Command(check, withBaseArgs(path, fmt.Sprintf("-%s=%s", tc.flag, tc.good))...)
					if output, err := cmd.CombinedOutput(); err != nil {
						t.Errorf("%s (%v) failed unexpectedly: %v, %s", cmd, p, err, output)
					}
				})
			})
		}
	}
}

func TestCheckBadFlagOverridesGoodField(t *testing.T) {
	for _, tc := range testCases() {
		for i, bad := range tc.bad {
			t.Run(fmt.Sprintf("%s_bad[%d]", tc.flag, i+1), func(t *testing.T) {
				p := &ccpb.Policy{HeaderPolicy: &ccpb.HeaderPolicy{}, TdQuoteBodyPolicy: &ccpb.TDQuoteBodyPolicy{}}
				if tc.setter(p, tc.good, t) {
					t.Fatal("unexpected parse failure")
				}
				withTestConfig(p, t, func(path string) {
					cmd := exec.Command(check, withBaseArgs(path, fmt.Sprintf("-%s=%s", tc.flag, bad))...)
					if output, err := cmd.CombinedOutput(); err == nil {
						t.Errorf("%s (%v) succeeded unexpectedly: %s", cmd, p, output)
					}
				})
			})
		}
	}
}

func TestNetworkFlags(t *testing.T) {
	// check_crl = true should fail if get_collateral = false
	cmd := exec.Command(check, withBaseArgs("", fmt.Sprintf("-%s=%s", "check_crl", "true"))...)
	if output, err := cmd.CombinedOutput(); err == nil {
		t.Errorf("%s check_crl flag succeeded unexpectedly: %v, %s", cmd, err, output)
	}
}

func TestCaBundles(t *testing.T) {
	correctPath := []string{"../../verify/trusted_root.pem",
		"../../verify/trusted_root.pem,../../verify/trusted_root.pem"}
	fakePath := []string{"fake_path"}

	for _, path := range correctPath {
		cmd := exec.Command(check, withBaseArgs("", fmt.Sprintf("-%s=%s", "trusted_roots", path))...)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("%s correct path for trusted roots failed unexpectedly: %v, %s", cmd, err, output)
		}
	}
	for _, path := range fakePath {
		cmd := exec.Command(check, withBaseArgs("", fmt.Sprintf("-%s=%s", "trusted_roots", path))...)
		if output, err := cmd.CombinedOutput(); err == nil {
			t.Errorf("%s fake path for trusted roots succeeded unexpectedly: %s", cmd, output)
		}
	}
}
