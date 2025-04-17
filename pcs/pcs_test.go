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

package pcs

import (
	"encoding/hex"
	"testing"
)

func TestPckCrlURL(t *testing.T) {
	want := SgxBaseURL + "/pckcrl?ca=platform&encoding=der"

	if got := PckCrlURL("platform"); got != want {
		t.Errorf(`PckCrlURL("platform") = %q. Expected %q`, got, want)
	}
}

func TestTcbInfoURL(t *testing.T) {
	fmspcBytes := []byte{80, 128, 111, 0, 0, 0}
	fmspc := hex.EncodeToString(fmspcBytes)

	testCases := []struct {
		name          string
		updateChannel CollateralUpdate
		wantUrl       string
	}{
		{
			name:          "success with standard access",
			updateChannel: CollateralUpdateStandard,
			wantUrl:       TdxBaseURL + "/tcb?fmspc=50806f000000&update=standard",
		},
		{
			name:          "success with early access",
			updateChannel: CollateralUpdateEarly,
			wantUrl:       TdxBaseURL + "/tcb?fmspc=50806f000000&update=early",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := TcbInfoURL(fmspc, tc.updateChannel); got != tc.wantUrl {
				t.Errorf("TcbInfoURL(%q) = %q. Expected %q", fmspc, got, tc.wantUrl)
			}
		})
	}
}

func TestQeIdentityURL(t *testing.T) {
	testCases := []struct {
		name          string
		updateChannel CollateralUpdate
		wantUrl       string
	}{
		{
			name:          "success with standard access",
			updateChannel: CollateralUpdateStandard,
			wantUrl:       TdxBaseURL + "/qe/identity?update=standard",
		},
		{
			name:          "success with early access",
			updateChannel: CollateralUpdateEarly,
			wantUrl:       TdxBaseURL + "/qe/identity?update=early",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := QeIdentityURL(tc.updateChannel); got != tc.wantUrl {
				t.Errorf("QEIdentityURL() = %q. Expected %q", got, tc.wantUrl)
			}
		})
	}
}
