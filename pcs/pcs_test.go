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
	want := TdxBaseURL + "/tcb?fmspc=50806f000000"
	fmspcBytes := []byte{80, 128, 111, 0, 0, 0}
	fmspc := hex.EncodeToString(fmspcBytes)
	if got := TcbInfoURL(fmspc); got != want {
		t.Errorf("TcbInfoURL(%q) = %q. Expected %q", fmspc, got, want)
	}
}

func TestQeIdentityURL(t *testing.T) {
	want := TdxBaseURL + "/qe/identity"
	if got := QeIdentityURL(); got != want {
		t.Errorf("QEIdentityURL() = %q. Expected %q", got, want)
	}
}
