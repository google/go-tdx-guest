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

package configfsi

import (
	"crypto/rand"
	"strings"
	"testing"
)

func TestTsmPathString(t *testing.T) {
	tcs := []struct {
		input *TsmPath
		want  string
	}{
		{input: &TsmPath{}, want: "/sys/kernel/config/tsm"},
		{input: &TsmPath{Subsystem: "rebort"}, want: "/sys/kernel/config/tsm/rebort"},
		{
			input: &TsmPath{Subsystem: "repart", Entry: "j"},
			want:  "/sys/kernel/config/tsm/repart/j",
		},
		{
			input: &TsmPath{Subsystem: "report", Entry: "r", Attribute: "inblob"},
			want:  "/sys/kernel/config/tsm/report/r/inblob",
		},
	}
	for _, tc := range tcs {
		got := tc.input.String()
		if got != tc.want {
			t.Errorf("%v.String() = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func match(err error, want string) bool {
	if err == nil && want == "" {
		return true
	}
	return (err != nil && want != "" && strings.Contains(err.Error(), want))
}

func TestParseTsmPath(t *testing.T) {
	tcs := []struct {
		input   string
		want    *TsmPath
		wantErr string
	}{
		{
			input:   "not/to/configfs",
			wantErr: `"not/to/configfs" does not begin with "/sys/kernel/config/tsm"`,
		},
		{
			input:   "///sys/kernel/config/tsm",
			wantErr: `"/sys/kernel/config/tsm" does not contain a subsystem`,
		},
		{
			input:   "/sys/kernel/config/tsm/report/is/way/too/long",
			wantErr: `"report/is/way/too/long" suffix expected to be of form`,
		},
		{
			input: "/sys/kernel/config/tsm/a",
			want:  &TsmPath{Subsystem: "a"},
		},
		{
			input: "/sys/kernel/config/tsm/a/b",
			want:  &TsmPath{Subsystem: "a", Entry: "b"},
		},
		{
			input: "/sys/kernel/config/tsm/a/b/c",
			want:  &TsmPath{Subsystem: "a", Entry: "b", Attribute: "c"},
		},
	}
	for _, tc := range tcs {
		got, err := ParseTsmPath(tc.input)
		if !match(err, tc.wantErr) {
			t.Errorf("ParseTsmPath(%q) = %v, %v errored unexpectedly. Want %s",
				tc.input, got, err, tc.wantErr)
		}
		if tc.wantErr == "" && *got != *tc.want {
			t.Errorf("ParseTsmPath(%q) = %v, nil. Want %v", tc.input, *got, *tc.want)
		}
	}
}

func TestTempName(t *testing.T) {
	tcs := []struct {
		name       string
		pattern    string
		wantPrefix string
		wantSuffix string
	}{
		{name: "empty"},
		{
			name:       "no asterisk",
			pattern:    "hi",
			wantPrefix: "hi",
		},
		{name: "1 asterisk at end",
			pattern:    "friend*",
			wantPrefix: "friend",
		},
		{name: "many asterisks",
			pattern:    "friend*ly*monster",
			wantPrefix: "friend*ly",
			wantSuffix: "monster",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			got := TempName(rand.Reader, tc.pattern)
			wantReplaceLen := len(tc.pattern) + randomPathSize
			if strings.LastIndex(tc.pattern, "*") != -1 {
				wantReplaceLen-- // The * gets replaced, so subtract it.
			}
			if len(got) != wantReplaceLen {
				t.Errorf("TempName(_, %q) = %q, whose length is not %d", tc.pattern, got, wantReplaceLen)
			}
			if !strings.HasPrefix(got, tc.wantPrefix) {
				t.Errorf("TempName(_, %q) = %q, does not have prefix %q", tc.pattern, got, tc.wantPrefix)
			}
			if !strings.HasSuffix(got, tc.wantSuffix) {
				t.Errorf("TempName(_, %q) = %q, does not have suffix %q", tc.pattern, got, tc.wantSuffix)
			}
		})
	}

}
