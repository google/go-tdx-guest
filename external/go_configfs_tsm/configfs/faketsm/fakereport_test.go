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

package faketsm

import (
	"bytes"
	"fmt"
	"math/big"
	"path"
	"testing"

	"github.com/google/go-tdx-guest/external/go_configfs_tsm/configfs/configfsi"
	"github.com/google/go-tdx-guest/external/go_configfs_tsm/report"
)

func checkOutblobExpectation(inblob []byte, privlevel uint, outblob []byte) error {
	want := renderOutBlob([]byte(fmt.Sprintf("%d\n", privlevel)), inblob)
	if !bytes.Equal(want, outblob) {
		return fmt.Errorf("got %q, want %q", string(outblob), string(want))
	}
	return nil
}

func makeNonce(id uint) []byte {
	// The nonce is currently expected to always be size 64.
	result := make([]byte, 64)
	copy(result, []byte(big.NewInt(int64(id)).String()))
	return result
}

func checkErr(err error) (bool, error) {
	if err != nil {
		if err := report.GetGenerationErr(err); err != nil {
			return true, nil
		}
		return false, err
	}
	return false, nil
}

func runIteration(t testing.TB, c configfsi.Client, r *report.OpenReport, tc *runner) error {
	t.Helper()
	nonce := makeNonce(tc.id)
	t.Logf("Writing inblob %v", nonce)
	if err := r.WriteOption("inblob", nonce); err != nil {
		return fmt.Errorf("could not write inblob in %d: %v", tc.id, err)
	}
	t.Logf("Writing privlevel %d", (tc.id % 4))
	if err := r.WriteOption("privlevel", []byte(fmt.Sprintf("%d", (tc.id%4)))); err != nil {
		return fmt.Errorf("could not set privlevel: %v", err)
	}
	t.Logf("Reading outblob")
	out, err := r.ReadOption("outblob")
	if done, err := checkErr(err); done || err != nil {
		if err != nil {
			return fmt.Errorf("outblob read on client %d failed: %v", tc.id, err)
		}
		return nil
	}
	t.Logf("Checking outblob %v", out)
	if err := checkOutblobExpectation(nonce, (tc.id % 4), out); err != nil {
		return fmt.Errorf("attestation invariant violated: %v", err)
	}
	return nil
}

type runner struct {
	iterations int
	id         uint
	done       chan int
}

func runInterference(t testing.TB, c configfsi.Client, entryPath string, tc *runner) {
	t.Helper()
	for i := 0; i < tc.iterations; i++ {
		r, err := report.UnsafeWrap(c, entryPath)
		if err != nil {
			t.Errorf("could not create report entry: %v", err)
			tc.done <- 1
			return
		}
		if err := runIteration(t, c, r, tc); err != nil {
			t.Error(err)
			tc.done <- 1
			return
		}
	}
	t.Logf("Posting done for %d", tc.id)
	tc.done <- 0
}

// func runNoninterference(t testing.TB, c configfsi.Client, tc *runner) {
// 	t.Helper()
// 	for i := 0; i < tc.iterations; i++ {
// 		nonce := makeNonce(tc.id)
// 		resp, err := report.Get(c, &report.Request{
// 			InBlob:    nonce,
// 			Privilege: &report.Privilege{Level: (tc.id % 4)},
// 		})
// 		if err == nil {
// 			err = checkOutblobExpectation(nonce, (tc.id % 4), resp.OutBlob)
// 		}
// 		if err != nil {
// 			t.Error(err)
// 			tc.done <- 1
// 			return
// 		}
// 	}
// 	t.Logf("Posting done for %d", tc.id)
// 	tc.done <- 0
// }

// clients-many concurrent routines attempt to get an output on the same entry with
// different inblobs.
func nonceAnonceB(t testing.TB, clients, iterations int) {
	t.Helper()
	c := ReportV7(0)
	entryPath, err := c.MkdirTemp(path.Join(configfsi.TsmPrefix, "report"), "entry")
	if err != nil {
		t.Fatalf("could not create entry: %v", err)
	}
	t.Logf("made entry %s", entryPath)
	defer c.RemoveAll(entryPath)

	complete := make(chan int)
	for i := 0; i < clients; i++ {
		go runInterference(t, c, entryPath, &runner{
			iterations: iterations,
			id:         uint(i),
			done:       complete})
	}
	// Each client should write to the channel.
	for i := 0; i < clients; i++ {
		code := <-complete
		if code == 1 {
			t.Fatalf("early failure")
		}
	}
	t.Logf("doooone")
}

// func noninterferenceByDesign(t testing.TB, clients, iterations int) {
// 	t.Helper()
// 	c := ReportV7(0)
// 	complete := make(chan int)
// 	for i := 0; i < clients; i++ {
// 		go runNoninterference(t, c, &runner{
// 			iterations: iterations,
// 			id:         uint(i),
// 			done:       complete})
// 	}
// 	// Each client should write to the channel.
// 	for i := 0; i < clients; i++ {
// 		code := <-complete
// 		if code == 1 {
// 			t.Fatalf("early failure")
// 		}
// 	}
// }

func BenchmarkReportGenerationInterference(b *testing.B) {
	nonceAnonceB(b, 4, b.N)
}

func BenchmarkReportGenerationNoninterference(b *testing.B) {
	nonceAnonceB(b, 20, b.N)
}
