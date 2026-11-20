// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.

package rtmr

import (
	"bytes"
	"os"
	"testing"

	"github.com/google/go-tdx-guest/abi"
	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
)

func TestReplayCcelWithTdQuote(t *testing.T) {
	ccelBytes, err := os.ReadFile("../testing/testdata/ccel/ccel_data.dat")
	if err != nil {
		t.Fatal(err)
	}
	tableBytes, err := os.ReadFile("../testing/testdata/ccel/ccel_table.dat")
	if err != nil {
		t.Fatal(err)
	}
	quoteBytes, err := os.ReadFile("../testing/testdata/ccel/cos-113-tdx-quote.dat")
	if err != nil {
		t.Fatal(err)
	}
	nonceBytes, err := os.ReadFile("../testing/testdata/ccel/nonce.dat")
	if err != nil {
		t.Fatal(err)
	}
	option := TdxDefaultOpts(nonceBytes)
	quote, err := abi.QuoteToProto(quoteBytes)
	if err != nil {
		t.Fatal(err)
	}
	ccel, err := ParseCcelWithTdQuote(ccelBytes, tableBytes, quote, &option)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(ccel)
}

func TestGetRtmrsFromTdQuote(t *testing.T) {
	rtmrs := [][]byte{
		bytes.Repeat([]byte{0x00}, 48),
		bytes.Repeat([]byte{0x01}, 48),
		bytes.Repeat([]byte{0x02}, 48),
		bytes.Repeat([]byte{0x03}, 48),
	}
	tooMany := append(append([][]byte{}, rtmrs...), bytes.Repeat([]byte{0x04}, 48))
	tooFew := rtmrs[:3]
	wrongSize := [][]byte{rtmrs[0], rtmrs[1], rtmrs[2], bytes.Repeat([]byte{0x03}, 32)}

	tests := []struct {
		name    string
		quote   any
		want    [][]byte
		wantErr bool
	}{
		{
			name:  "QuoteV4",
			quote: &tdxpb.QuoteV4{TdQuoteBody: &tdxpb.TDQuoteBody{Rtmrs: rtmrs}},
			want:  rtmrs,
		},
		{
			name: "QuoteV5",
			quote: &tdxpb.QuoteV5{TdQuoteBodyDescriptor: &tdxpb.TDQuoteBodyDescriptor{
				TdQuoteBodyV5: &tdxpb.TDQuoteBodyV5{Rtmrs: rtmrs},
			}},
			want: rtmrs,
		},
		{
			name:    "QuoteV4 too many RTMRs",
			quote:   &tdxpb.QuoteV4{TdQuoteBody: &tdxpb.TDQuoteBody{Rtmrs: tooMany}},
			wantErr: true,
		},
		{
			name: "QuoteV5 too many RTMRs",
			quote: &tdxpb.QuoteV5{TdQuoteBodyDescriptor: &tdxpb.TDQuoteBodyDescriptor{
				TdQuoteBodyV5: &tdxpb.TDQuoteBodyV5{Rtmrs: tooMany},
			}},
			wantErr: true,
		},
		{
			name:    "QuoteV4 too few RTMRs",
			quote:   &tdxpb.QuoteV4{TdQuoteBody: &tdxpb.TDQuoteBody{Rtmrs: tooFew}},
			wantErr: true,
		},
		{
			name: "QuoteV5 too few RTMRs",
			quote: &tdxpb.QuoteV5{TdQuoteBodyDescriptor: &tdxpb.TDQuoteBodyDescriptor{
				TdQuoteBodyV5: &tdxpb.TDQuoteBodyV5{Rtmrs: tooFew},
			}},
			wantErr: true,
		},
		{
			name:    "QuoteV4 wrong RTMR size",
			quote:   &tdxpb.QuoteV4{TdQuoteBody: &tdxpb.TDQuoteBody{Rtmrs: wrongSize}},
			wantErr: true,
		},
		{
			name: "QuoteV5 wrong RTMR size",
			quote: &tdxpb.QuoteV5{TdQuoteBodyDescriptor: &tdxpb.TDQuoteBodyDescriptor{
				TdQuoteBodyV5: &tdxpb.TDQuoteBodyV5{Rtmrs: wrongSize},
			}},
			wantErr: true,
		},
		{
			name:    "QuoteV4 missing body",
			quote:   &tdxpb.QuoteV4{},
			wantErr: true,
		},
		{
			name:    "QuoteV5 missing body",
			quote:   &tdxpb.QuoteV5{},
			wantErr: true,
		},
		{
			name:    "unsupported type",
			quote:   "not a quote",
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bank, err := GetRtmrsFromTdQuote(tc.quote)
			if (err != nil) != tc.wantErr {
				t.Fatalf("GetRtmrsFromTdQuote() error = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			if len(bank.RTMRs) != len(tc.want) {
				t.Fatalf("got %d RTMRs, want %d", len(bank.RTMRs), len(tc.want))
			}
			for i, r := range bank.RTMRs {
				if r.Index != i {
					t.Errorf("RTMR[%d].Index = %d, want %d", i, r.Index, i)
				}
				if !bytes.Equal(r.Digest, tc.want[i]) {
					t.Errorf("RTMR[%d].Digest = %x, want %x", i, r.Digest, tc.want[i])
				}
			}
		})
	}
}
