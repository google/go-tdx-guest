// Copyright 2025 Edgeless Systems GmbH
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

package trust_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/go-tdx-guest/verify/trust"
)

// Ensure that the HTTPSGetters implement the expected interfaces.
var (
	_ = trust.HTTPSGetter(&trust.RetryHTTPSGetter{})
	_ = trust.ContextHTTPSGetter(&trust.RetryHTTPSGetter{})
	_ = trust.HTTPSGetter(&trust.SimpleHTTPSGetter{})
	_ = trust.ContextHTTPSGetter(&trust.SimpleHTTPSGetter{})
)

func TestRetryHTTPSGetterContext(t *testing.T) {
	testGetter := &recordingContextGetter{}
	r := &trust.RetryHTTPSGetter{
		MaxRetryDelay: 1 * time.Millisecond,
		Getter:        testGetter,
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	headers, body, err := r.GetContext(ctx, "https://fetch.me")
	if len(headers) > 0 {
		t.Errorf("expected empty headers but got %q", headers)
	}
	if !bytes.Equal(body, []byte("")) {
		t.Errorf("expected empty body but got %q", body)
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected error %q, but got %q", context.Canceled, err)
	}
}

func TestGetWith(t *testing.T) {
	url := ""
	t.Run("HTTPSGetter uses Get", func(t *testing.T) {
		contextGetter := recordingContextGetter{}
		if _, _, err := trust.GetWith(context.Background(), &contextGetter.recordingGetter, url); err != nil {
			t.Fatalf("trust.GetWith returned an unexpected error: %v", err)
		}
		if contextGetter.getContextCalls != 0 {
			t.Errorf("wrong number of calls to GetContext: got %d, want 0", contextGetter.getContextCalls)
		}
		if contextGetter.recordingGetter.getCalls != 1 {
			t.Errorf("wrong number of calls to Get: got %d, want 1", contextGetter.getCalls)
		}
	})
	t.Run("ContextHTTPSGetter uses GetContext", func(t *testing.T) {
		contextGetter := recordingContextGetter{}
		if _, _, err := trust.GetWith(context.Background(), &contextGetter, url); err != nil {
			t.Fatalf("trust.GetWith returned an unexpected error: %v", err)
		}
		if contextGetter.getContextCalls != 1 {
			t.Errorf("wrong number of calls to GetContext: got %d, want 1", contextGetter.getContextCalls)
		}
		if contextGetter.recordingGetter.getCalls != 0 {
			t.Errorf("wrong number of calls to Get: got %d, want 0", contextGetter.getCalls)
		}
	})

}

type recordingGetter struct {
	getCalls int
}

func (r *recordingGetter) Get(_ string) (map[string][]string, []byte, error) {
	r.getCalls++
	return map[string][]string{"Header": {"value"}}, []byte("content"), nil
}

type recordingContextGetter struct {
	recordingGetter
	getContextCalls int
}

func (r *recordingContextGetter) GetContext(ctx context.Context, _ string) (map[string][]string, []byte, error) {
	r.getContextCalls++
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	default:
		return map[string][]string{"Header": {"value"}}, []byte("content"), nil
	}
}
