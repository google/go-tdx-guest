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

// Package trust defines core trust types and values for attestation verification.
package trust

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

// HTTPSGetter represents the ability to fetch data from the internet from an HTTP URL.
type HTTPSGetter interface {
	Get(url string) (map[string][]string, []byte, error)
}

// AttestationRecreationErr represents a problem with fetching or interpreting associated
// API responses for a given API call. This is typically due to network unreliability.
type AttestationRecreationErr struct {
	Msg string
}

func (e *AttestationRecreationErr) Error() string {
	return e.Msg
}

// SimpleHTTPSGetter implements the HTTPSGetter interface with http.Get.
type SimpleHTTPSGetter struct{}

// Get uses http.Get to return the HTTPS response body as a byte array.
func (n *SimpleHTTPSGetter) Get(url string) (map[string][]string, []byte, error) {
	var header map[string][]string

	resp, err := http.Get(url)
	if err != nil {
		return nil, nil, err
	} else if resp.StatusCode >= 300 {
		return nil, nil, fmt.Errorf("failed to retrieve %s, status code received %d", url, resp.StatusCode)
	}

	header = resp.Header

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	resp.Body.Close()
	return header, body, nil
}

// RetryHTTPSGetter is a meta-HTTPS getter that will retry on failure a given number of times.
type RetryHTTPSGetter struct {
	// Timeout is how long to retry before failure.
	Timeout time.Duration
	// MaxRetryDelay is the maximum amount of time to wait between retries.
	MaxRetryDelay time.Duration
	// Getter is the non-retrying way of getting a URL.
	Getter HTTPSGetter
}

// Get fetches the body of the URL, retrying a given amount of times on failure.
func (n *RetryHTTPSGetter) Get(url string) (map[string][]string, []byte, error) {
	delay := 2 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), n.Timeout)
	for {
		header, body, err := n.Getter.Get(url)
		if err == nil {
			cancel()
			return header, body, nil
		}
		delay = delay + delay
		if delay > n.MaxRetryDelay {
			delay = n.MaxRetryDelay
		}
		select {
		case <-ctx.Done():
			cancel()
			return nil, nil, fmt.Errorf("timeout") // context cancelled
		case <-time.After(delay): // wait to retry
		}
	}
}

// DefaultHTTPSGetter returns the library's default getter implementation. It will
// retry slowly.
func DefaultHTTPSGetter() HTTPSGetter {
	return &RetryHTTPSGetter{
		Timeout:       2 * time.Minute,
		MaxRetryDelay: 30 * time.Second,
		Getter:        &SimpleHTTPSGetter{},
	}
}
