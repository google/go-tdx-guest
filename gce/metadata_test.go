// Copyright 2026 Google LLC
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

package gce

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestInstanceInfoFromMetadata(t *testing.T) {
	responses := map[string]string{
		"instance/zone":              "projects/123456789012/zones/us-central1-a",
		"project/project-id":         "test-project",
		"project/numeric-project-id": "123456789012",
		"instance/name":              "test-instance",
		"instance/id":                "112233445566778899",
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Metadata-Flavor"); got != "Google" {
			t.Errorf("Metadata-Flavor request header = %q, want Google", got)
		}
		const prefix = "/computeMetadata/v1/"
		suffix := r.URL.Path[len(prefix):]
		value, ok := responses[suffix]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Metadata-Flavor", "Google")
		fmt.Fprint(w, value)
	}))
	defer server.Close()

	got, err := instanceInfoFromMetadata(context.Background(), server.URL+"/computeMetadata/v1/", server.Client())
	if err != nil {
		t.Fatalf("instanceInfoFromMetadata() failed: %v", err)
	}
	want := &InstanceInfo{
		Zone:          "us-central1-a",
		ProjectID:     "test-project",
		ProjectNumber: 123456789012,
		InstanceName:  "test-instance",
		InstanceID:    112233445566778899,
	}
	if *got != *want {
		t.Errorf("instanceInfoFromMetadata() = %+v, want %+v", got, want)
	}
}

func TestInstanceInfoLogString(t *testing.T) {
	info := &InstanceInfo{
		Zone:          "us-central1-a",
		ProjectID:     "test-project",
		ProjectNumber: 123456789012,
		InstanceName:  "test-instance",
		InstanceID:    112233445566778899,
	}

	got := info.LogString()
	want := "gce_instance=projects/123456789012/zones/us-central1-a/instances/112233445566778899 project_id=test-project instance_name=test-instance"
	if got != want {
		t.Errorf("InstanceInfo.LogString() = %q, want %q", got, want)
	}
}

func TestNilInstanceInfoStrings(t *testing.T) {
	var info *InstanceInfo
	if got := info.ResourceString(); got != "" {
		t.Errorf("nil InstanceInfo.ResourceString() = %q, want empty string", got)
	}
	if got := info.LogString(); got != "<nil>" {
		t.Errorf("nil InstanceInfo.LogString() = %q, want %q", got, "<nil>")
	}
}

func TestInstanceInfoFromMetadataRejectsInvalidProjectNumber(t *testing.T) {
	responses := map[string]string{
		"instance/zone":              "projects/123456789012/zones/us-central1-a",
		"project/project-id":         "test-project",
		"project/numeric-project-id": "not-a-number",
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const prefix = "/computeMetadata/v1/"
		suffix := r.URL.Path[len(prefix):]
		value, ok := responses[suffix]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Metadata-Flavor", "Google")
		fmt.Fprint(w, value)
	}))
	defer server.Close()

	if _, err := instanceInfoFromMetadata(context.Background(), server.URL+"/computeMetadata/v1/", server.Client()); err == nil {
		t.Error("instanceInfoFromMetadata() succeeded, want error")
	}
}

func TestInstanceInfoFromGCEInstance(t *testing.T) {
	got, err := InstanceInfoFromGCEInstance("projects/123456789012/zones/us-central1-a/instances/112233445566778899")
	if err != nil {
		t.Fatalf("InstanceInfoFromGCEInstance() failed: %v", err)
	}
	want := &InstanceInfo{
		Zone:          "us-central1-a",
		ProjectNumber: 123456789012,
		InstanceID:    112233445566778899,
	}
	if *got != *want {
		t.Errorf("InstanceInfoFromGCEInstance() = %+v, want %+v", got, want)
	}
}

func TestInstanceInfoFromGCEInstanceRejectsMalformedInput(t *testing.T) {
	testCases := []struct {
		name  string
		value string
	}{
		{
			name:  "Wrong resource shape",
			value: "projects/123456789012/instances/112233445566778899",
		},
		{
			name:  "Non-numeric project number",
			value: "projects/test-project/zones/us-central1-a/instances/112233445566778899",
		},
		{
			name:  "Non-numeric instance ID",
			value: "projects/123456789012/zones/us-central1-a/instances/test-instance",
		},
		{
			name:  "Empty zone",
			value: "projects/123456789012/zones//instances/112233445566778899",
		},
		{
			name:  "Invalid zone characters",
			value: "projects/123456789012/zones/us_central1-a/instances/112233445566778899",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := InstanceInfoFromGCEInstance(tc.value); err == nil {
				t.Error("InstanceInfoFromGCEInstance() succeeded, want error")
			}
		})
	}
}

func TestResolveInstanceInfoRejectsConflictingSources(t *testing.T) {
	if _, err := ResolveInstanceInfo(context.Background(), "projects/123/zones/us-central1-a/instances/456", true); err == nil {
		t.Error("ResolveInstanceInfo() succeeded with two identity sources, want error")
	}
}

func TestResolveInstanceInfoRejectsMalformedGCEInstance(t *testing.T) {
	_, err := ResolveInstanceInfo(context.Background(), "not-a-resource", false)
	if err == nil {
		t.Fatal("ResolveInstanceInfo() succeeded with malformed instance resource, want error")
	}
	if got, want := err.Error(), "parse GCE instance resource string:"; !strings.Contains(got, want) {
		t.Errorf("ResolveInstanceInfo() error = %q, want prefix %q", got, want)
	}
}

func TestResolveInstanceInfoFromGCEInstance(t *testing.T) {
	got, err := ResolveInstanceInfo(context.Background(), "projects/123/zones/us-central1-a/instances/456", false)
	if err != nil {
		t.Fatalf("ResolveInstanceInfo() failed: %v", err)
	}
	want := &InstanceInfo{
		Zone:          "us-central1-a",
		ProjectNumber: 123,
		InstanceID:    456,
	}
	if *got != *want {
		t.Errorf("ResolveInstanceInfo() = %+v, want %+v", got, want)
	}
}

func TestResolveInstanceInfoUsesMetadataByDefault(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := ResolveInstanceInfo(ctx, "", false)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("ResolveInstanceInfo() error = %v, want %v", err, context.Canceled)
	}
}
