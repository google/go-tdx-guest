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

// Package gce contains Google Compute Engine helpers for TDX guests.
package gce

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const defaultMetadataBaseURL = "http://metadata.google.internal/computeMetadata/v1/"

var (
	defaultMetadataHTTPClient = &http.Client{Timeout: 2 * time.Second}
	gceInstancePattern        = regexp.MustCompile(`^projects/([^/]*)/zones/([^/]*)/instances/([^/]*)$`)
)

// InstanceInfo identifies the GCE VM described by the metadata server.
type InstanceInfo struct {
	Zone          string
	ProjectID     string
	ProjectNumber uint64
	InstanceName  string
	InstanceID    uint64
}

// ResourceString returns the canonical GCE instance resource string when the
// numeric project and instance IDs are available.
func (i *InstanceInfo) ResourceString() string {
	if i == nil {
		return ""
	}
	return fmt.Sprintf("projects/%d/zones/%s/instances/%d", i.ProjectNumber, i.Zone, i.InstanceID)
}

// LogString returns a compact, stable representation of the collected instance
// identity used for CLI diagnostics.
func (i *InstanceInfo) LogString() string {
	if i == nil {
		return "<nil>"
	}
	parts := []string{
		fmt.Sprintf("gce_instance=%s", i.ResourceString()),
	}
	if i.ProjectID != "" {
		parts = append(parts, fmt.Sprintf("project_id=%s", i.ProjectID))
	}
	if i.InstanceName != "" {
		parts = append(parts, fmt.Sprintf("instance_name=%s", i.InstanceName))
	}
	return strings.Join(parts, " ")
}

// ResolveInstanceInfo returns GCE instance identity from either an explicit
// resource string or the metadata server. When gceInstance is empty, metadata is
// used by default; mdsRequested exists to reject callers that explicitly request
// metadata while also providing an instance resource.
func ResolveInstanceInfo(ctx context.Context, gceInstance string, mdsRequested bool) (*InstanceInfo, error) {
	if gceInstance != "" && mdsRequested {
		return nil, errors.New("set only one GCE instance identity source")
	}
	if gceInstance != "" {
		info, err := InstanceInfoFromGCEInstance(gceInstance)
		if err != nil {
			return nil, fmt.Errorf("parse GCE instance resource string: %w", err)
		}
		return info, nil
	}
	info, err := InstanceInfoFromMetadata(ctx)
	if err != nil {
		return nil, fmt.Errorf("resolve GCE instance identity from metadata server: %w", err)
	}
	return info, nil
}

// InstanceInfoFromGCEInstance parses a GCE instance resource string in the form
// projects/<project-number>/zones/<zone>/instances/<instance-id>.
func InstanceInfoFromGCEInstance(value string) (*InstanceInfo, error) {
	matches := gceInstancePattern.FindStringSubmatch(strings.TrimSpace(value))
	if matches == nil {
		return nil, fmt.Errorf("GCE instance must be in form projects/<project-number>/zones/<zone>/instances/<instance-id>")
	}
	projectNumber, err := parseUintField("project number", matches[1])
	if err != nil {
		return nil, err
	}
	zone := matches[2]
	if err := validateZone(zone); err != nil {
		return nil, fmt.Errorf("GCE instance %w", err)
	}
	instanceID, err := parseUintField("instance ID", matches[3])
	if err != nil {
		return nil, err
	}
	return &InstanceInfo{
		Zone:          zone,
		ProjectNumber: projectNumber,
		InstanceID:    instanceID,
	}, nil
}

// InstanceInfoFromMetadata reads GCE instance identity from the metadata server.
func InstanceInfoFromMetadata(ctx context.Context) (*InstanceInfo, error) {
	return instanceInfoFromMetadata(ctx, defaultMetadataBaseURL, defaultMetadataHTTPClient)
}

func instanceInfoFromMetadata(ctx context.Context, baseURL string, client *http.Client) (*InstanceInfo, error) {
	if client == nil {
		client = defaultMetadataHTTPClient
	}
	zone, err := getMetadata(ctx, client, baseURL, "instance/zone")
	if err != nil {
		return nil, fmt.Errorf("fetch zone from metadata server: %w", err)
	}
	projectID, err := getMetadata(ctx, client, baseURL, "project/project-id")
	if err != nil {
		return nil, fmt.Errorf("fetch project ID from metadata server: %w", err)
	}
	projectNumber, err := getMetadataUint(ctx, client, baseURL, "project/numeric-project-id")
	if err != nil {
		return nil, err
	}
	instanceName, err := getMetadata(ctx, client, baseURL, "instance/name")
	if err != nil {
		return nil, fmt.Errorf("fetch instance name from metadata server: %w", err)
	}
	instanceID, err := getMetadataUint(ctx, client, baseURL, "instance/id")
	if err != nil {
		return nil, err
	}

	return &InstanceInfo{
		Zone:          lastMetadataPathComponent(zone),
		ProjectID:     projectID,
		ProjectNumber: projectNumber,
		InstanceName:  instanceName,
		InstanceID:    instanceID,
	}, nil
}

func getMetadataUint(ctx context.Context, client *http.Client, baseURL, suffix string) (uint64, error) {
	value, err := getMetadata(ctx, client, baseURL, suffix)
	if err != nil {
		return 0, fmt.Errorf("fetch %s from metadata server: %w", suffix, err)
	}
	return parseUintField("metadata "+suffix, value)
}

func getMetadata(ctx context.Context, client *http.Client, baseURL, suffix string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataURL(baseURL, suffix), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("metadata server returned %s for %s", resp.Status, suffix)
	}
	if resp.Header.Get("Metadata-Flavor") != "Google" {
		return "", fmt.Errorf("metadata server response for %s missing Metadata-Flavor: Google", suffix)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(body))
	if value == "" {
		return "", fmt.Errorf("metadata server returned empty value for %s", suffix)
	}
	return value, nil
}

func metadataURL(baseURL, suffix string) string {
	return strings.TrimRight(baseURL, "/") + "/" + strings.TrimLeft(suffix, "/")
}

func lastMetadataPathComponent(value string) string {
	parts := strings.Split(value, "/")
	return parts[len(parts)-1]
}

func parseUintField(name, value string) (uint64, error) {
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse %s value %q as uint64: %w", name, value, err)
	}
	return parsed, nil
}

func validateZone(zone string) error {
	if zone == "" {
		return errors.New("zone is empty")
	}
	for _, r := range zone {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return fmt.Errorf("zone %q contains non-GCE zone characters", zone)
		}
	}
	return nil
}
