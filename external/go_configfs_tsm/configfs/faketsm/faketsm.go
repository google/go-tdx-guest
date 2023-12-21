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

// Package faketsm defines a configfsi.Client for faking TSM behavior.
// The provider attribute returns "fake" and the attestation report format
// is just the state of the attributes. The certificate blob is part of the
// Client definition.
package faketsm

import (
	"fmt"

	"github.com/google/go-tdx-guest/external/go_configfs_tsm/configfs/configfsi"
)

// Client provides a "fake" provider for configfs to emulate the /sys/kernel/config/tsm behavior.
// Dispatches to specialized subsystem Client interfaces.
type Client struct {
	Subsystems map[string]configfsi.Client
}

func (c *Client) getSubsystem(name string) (configfsi.Client, error) {
	p, err := configfsi.ParseTsmPath(name)
	if err != nil {
		return nil, fmt.Errorf("getSubsystem: %v", err)
	}
	if p.Subsystem == "" {
		return nil, fmt.Errorf("faketsm: expected tsm subsystem in %q", name)
	}
	sub, ok := c.Subsystems[p.Subsystem]
	if !ok {
		return nil, fmt.Errorf("faketsm: unsupported subsystem %q", p.Subsystem)
	}
	return sub, nil
}

// MkdirTemp creates a new temporary directory in the directory dir and returns the pathname
// of the new directory. Pattern semantics follow os.MkdirTemp.
func (c *Client) MkdirTemp(dir, pattern string) (string, error) {
	if dir == "" {
		return "", fmt.Errorf("faketsm doesn't implement empty directory behavior")
	}
	sub, err := c.getSubsystem(dir)
	if err != nil {
		return "", err
	}
	return sub.MkdirTemp(dir, pattern)
}

// ReadFile reads the named file and returns the contents.
func (c *Client) ReadFile(name string) ([]byte, error) {
	sub, err := c.getSubsystem(name)
	if err != nil {
		return nil, err
	}
	return sub.ReadFile(name)
}

// WriteFile writes data to the named file, creating it if necessary. The permissions
// are implementation-defined.
func (c *Client) WriteFile(name string, contents []byte) error {
	sub, err := c.getSubsystem(name)
	if err != nil {
		return err
	}
	return sub.WriteFile(name, contents)
}

// RemoveAll removes path and any children it contains.
func (c *Client) RemoveAll(name string) error {
	sub, err := c.getSubsystem(name)
	if err != nil {
		return err
	}
	return sub.RemoveAll(name)
}
