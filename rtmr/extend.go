// Copyright 2024 Google LLC
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

// Package rtmr provides the library functions:
// 1. extend and read TDX rtmr registers and their tcg maps.
// 2. replay the event log with the TDX quote.
package rtmr

import (
	"crypto"
	_ "crypto/sha512" // Register SHA384 and SHA512
	"fmt"
	"os"

	"github.com/google/go-configfs-tsm/configfs/configfsi"
	"github.com/google/go-configfs-tsm/configfs/linuxtsm"
	"github.com/google/go-configfs-tsm/rtmr"
)

const (
	// Defines the legacy rtmr file path.
	legacyRTMRPath = "/sys/kernel/config/tsm/rtmrs"
)

// ExtendDigestSysfs extends the measurement to the rtmr through the sysfs interface.
// This is the modern method for extending TDX rtmr.
func ExtendDigestSysfs(rtmrIndex int, digest []byte) error {
	if rtmrIndex < 0 || rtmrIndex > 3 {
		return fmt.Errorf("invalid rtmr index %d. For TDX, index can only be 0-3", rtmrIndex)
	}
	if len(digest) != crypto.SHA384.Size() {
		return fmt.Errorf("sha384 digest should be %d bytes, the input is %d bytes", crypto.SHA384.Size(), len(digest))
	}
	// The sysfs file is an interface for rtmr. Each write operation functions
	// as an "extend" operation, not a normal file write.
	filePath := fmt.Sprintf("/sys/class/misc/tdx_guest/measurements/rtmr%d:sha384", rtmrIndex)
	file, err := os.OpenFile(filePath, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("failed to open TDX RTMR file %s: %w", filePath, err)
	}
	defer file.Close()

	if _, err = file.WriteAt(digest, 0); err != nil {
		return fmt.Errorf("failed to write data to %s at offset 0: %w", filePath, err)
	}
	return nil
}

// ExtendDigestClient extends the measurement to the rtmr with the given client.
func ExtendDigestClient(client configfsi.Client, rtmrIndex int, digest []byte) error {
	if rtmrIndex < 0 || rtmrIndex > 3 {
		return fmt.Errorf("invalid rtmr index %d. For TDX, index can only be 0-3", rtmrIndex)
	}
	if len(digest) != crypto.SHA384.Size() {
		return fmt.Errorf("sha384 digest should be %d bytes, the input is %d bytes", crypto.SHA384.Size(), len(digest))
	}
	// TODO: check the TCG mapping of the rtmr index
	return rtmr.ExtendDigest(client, rtmrIndex, digest)
}

// ExtendEventLogSysfs extends the event log to the rtmr through the sysfs interface.
func ExtendEventLogSysfs(rtmrIndex int, hashAlgo crypto.Hash, eventLog []byte) error {
	if hashAlgo != crypto.SHA384 {
		return fmt.Errorf("unsupported hash algorithm %v", hashAlgo)
	}
	if len(eventLog) == 0 {
		return fmt.Errorf("input event log is empty")
	}

	sha384 := hashAlgo.New()
	sha384.Write(eventLog)
	hash := sha384.Sum(nil)
	return ExtendDigestSysfs(rtmrIndex, hash)
}

// ExtendEventLogClient extends the event log to the rtmr with the given client.
func ExtendEventLogClient(client configfsi.Client, rtmrIndex int, hashAlgo crypto.Hash, eventLog []byte) error {
	if hashAlgo != crypto.SHA384 {
		return fmt.Errorf("unsupported hash algorithm %v", hashAlgo)
	}
	if len(eventLog) == 0 {
		return fmt.Errorf("input event log is empty")
	}
	sha384 := hashAlgo.New()
	sha384.Write(eventLog)
	hash := sha384.Sum(nil)
	return ExtendDigestClient(client, rtmrIndex, hash)
}

// ExtendEventLog extends the measurement into the rtmr with the given hash algorithm and event log.
// It checks for the existence of the legacy configfs path to decide whether to use the client or sysfs method.
func ExtendEventLog(rtmrIndex int, hashAlgo crypto.Hash, eventLog []byte) error {
	// Check if the legacy configfs path exists to determine the extension method.
	_, err := os.Stat(legacyRTMRPath)
	if err == nil {
		// If the path exists, use the client method.
		client, err := linuxtsm.MakeClient()
		if err != nil {
			return err
		}
		return ExtendEventLogClient(client, rtmrIndex, hashAlgo, eventLog)
	} else if os.IsNotExist(err) {
		// If the configfs path does not exist, use the sysfs interface instead.
		return ExtendEventLogSysfs(rtmrIndex, hashAlgo, eventLog)
	}
	// Handle other unexpected errors from os.Stat.
	return fmt.Errorf("failed to check for directory %s: %w", legacyRTMRPath, err)
}

// ExtendDigest extends the measurement into the rtmr with the given digest.
// It checks for the existence of the legacy configfs path to decide whether to use the client or sysfs method.
func ExtendDigest(rtmrIndex int, digest []byte) error {
	// Check if the legacy configfs path exists to determine the extension method.
	_, err := os.Stat(legacyRTMRPath)
	if err == nil {
		// If the path exists, use the client method.
		client, err := linuxtsm.MakeClient()
		if err != nil {
			return err
		}
		return ExtendDigestClient(client, rtmrIndex, digest)
	} else if os.IsNotExist(err) {
		// If the configs path does not exist, use the sysfs interface instead.
		return ExtendDigestSysfs(rtmrIndex, digest)
	}
	// Handle other unexpected errors from os.Stat.
	return fmt.Errorf("failed to check for directory %s: %w", legacyRTMRPath, err)
}
