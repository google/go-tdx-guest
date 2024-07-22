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

// Package rtmr provides the library functions to extend and read TDX rtmr
// registers and their tcg maps.
package rtmr

import (
	"crypto"
	_ "crypto/sha512" // Register SHA384 and SHA512
	"fmt"

	"github.com/google/go-configfs-tsm/configfs/configfsi"
	"github.com/google/go-configfs-tsm/configfs/linuxtsm"
	"github.com/google/go-configfs-tsm/rtmr"
)

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
func ExtendEventLog(rtmrIndex int, hashAlgo crypto.Hash, eventLog []byte) error {
	client, err := linuxtsm.MakeClient()
	if err != nil {
		return err
	}
	return ExtendEventLogClient(client, rtmrIndex, hashAlgo, eventLog)
}

// ExtendDigest extends the measurement into the rtmr with the given digest.
func ExtendDigest(rtmrIndex int, digest []byte) error {
	client, err := linuxtsm.MakeClient()
	if err != nil {
		return err
	}
	return ExtendDigestClient(client, rtmrIndex, digest)
}
