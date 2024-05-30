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

package extend

import (
	"bytes"
	"crypto"
	_ "crypto/sha512" // Registrer SHA384 and SHA512
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/google/go-configfs-tsm/configfs/configfsi"
	"github.com/google/go-configfs-tsm/configfs/linuxtsm"
	"github.com/google/logger"
)

const (
	RtmrSubsystem = "rtmrs"
	TsmRtmrPrefix = configfsi.TsmPrefix + "/" + RtmrSubsystem
	TsmRtmrDigest = "digest"
	TsmPathIndex  = "index"
	TsmPathTcgMap = "tcg_map"
)

// RtmrExtend is a struct that represents a rtmr entry in the configfs.
type RtmrExtend struct {
	RtmrIndex int
	entry     *configfsi.TsmPath
	client    configfsi.Client
}

// Remove the null bytes from the c-string
func convertCstring(b []byte) string {
	return string(bytes.Trim(b, "\x00"))
}

func (r *RtmrExtend) attribute(subtree string) string {
	a := *r.entry
	a.Attribute = subtree
	return a.String()
}

// extendDigest extends the measurement to the rtmr with the given hash.
func (r *RtmrExtend) extendDigest(hash []byte) error {
	if err := r.client.WriteFile(r.attribute(TsmRtmrDigest), hash); err != nil {
		if (r.RtmrIndex == 2) || (r.RtmrIndex == 3) {
			return fmt.Errorf("could not write digest to rmtr%d: %v. Is your rtmr index extendable from userspace?", r.RtmrIndex, err)
		}
		return fmt.Errorf("could not write digest to rmtr%d: %v", r.RtmrIndex, err)
	}
	return nil
}

// setRtmrIndex sets a configfs rtmr entry to the given index.
// It reports an error if the index cannot be written or the rtmr_tcg map does not match.
func (r *RtmrExtend) setRtmrIndex() error {
	indexBytes := []byte(strconv.Itoa(r.RtmrIndex)) // Convert index to []byte
	indexPath := r.attribute(TsmPathIndex)
	if err := r.client.WriteFile(indexPath, indexBytes); err != nil {
		return fmt.Errorf("could not write index %s: %v", indexPath, err)
	}
	if err := r.validateRtmrIndex(); err != nil {
		return fmt.Errorf("the tcg_map is invalid %s: %v", indexPath, err)
	}
	return nil
}

// validateRtmrIndex checks if the rtmr to PCR map is valid.
// It returns an error if the rtmr_tcg map does not match the expected value.
func (r *RtmrExtend) validateRtmrIndex() error {
	if (r.client == nil) || (r.entry == nil) {
		return fmt.Errorf("RtmrExtend is not initialized")
	}
	data, err := r.client.ReadFile(r.attribute(TsmPathTcgMap))
	if err != nil {
		return fmt.Errorf("could not read  %s: %v", TsmPathTcgMap, err)
	}
	var rtmrPcrMaps = map[int]string{
		0: "1,7\n",
		1: "2-6\n",
		2: "8-15\n",
		3: "\n",
	}

	inputMap := convertCstring(data)
	if inputMap != rtmrPcrMaps[r.RtmrIndex] {
		return fmt.Errorf("rtmr %d tcg map is %q, expect %q", r.RtmrIndex, rtmrPcrMaps[r.RtmrIndex], string(data))
	}
	return nil
}

// SearchRtmrInterface searches for an rtmr entry in the configfs.
func SearchRtmrInterface(client configfsi.Client, index int) (*RtmrExtend, error) {
	root := TsmRtmrPrefix
	out := RtmrExtend{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			p, err := configfsi.ParseTsmPath(path)
			if err != nil {
				return err
			}
			r := RtmrExtend{
				RtmrIndex: index,
				entry:     &configfsi.TsmPath{Subsystem: RtmrSubsystem, Entry: p.Entry},
				client:    client,
			}
			if r.validateRtmrIndex() == nil {
				out = r
				return nil
			}
		}
		return nil
	})

	if err != nil {
		return nil, err
	}
	if out.validateRtmrIndex() != nil {
		return nil, fmt.Errorf("could not find rtmr entry in configfs: %v", err)
	}

	return &out, nil
}

// CreateRtmrInterface creates a new rtmr entry in the configfs.
func CreateRtmrInterface(client configfsi.Client, index int) (r *RtmrExtend, err error) {
	entryPath, err := client.MkdirTemp(TsmRtmrPrefix, fmt.Sprintf("rtmr%d-", index))
	if err != nil {
		return nil, fmt.Errorf("could not create rtmr entry in configfs: %v", err)
	}
	p, _ := configfsi.ParseTsmPath(entryPath)

	r = &RtmrExtend{
		RtmrIndex: index,
		entry:     &configfsi.TsmPath{Subsystem: RtmrSubsystem, Entry: p.Entry},
		client:    client,
	}

	if err := r.setRtmrIndex(); err != nil {
		return nil, fmt.Errorf("could not set rtmr index %d: %v", index, err)
	}
	return r, nil
}

// ExtendDigestRtmr extends the measurement to the rtmr with the given digest.
func ExtendDigestRtmr(client configfsi.Client, rtmr int, digest []byte) error {
	if len(digest) > crypto.SHA384.Size() {
		return fmt.Errorf("digest is too long. The maximum length is %d bytes", crypto.SHA384.Size())
	}
	if rtmr < 0 || rtmr > 3 {
		return fmt.Errorf("invalid rtmr index %d. Index can only be 0-3", rtmr)
	}
	r, err := SearchRtmrInterface(client, rtmr)
	if err != nil {
		logger.V(2).Infof("Could not find rtmr entry in configfs. error: %v", err)
		logger.V(1).Info("Creating new rtmr entry in configfs.")
		r, err = CreateRtmrInterface(client, rtmr)
		if err != nil {
			return err
		}
	} else {
		logger.V(1).Info("Found existing rtmr entry in configfs.")
	}
	return r.extendDigest(digest)
}

// ExtendEventLogRtmrClient extends the measurement to the rtmr with the given client.
func ExtendEventLogRtmrClient(client configfsi.Client, rtmr int, hashAlgo crypto.Hash, content []byte) error {
	if hashAlgo != crypto.SHA384 {
		return fmt.Errorf("unsupported hash algorithm %v", hashAlgo)
	}
	if len(content) == 0 {
		return fmt.Errorf("input event log is empty")
	}
	sha384 := hashAlgo.New()
	sha384.Write(content)
	hash := sha384.Sum(nil)
	return ExtendDigestRtmr(client, rtmr, hash)
}

// ExtendEventLogRtmr extends the measurement into the rtmr with the given hash algorithm and content.
func ExtendEventLogRtmr(rtmr int, hashAlgo crypto.Hash, content []byte) error {
	client, err := linuxtsm.MakeClient()
	if err != nil {
		return err
	}
	return ExtendEventLogRtmrClient(client, rtmr, hashAlgo, content)
}
