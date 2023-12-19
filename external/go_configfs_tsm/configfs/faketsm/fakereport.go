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
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sync"
	"syscall"
	"unicode/utf8"

	"github.com/google/go-tdx-guest/external/go_configfs_tsm/configfs/configfsi"
)

// ErrPrivLevelFormat to store error due to incorrect privilege level.
var ErrPrivLevelFormat = errors.New("privlevel must be 0-3")

const (
	// subsystemName is the expected subsystem path entry under tsm for reports.
	subsystemName = "report"
	tsmInBlobSize = 64
	renderBase    = 10
)

// ReportAttributeState rewrites a writable attribute's value state. May also be readable.
type ReportAttributeState struct {
	Value     []byte
	ReadWrite bool
}

// ReportEntry represents a report entry in the TSM report subsystem.
type ReportEntry struct {
	mu              sync.RWMutex
	destroyed       bool
	ReadGeneration  uint64
	WriteGeneration uint64
	// InAttrs represents the value of all WO attributes by name (relative to entry).
	// All possible attributes ought to be mapped on creation.
	InAttrs map[string]*ReportAttributeState
	// ROAttrs is populated on ReadFile under mu and acts as a cache when
	// generations align before calling ReadAttr.
	ROAttrs map[string][]byte
}

// ReportSubsystem represents the general behavior of the configfs-tsm report subsystem
type ReportSubsystem struct {
	// CheckInAttr called on any WriteFile to an attribute. If non-nil, WriteFile returns
	// the error instead of writing. Called while holding client and entry locks.
	CheckInAttr func(e *ReportEntry, attr string, contents []byte) error
	// ReadAttr is called on any non-InAddr key while holding the client and entry locks.
	ReadAttr func(e *ReportEntry, attr string) ([]byte, error)
	// MakeEntry returns a fresh entry with all expected InAttrs. Called while holding
	// the client lock.
	MakeEntry func() *ReportEntry
	mu        sync.RWMutex
	Entries   map[string]*ReportEntry
	// Random is the source of randomness to use for MkdirTemp
	Random io.Reader
}

// Called while mu is held
func (e *ReportEntry) tryAdvanceWriteGeneration() error {
	if e.destroyed {
		return os.ErrNotExist
	}
	if e.WriteGeneration == e.ReadGeneration-1 {
		return syscall.EBUSY
	}
	e.WriteGeneration++
	return nil
}

// MkdirTemp creates a new temporary directory in the directory dir and returns the pathname
// of the new directory. Pattern semantics follow os.MkdirTemp.
func (r *ReportSubsystem) MkdirTemp(dir, pattern string) (string, error) {
	p, err := configfsi.ParseTsmPath(dir)
	if err != nil {
		return "", fmt.Errorf("MkdirTemp: %v", err)
	}
	if p.Entry != "" {
		return "", fmt.Errorf("report entry %q cannot have subdirectories", dir)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.Entries == nil {
		r.Entries = make(map[string]*ReportEntry)
	}
	name := configfsi.TempName(r.Random, pattern)
	if _, ok := r.Entries[name]; ok {
		return "", os.ErrExist
	}
	r.Entries[name] = r.MakeEntry()
	return path.Join(dir, name), nil
}

func (e *ReportEntry) readCached(attr string) ([]byte, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.destroyed {
		return nil, os.ErrNotExist
	}
	// The only special attribute is "generation", since it peers into the
	// mechanics of mutation.
	if attr == "generation" {
		return []byte(fmt.Sprintf("%d\n", e.WriteGeneration)), nil
	}
	if e.ReadGeneration != e.WriteGeneration {
		return nil, syscall.EWOULDBLOCK
	}
	if a, ok := e.InAttrs[attr]; ok {
		if !a.ReadWrite {
			return nil, fmt.Errorf("%q is not readable", attr)
		}
		dup := make([]byte, len(a.Value))
		copy(dup, a.Value)
		return dup, nil
	}
	if e.ROAttrs != nil {
		if a, ok := e.ROAttrs[attr]; ok {
			if len(a) != 0 {
				dup := make([]byte, len(a))
				copy(dup, a)
				return dup, nil
			}
			return nil, nil
		}
	}
	return nil, os.ErrNotExist

}

// ReadFile reads the named file and returns the contents.
func (r *ReportSubsystem) ReadFile(name string) ([]byte, error) {
	p, err := configfsi.ParseTsmPath(name)
	if err != nil {
		return nil, fmt.Errorf("ReadFile: %v", err)
	}
	if p.Attribute == "" {
		return nil, fmt.Errorf("not an attribute: %q", name)
	}
	r.mu.RLock()
	if r.Entries == nil {
		return nil, os.ErrNotExist
	}
	e, ok := r.Entries[p.Entry]
	if !ok {
		r.mu.RUnlock()
		return nil, os.ErrNotExist
	}
	r.mu.RUnlock()
	if b, err := e.readCached(p.Attribute); (err == nil && len(b) != 0) || err != syscall.EWOULDBLOCK {
		return b, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.ROAttrs == nil {
		e.ROAttrs = make(map[string][]byte)
	}
	// It's possible another thread has populated the report between RUnlock and Lock.
	if b, ok := e.ROAttrs[p.Attribute]; ok && e.ReadGeneration == e.WriteGeneration {
		return b, nil
	}
	e.ROAttrs[p.Attribute] = nil
	b, err := r.ReadAttr(e, p.Attribute)
	if err != nil {
		return nil, fmt.Errorf("ReadAttr(_, %q): %v", p.Attribute, err)
	}
	e.ROAttrs[p.Attribute] = b
	return b, nil
}

// WriteFile writes data to the named file, creating it if necessary. The permissions
// are implementation-defined.
func (r *ReportSubsystem) WriteFile(name string, contents []byte) error {
	p, err := configfsi.ParseTsmPath(name)
	if err != nil {
		return fmt.Errorf("WriteFile: %v", err)
	}
	if p.Attribute == "" {
		return fmt.Errorf("cannot write to non-attribute: %q", name)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.Entries[p.Entry]
	if !ok {
		return os.ErrNotExist
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.destroyed {
		return os.ErrNotExist
	}
	if err := r.CheckInAttr(e, p.Attribute, contents); err != nil {
		return fmt.Errorf("could not write %q: %v", name, err)
	}
	if err := e.tryAdvanceWriteGeneration(); err != nil {
		return err
	}
	e.InAttrs[p.Attribute].Value = contents
	return nil
}

// RemoveAll removes path and any children it contains.
func (r *ReportSubsystem) RemoveAll(name string) error {
	p, err := configfsi.ParseTsmPath(name)
	if err != nil {
		return fmt.Errorf("RemoveAll: %v", err)
	}
	if p.Attribute != "" || p.Entry == "" || p.Subsystem != subsystemName {
		return fmt.Errorf("RemoveAll(%q) expected report subsystem entry path", name)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.Entries == nil {
		return os.ErrNotExist
	}
	e, ok := r.Entries[p.Entry]
	if !ok {
		return os.ErrNotExist
	}
	// Don't delete while another operation is using the entry.
	e.mu.Lock()
	e.destroyed = true
	delete(r.Entries, p.Entry)
	e.mu.Unlock()
	return nil
}

func renderOutBlob(privlevel, inblob []byte) []byte {
	// checkv7 already ensures this does not error
	priv, _ := configfsi.Kstrtouint(privlevel, renderBase, 2)
	return []byte(fmt.Sprintf("privlevel: %d\ninblob: %s",
		priv,
		hex.EncodeToString(inblob)))
}

func readV7(privlevelFloor uint) func(*ReportEntry, string) ([]byte, error) {
	return func(e *ReportEntry, attr string) ([]byte, error) {
		switch attr {
		case "provider":
			return []byte("fake\n"), nil
		case "auxblob":
			return []byte(`auxblob`), nil
		case "outblob":
			privlevel := []byte("<missing>")
			if a, ok := e.InAttrs["privlevel"]; ok && len(a.Value) > 0 {
				privlevel = a.Value
			}
			inblob, ok := e.InAttrs["inblob"]
			if !ok || len(inblob.Value) == 0 {
				return nil, syscall.EINVAL
			}
			return renderOutBlob(privlevel, inblob.Value), nil
		case "privlevel_floor":
			return []byte(fmt.Sprintf("%d\n", privlevelFloor)), nil
		}
		return nil, os.ErrNotExist
	}
}

func makeV7() *ReportEntry {
	return &ReportEntry{
		InAttrs: map[string]*ReportAttributeState{
			"privlevel": {Value: []byte("0\n")},
			"inblob":    {},
		},
	}
}

func checkV7(privlevelFloor uint) func(*ReportEntry, string, []byte) error {
	return func(e *ReportEntry, attr string, contents []byte) error {
		switch attr {
		case "inblob":
			if len(contents) > tsmInBlobSize {
				return syscall.EINVAL
			}
		case "privlevel":
			if !utf8.Valid(contents) {
				return ErrPrivLevelFormat
			}
			level, err := configfsi.Kstrtouint(contents, renderBase, 2)
			if err != nil {
				return ErrPrivLevelFormat
			}
			if uint(level) < privlevelFloor {
				return fmt.Errorf("privlevel %d cannot be less than %d",
					level, privlevelFloor)
			}
		default:
			return fmt.Errorf("unwritable attribute: %q", attr)
		}
		return nil
	}
}

// ReportV7 returns an empty report subsystem with attributes as specified in the configfs-tsm
// Patch v7 series.
func ReportV7(privlevelFloor uint) *ReportSubsystem {
	return &ReportSubsystem{
		MakeEntry:   makeV7,
		ReadAttr:    readV7(privlevelFloor),
		CheckInAttr: checkV7(privlevelFloor),
		Random:      rand.Reader,
	}
}
