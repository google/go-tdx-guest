// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package proto contains protocol buffers that are exchanged between the client
// and server, as well as convenience configuration definitions for tools.
//
// # Generating Protocol Buffer Code
//
// Anytime the Protocol Buffer definitions change, the generated Go code must be
// regenerated. This can be done with "go generate". Just run:
//
// go generate ./...
//
// Upstream documentation:
// https://developers.google.com/protocol-buffers/docs/reference/go-generated
//
// # Code Generation Dependencies
//
// To generate the Go code, your system must have "protoc" installed. See:
// https://github.com/protocolbuffers/protobuf#protocol-compiler-installation
//
// The "protoc-gen-go" tool must also be installed. To install it, run:
//
// go install google.golang.org/protobuf/cmd/protoc-gen-go
//
// If you see a 'protoc-gen-go: program not found or is not executable' error
// for the 'go generate' command, run the following:
//
// echo 'export PATH=$PATH:$GOPATH/bin' >> $HOME/.bashrc
// source $HOME/.bashrc
//
// If you see 'google/protobuf/wrappers.proto not found', then you need to
// similarly set your PROTOC_INSTALL_DIR environment variable to the protoc
// installation directory which should have the "well-known types" in the
// include subdirectory.
package proto

//go:generate protoc -I$PROTOC_INSTALL_DIR/include -I=. --go_out=. --go_opt=module=github.com/google/go-tdx-guest/proto tdx.proto
