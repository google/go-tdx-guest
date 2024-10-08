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

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.31.0
// 	protoc        v3.12.4
// source: checkconfig.proto

// Package checkconfig represents an attestation validation policy.

package checkconfig

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// Policy is a representation of an attestation quote validation policy.
// Each field corresponds to a field on validate.Options. This format
// is useful for providing programmatic inputs to the `check` CLI tool.
type Policy struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// HeaderPolicy is representation of Header of an attestation quote validation
	// policy.
	HeaderPolicy *HeaderPolicy `protobuf:"bytes,1,opt,name=header_policy,json=headerPolicy,proto3" json:"header_policy,omitempty"` // should be 20 bytes
	// TDQuoteBodyPolicy is representation of TdQuoteBody of an attestation quote
	// validation policy.
	TdQuoteBodyPolicy *TDQuoteBodyPolicy `protobuf:"bytes,2,opt,name=td_quote_body_policy,json=tdQuoteBodyPolicy,proto3" json:"td_quote_body_policy,omitempty"` // should be 528 bytes
}

func (x *Policy) Reset() {
	*x = Policy{}
	if protoimpl.UnsafeEnabled {
		mi := &file_checkconfig_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Policy) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Policy) ProtoMessage() {}

func (x *Policy) ProtoReflect() protoreflect.Message {
	mi := &file_checkconfig_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Policy.ProtoReflect.Descriptor instead.
func (*Policy) Descriptor() ([]byte, []int) {
	return file_checkconfig_proto_rawDescGZIP(), []int{0}
}

func (x *Policy) GetHeaderPolicy() *HeaderPolicy {
	if x != nil {
		return x.HeaderPolicy
	}
	return nil
}

func (x *Policy) GetTdQuoteBodyPolicy() *TDQuoteBodyPolicy {
	if x != nil {
		return x.TdQuoteBodyPolicy
	}
	return nil
}

type HeaderPolicy struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	MinimumQeSvn  uint32 `protobuf:"varint,1,opt,name=minimum_qe_svn,json=minimumQeSvn,proto3" json:"minimum_qe_svn,omitempty"`    // should not exceed uint16 max
	MinimumPceSvn uint32 `protobuf:"varint,2,opt,name=minimum_pce_svn,json=minimumPceSvn,proto3" json:"minimum_pce_svn,omitempty"` // should not exceed uint16 max
	// Unique vendor id of QE vendor
	QeVendorId []byte `protobuf:"bytes,3,opt,name=qe_vendor_id,json=qeVendorId,proto3" json:"qe_vendor_id,omitempty"` // should be 16 bytes
}

func (x *HeaderPolicy) Reset() {
	*x = HeaderPolicy{}
	if protoimpl.UnsafeEnabled {
		mi := &file_checkconfig_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *HeaderPolicy) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HeaderPolicy) ProtoMessage() {}

func (x *HeaderPolicy) ProtoReflect() protoreflect.Message {
	mi := &file_checkconfig_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HeaderPolicy.ProtoReflect.Descriptor instead.
func (*HeaderPolicy) Descriptor() ([]byte, []int) {
	return file_checkconfig_proto_rawDescGZIP(), []int{1}
}

func (x *HeaderPolicy) GetMinimumQeSvn() uint32 {
	if x != nil {
		return x.MinimumQeSvn
	}
	return 0
}

func (x *HeaderPolicy) GetMinimumPceSvn() uint32 {
	if x != nil {
		return x.MinimumPceSvn
	}
	return 0
}

func (x *HeaderPolicy) GetQeVendorId() []byte {
	if x != nil {
		return x.QeVendorId
	}
	return nil
}

type TDQuoteBodyPolicy struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	MinimumTeeTcbSvn []byte   `protobuf:"bytes,1,opt,name=minimum_tee_tcb_svn,json=minimumTeeTcbSvn,proto3" json:"minimum_tee_tcb_svn,omitempty"` // should be 16 bytes
	MrSeam           []byte   `protobuf:"bytes,2,opt,name=mr_seam,json=mrSeam,proto3" json:"mr_seam,omitempty"`                                   // should be 48 bytes
	TdAttributes     []byte   `protobuf:"bytes,3,opt,name=td_attributes,json=tdAttributes,proto3" json:"td_attributes,omitempty"`                 // should be 8 bytes
	Xfam             []byte   `protobuf:"bytes,4,opt,name=xfam,proto3" json:"xfam,omitempty"`                                                     // should be 8 bytes
	MrTd             []byte   `protobuf:"bytes,5,opt,name=mr_td,json=mrTd,proto3" json:"mr_td,omitempty"`                                         // should be 48 bytes
	MrConfigId       []byte   `protobuf:"bytes,6,opt,name=mr_config_id,json=mrConfigId,proto3" json:"mr_config_id,omitempty"`                     // should be 48 bytes
	MrOwner          []byte   `protobuf:"bytes,7,opt,name=mr_owner,json=mrOwner,proto3" json:"mr_owner,omitempty"`                                // should be 48 bytes
	MrOwnerConfig    []byte   `protobuf:"bytes,8,opt,name=mr_owner_config,json=mrOwnerConfig,proto3" json:"mr_owner_config,omitempty"`            // should be 48 bytes
	Rtmrs            [][]byte `protobuf:"bytes,9,rep,name=rtmrs,proto3" json:"rtmrs,omitempty"`                                                   // should be 48 * rtmrsCount
	ReportData       []byte   `protobuf:"bytes,10,opt,name=report_data,json=reportData,proto3" json:"report_data,omitempty"`                      // should be 64 bytes
	AnyMrTd          [][]byte `protobuf:"bytes,11,rep,name=any_mr_td,json=anyMrTd,proto3" json:"any_mr_td,omitempty"`                             // each should be 48 bytes.
}

func (x *TDQuoteBodyPolicy) Reset() {
	*x = TDQuoteBodyPolicy{}
	if protoimpl.UnsafeEnabled {
		mi := &file_checkconfig_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TDQuoteBodyPolicy) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TDQuoteBodyPolicy) ProtoMessage() {}

func (x *TDQuoteBodyPolicy) ProtoReflect() protoreflect.Message {
	mi := &file_checkconfig_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TDQuoteBodyPolicy.ProtoReflect.Descriptor instead.
func (*TDQuoteBodyPolicy) Descriptor() ([]byte, []int) {
	return file_checkconfig_proto_rawDescGZIP(), []int{2}
}

func (x *TDQuoteBodyPolicy) GetMinimumTeeTcbSvn() []byte {
	if x != nil {
		return x.MinimumTeeTcbSvn
	}
	return nil
}

func (x *TDQuoteBodyPolicy) GetMrSeam() []byte {
	if x != nil {
		return x.MrSeam
	}
	return nil
}

func (x *TDQuoteBodyPolicy) GetTdAttributes() []byte {
	if x != nil {
		return x.TdAttributes
	}
	return nil
}

func (x *TDQuoteBodyPolicy) GetXfam() []byte {
	if x != nil {
		return x.Xfam
	}
	return nil
}

func (x *TDQuoteBodyPolicy) GetMrTd() []byte {
	if x != nil {
		return x.MrTd
	}
	return nil
}

func (x *TDQuoteBodyPolicy) GetMrConfigId() []byte {
	if x != nil {
		return x.MrConfigId
	}
	return nil
}

func (x *TDQuoteBodyPolicy) GetMrOwner() []byte {
	if x != nil {
		return x.MrOwner
	}
	return nil
}

func (x *TDQuoteBodyPolicy) GetMrOwnerConfig() []byte {
	if x != nil {
		return x.MrOwnerConfig
	}
	return nil
}

func (x *TDQuoteBodyPolicy) GetRtmrs() [][]byte {
	if x != nil {
		return x.Rtmrs
	}
	return nil
}

func (x *TDQuoteBodyPolicy) GetReportData() []byte {
	if x != nil {
		return x.ReportData
	}
	return nil
}

func (x *TDQuoteBodyPolicy) GetAnyMrTd() [][]byte {
	if x != nil {
		return x.AnyMrTd
	}
	return nil
}

// RootOfTrust represents configuration for which hardware root of trust
// certificates to use for verifying attestation quote.
type RootOfTrust struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Paths to CA bundles for the Intel TDX.
	// Must be in PEM format.
	// If empty, uses the verification library's embedded certificates from Intel.
	CabundlePaths []string `protobuf:"bytes,1,rep,name=cabundle_paths,json=cabundlePaths,proto3" json:"cabundle_paths,omitempty"`
	// PEM format CA bundles for Intel TDX. Combined with contents of
	// cabundle_paths.
	Cabundles []string `protobuf:"bytes,2,rep,name=cabundles,proto3" json:"cabundles,omitempty"`
	// If true, download and check the CRL for revoked certificates.
	CheckCrl bool `protobuf:"varint,3,opt,name=check_crl,json=checkCrl,proto3" json:"check_crl,omitempty"`
	// If true, then check is not permitted to download necessary files for
	// verification.
	GetCollateral bool `protobuf:"varint,4,opt,name=get_collateral,json=getCollateral,proto3" json:"get_collateral,omitempty"`
}

func (x *RootOfTrust) Reset() {
	*x = RootOfTrust{}
	if protoimpl.UnsafeEnabled {
		mi := &file_checkconfig_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RootOfTrust) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RootOfTrust) ProtoMessage() {}

func (x *RootOfTrust) ProtoReflect() protoreflect.Message {
	mi := &file_checkconfig_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RootOfTrust.ProtoReflect.Descriptor instead.
func (*RootOfTrust) Descriptor() ([]byte, []int) {
	return file_checkconfig_proto_rawDescGZIP(), []int{3}
}

func (x *RootOfTrust) GetCabundlePaths() []string {
	if x != nil {
		return x.CabundlePaths
	}
	return nil
}

func (x *RootOfTrust) GetCabundles() []string {
	if x != nil {
		return x.Cabundles
	}
	return nil
}

func (x *RootOfTrust) GetCheckCrl() bool {
	if x != nil {
		return x.CheckCrl
	}
	return false
}

func (x *RootOfTrust) GetGetCollateral() bool {
	if x != nil {
		return x.GetCollateral
	}
	return false
}

// Config is the overall message input for the check tool. This provides all
// the flags that configure the tool, including the validation policy.
type Config struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The report validation policy.
	Policy *Policy `protobuf:"bytes,1,opt,name=policy,proto3" json:"policy,omitempty"`
	// Configures which hardware keys to trust. Default uses library-embedded
	// certificate.
	RootOfTrust *RootOfTrust `protobuf:"bytes,2,opt,name=root_of_trust,json=rootOfTrust,proto3" json:"root_of_trust,omitempty"`
}

func (x *Config) Reset() {
	*x = Config{}
	if protoimpl.UnsafeEnabled {
		mi := &file_checkconfig_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Config) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Config) ProtoMessage() {}

func (x *Config) ProtoReflect() protoreflect.Message {
	mi := &file_checkconfig_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Config.ProtoReflect.Descriptor instead.
func (*Config) Descriptor() ([]byte, []int) {
	return file_checkconfig_proto_rawDescGZIP(), []int{4}
}

func (x *Config) GetPolicy() *Policy {
	if x != nil {
		return x.Policy
	}
	return nil
}

func (x *Config) GetRootOfTrust() *RootOfTrust {
	if x != nil {
		return x.RootOfTrust
	}
	return nil
}

var File_checkconfig_proto protoreflect.FileDescriptor

var file_checkconfig_proto_rawDesc = []byte{
	0x0a, 0x11, 0x63, 0x68, 0x65, 0x63, 0x6b, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x12, 0x0b, 0x63, 0x68, 0x65, 0x63, 0x6b, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67,
	0x22, 0x99, 0x01, 0x0a, 0x06, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x12, 0x3e, 0x0a, 0x0d, 0x68,
	0x65, 0x61, 0x64, 0x65, 0x72, 0x5f, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x19, 0x2e, 0x63, 0x68, 0x65, 0x63, 0x6b, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67,
	0x2e, 0x48, 0x65, 0x61, 0x64, 0x65, 0x72, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x52, 0x0c, 0x68,
	0x65, 0x61, 0x64, 0x65, 0x72, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x12, 0x4f, 0x0a, 0x14, 0x74,
	0x64, 0x5f, 0x71, 0x75, 0x6f, 0x74, 0x65, 0x5f, 0x62, 0x6f, 0x64, 0x79, 0x5f, 0x70, 0x6f, 0x6c,
	0x69, 0x63, 0x79, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1e, 0x2e, 0x63, 0x68, 0x65, 0x63,
	0x6b, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x54, 0x44, 0x51, 0x75, 0x6f, 0x74, 0x65, 0x42,
	0x6f, 0x64, 0x79, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x52, 0x11, 0x74, 0x64, 0x51, 0x75, 0x6f,
	0x74, 0x65, 0x42, 0x6f, 0x64, 0x79, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x22, 0x7e, 0x0a, 0x0c,
	0x48, 0x65, 0x61, 0x64, 0x65, 0x72, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x12, 0x24, 0x0a, 0x0e,
	0x6d, 0x69, 0x6e, 0x69, 0x6d, 0x75, 0x6d, 0x5f, 0x71, 0x65, 0x5f, 0x73, 0x76, 0x6e, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x0d, 0x52, 0x0c, 0x6d, 0x69, 0x6e, 0x69, 0x6d, 0x75, 0x6d, 0x51, 0x65, 0x53,
	0x76, 0x6e, 0x12, 0x26, 0x0a, 0x0f, 0x6d, 0x69, 0x6e, 0x69, 0x6d, 0x75, 0x6d, 0x5f, 0x70, 0x63,
	0x65, 0x5f, 0x73, 0x76, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0d, 0x6d, 0x69, 0x6e,
	0x69, 0x6d, 0x75, 0x6d, 0x50, 0x63, 0x65, 0x53, 0x76, 0x6e, 0x12, 0x20, 0x0a, 0x0c, 0x71, 0x65,
	0x5f, 0x76, 0x65, 0x6e, 0x64, 0x6f, 0x72, 0x5f, 0x69, 0x64, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c,
	0x52, 0x0a, 0x71, 0x65, 0x56, 0x65, 0x6e, 0x64, 0x6f, 0x72, 0x49, 0x64, 0x22, 0xe1, 0x02, 0x0a,
	0x11, 0x54, 0x44, 0x51, 0x75, 0x6f, 0x74, 0x65, 0x42, 0x6f, 0x64, 0x79, 0x50, 0x6f, 0x6c, 0x69,
	0x63, 0x79, 0x12, 0x2d, 0x0a, 0x13, 0x6d, 0x69, 0x6e, 0x69, 0x6d, 0x75, 0x6d, 0x5f, 0x74, 0x65,
	0x65, 0x5f, 0x74, 0x63, 0x62, 0x5f, 0x73, 0x76, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52,
	0x10, 0x6d, 0x69, 0x6e, 0x69, 0x6d, 0x75, 0x6d, 0x54, 0x65, 0x65, 0x54, 0x63, 0x62, 0x53, 0x76,
	0x6e, 0x12, 0x17, 0x0a, 0x07, 0x6d, 0x72, 0x5f, 0x73, 0x65, 0x61, 0x6d, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x06, 0x6d, 0x72, 0x53, 0x65, 0x61, 0x6d, 0x12, 0x23, 0x0a, 0x0d, 0x74, 0x64,
	0x5f, 0x61, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x0c, 0x74, 0x64, 0x41, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x12,
	0x12, 0x0a, 0x04, 0x78, 0x66, 0x61, 0x6d, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x04, 0x78,
	0x66, 0x61, 0x6d, 0x12, 0x13, 0x0a, 0x05, 0x6d, 0x72, 0x5f, 0x74, 0x64, 0x18, 0x05, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x04, 0x6d, 0x72, 0x54, 0x64, 0x12, 0x20, 0x0a, 0x0c, 0x6d, 0x72, 0x5f, 0x63,
	0x6f, 0x6e, 0x66, 0x69, 0x67, 0x5f, 0x69, 0x64, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0a,
	0x6d, 0x72, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x49, 0x64, 0x12, 0x19, 0x0a, 0x08, 0x6d, 0x72,
	0x5f, 0x6f, 0x77, 0x6e, 0x65, 0x72, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x07, 0x6d, 0x72,
	0x4f, 0x77, 0x6e, 0x65, 0x72, 0x12, 0x26, 0x0a, 0x0f, 0x6d, 0x72, 0x5f, 0x6f, 0x77, 0x6e, 0x65,
	0x72, 0x5f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x18, 0x08, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0d,
	0x6d, 0x72, 0x4f, 0x77, 0x6e, 0x65, 0x72, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x12, 0x14, 0x0a,
	0x05, 0x72, 0x74, 0x6d, 0x72, 0x73, 0x18, 0x09, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x05, 0x72, 0x74,
	0x6d, 0x72, 0x73, 0x12, 0x1f, 0x0a, 0x0b, 0x72, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x5f, 0x64, 0x61,
	0x74, 0x61, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0a, 0x72, 0x65, 0x70, 0x6f, 0x72, 0x74,
	0x44, 0x61, 0x74, 0x61, 0x12, 0x1a, 0x0a, 0x09, 0x61, 0x6e, 0x79, 0x5f, 0x6d, 0x72, 0x5f, 0x74,
	0x64, 0x18, 0x0b, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x07, 0x61, 0x6e, 0x79, 0x4d, 0x72, 0x54, 0x64,
	0x22, 0x96, 0x01, 0x0a, 0x0b, 0x52, 0x6f, 0x6f, 0x74, 0x4f, 0x66, 0x54, 0x72, 0x75, 0x73, 0x74,
	0x12, 0x25, 0x0a, 0x0e, 0x63, 0x61, 0x62, 0x75, 0x6e, 0x64, 0x6c, 0x65, 0x5f, 0x70, 0x61, 0x74,
	0x68, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x09, 0x52, 0x0d, 0x63, 0x61, 0x62, 0x75, 0x6e, 0x64,
	0x6c, 0x65, 0x50, 0x61, 0x74, 0x68, 0x73, 0x12, 0x1c, 0x0a, 0x09, 0x63, 0x61, 0x62, 0x75, 0x6e,
	0x64, 0x6c, 0x65, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x09, 0x52, 0x09, 0x63, 0x61, 0x62, 0x75,
	0x6e, 0x64, 0x6c, 0x65, 0x73, 0x12, 0x1b, 0x0a, 0x09, 0x63, 0x68, 0x65, 0x63, 0x6b, 0x5f, 0x63,
	0x72, 0x6c, 0x18, 0x03, 0x20, 0x01, 0x28, 0x08, 0x52, 0x08, 0x63, 0x68, 0x65, 0x63, 0x6b, 0x43,
	0x72, 0x6c, 0x12, 0x25, 0x0a, 0x0e, 0x67, 0x65, 0x74, 0x5f, 0x63, 0x6f, 0x6c, 0x6c, 0x61, 0x74,
	0x65, 0x72, 0x61, 0x6c, 0x18, 0x04, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0d, 0x67, 0x65, 0x74, 0x43,
	0x6f, 0x6c, 0x6c, 0x61, 0x74, 0x65, 0x72, 0x61, 0x6c, 0x22, 0x73, 0x0a, 0x06, 0x43, 0x6f, 0x6e,
	0x66, 0x69, 0x67, 0x12, 0x2b, 0x0a, 0x06, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x13, 0x2e, 0x63, 0x68, 0x65, 0x63, 0x6b, 0x63, 0x6f, 0x6e, 0x66, 0x69,
	0x67, 0x2e, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x52, 0x06, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79,
	0x12, 0x3c, 0x0a, 0x0d, 0x72, 0x6f, 0x6f, 0x74, 0x5f, 0x6f, 0x66, 0x5f, 0x74, 0x72, 0x75, 0x73,
	0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x18, 0x2e, 0x63, 0x68, 0x65, 0x63, 0x6b, 0x63,
	0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x52, 0x6f, 0x6f, 0x74, 0x4f, 0x66, 0x54, 0x72, 0x75, 0x73,
	0x74, 0x52, 0x0b, 0x72, 0x6f, 0x6f, 0x74, 0x4f, 0x66, 0x54, 0x72, 0x75, 0x73, 0x74, 0x42, 0x32,
	0x5a, 0x30, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2f, 0x67, 0x6f, 0x2d, 0x74, 0x64, 0x78, 0x2d, 0x67, 0x75, 0x65, 0x73, 0x74,
	0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x63, 0x68, 0x65, 0x63, 0x6b, 0x63, 0x6f, 0x6e, 0x66,
	0x69, 0x67, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_checkconfig_proto_rawDescOnce sync.Once
	file_checkconfig_proto_rawDescData = file_checkconfig_proto_rawDesc
)

func file_checkconfig_proto_rawDescGZIP() []byte {
	file_checkconfig_proto_rawDescOnce.Do(func() {
		file_checkconfig_proto_rawDescData = protoimpl.X.CompressGZIP(file_checkconfig_proto_rawDescData)
	})
	return file_checkconfig_proto_rawDescData
}

var file_checkconfig_proto_msgTypes = make([]protoimpl.MessageInfo, 5)
var file_checkconfig_proto_goTypes = []interface{}{
	(*Policy)(nil),            // 0: checkconfig.Policy
	(*HeaderPolicy)(nil),      // 1: checkconfig.HeaderPolicy
	(*TDQuoteBodyPolicy)(nil), // 2: checkconfig.TDQuoteBodyPolicy
	(*RootOfTrust)(nil),       // 3: checkconfig.RootOfTrust
	(*Config)(nil),            // 4: checkconfig.Config
}
var file_checkconfig_proto_depIdxs = []int32{
	1, // 0: checkconfig.Policy.header_policy:type_name -> checkconfig.HeaderPolicy
	2, // 1: checkconfig.Policy.td_quote_body_policy:type_name -> checkconfig.TDQuoteBodyPolicy
	0, // 2: checkconfig.Config.policy:type_name -> checkconfig.Policy
	3, // 3: checkconfig.Config.root_of_trust:type_name -> checkconfig.RootOfTrust
	4, // [4:4] is the sub-list for method output_type
	4, // [4:4] is the sub-list for method input_type
	4, // [4:4] is the sub-list for extension type_name
	4, // [4:4] is the sub-list for extension extendee
	0, // [0:4] is the sub-list for field type_name
}

func init() { file_checkconfig_proto_init() }
func file_checkconfig_proto_init() {
	if File_checkconfig_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_checkconfig_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Policy); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_checkconfig_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*HeaderPolicy); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_checkconfig_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TDQuoteBodyPolicy); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_checkconfig_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RootOfTrust); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_checkconfig_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Config); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_checkconfig_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   5,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_checkconfig_proto_goTypes,
		DependencyIndexes: file_checkconfig_proto_depIdxs,
		MessageInfos:      file_checkconfig_proto_msgTypes,
	}.Build()
	File_checkconfig_proto = out.File
	file_checkconfig_proto_rawDesc = nil
	file_checkconfig_proto_goTypes = nil
	file_checkconfig_proto_depIdxs = nil
}
