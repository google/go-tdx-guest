package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-tdx-guest/abi"
	"github.com/google/go-tdx-guest/gce"
	pb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/go-tdx-guest/testing/testdata"
)

func TestParseCommandFlagsDefaults(t *testing.T) {
	cfg, err := parseCommandFlags("gceprovenance verify", nil, io.Discard)
	if err != nil {
		t.Fatalf("parseCommandFlags() failed: %v", err)
	}
	if cfg.Bucket != defaultBucketName {
		t.Errorf("Bucket = %q, want %q", cfg.Bucket, defaultBucketName)
	}
	if got := quoteOutputPath(cfg); got != defaultQuoteOutName {
		t.Errorf("quoteOutputPath() = %q, want %q", got, defaultQuoteOutName)
	}
	if got := hostRegistryOutputPath(cfg); got != defaultHostRegistryOutName {
		t.Errorf("hostRegistryOutputPath() = %q, want %q", got, defaultHostRegistryOutName)
	}
}

func TestParseCommandFlagsOutDirDefaults(t *testing.T) {
	cfg, err := parseCommandFlags("gceprovenance verify", []string{"-out-dir", "/tmp/gceprovenance"}, io.Discard)
	if err != nil {
		t.Fatalf("parseCommandFlags() failed: %v", err)
	}
	if got, want := quoteOutputPath(cfg), filepath.Join("/tmp/gceprovenance", defaultQuoteOutName); got != want {
		t.Errorf("quoteOutputPath() = %q, want %q", got, want)
	}
	if got, want := hostRegistryOutputPath(cfg), filepath.Join("/tmp/gceprovenance", defaultHostRegistryOutName); got != want {
		t.Errorf("hostRegistryOutputPath() = %q, want %q", got, want)
	}
}

func TestRunCLIRejectsFlagsWithoutCommand(t *testing.T) {
	err := runCLI([]string{"-quote", "quote.bin"}, "", io.Discard, io.Discard)
	if err == nil {
		t.Fatal("runCLI() succeeded, want error")
	}
	if !strings.Contains(err.Error(), `use "gceprovenance verify"`) {
		t.Errorf("runCLI() error = %q, want verify guidance", err.Error())
	}
}

func TestUnsupportedFlags(t *testing.T) {
	for _, name := range []string{
		"ppid",
		"get_collateral",
		"check_crl",
		"trusted_roots",
		"timeout",
		"max_retry_delay",
		"disable_tcb_status_check",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := parseCommandFlags("gceprovenance verify", []string{"-" + name}, io.Discard)
			if err == nil {
				t.Fatal("parseCommandFlags() succeeded, want error")
			}
			if want := "flag provided but not defined: -" + name; !strings.Contains(err.Error(), want) {
				t.Errorf("parseCommandFlags() error = %q, want %q", err.Error(), want)
			}
		})
	}
}

func TestParseChallenge(t *testing.T) {
	value := strings.Repeat("ab", 64)
	challenge, reportData, err := parseChallenge(value)
	if err != nil {
		t.Fatalf("parseChallenge() failed: %v", err)
	}
	if len(challenge) != 64 {
		t.Fatalf("challenge length = %d, want 64", len(challenge))
	}
	if !bytes.Equal(challenge, reportData[:]) {
		t.Fatal("reportData did not receive challenge bytes")
	}
}

func TestParseChallengeRejectsWrongLength(t *testing.T) {
	if _, _, err := parseChallenge("abcd"); err == nil {
		t.Fatal("parseChallenge() succeeded, want error")
	}
}

func TestValidateReportDataSupportsQuoteV5(t *testing.T) {
	quote, err := abi.QuoteToProto(testdata.RawQuoteV5)
	if err != nil {
		t.Fatalf("QuoteToProto(RawQuoteV5) failed: %v", err)
	}
	quoteV5, ok := quote.(*pb.QuoteV5)
	if !ok {
		t.Fatalf("QuoteToProto(RawQuoteV5) type = %T, want *tdx.QuoteV5", quote)
	}
	challenge := quoteV5.GetTdQuoteBodyDescriptor().GetTdQuoteBodyV5().GetReportData()
	if err := validateReportData(quoteV5, challenge); err != nil {
		t.Fatalf("validateReportData() failed for QuoteV5: %v", err)
	}
}

func TestWriteQuoteOutputPreservesRawBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "quote.bin")
	raw := []byte{0, 1, 2, 3, 4}
	got, err := writeQuoteOutput(commandConfig{QuoteOut: path}, raw)
	if err != nil {
		t.Fatalf("writeQuoteOutput() failed: %v", err)
	}
	if got != path {
		t.Errorf("writeQuoteOutput() path = %q, want %q", got, path)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q) failed: %v", path, err)
	}
	if !bytes.Equal(contents, raw) {
		t.Errorf("quote output = %v, want %v", contents, raw)
	}
}

func TestReportedErrorWrapsCause(t *testing.T) {
	cause := errors.New("verification failed")
	err := &reportedError{err: cause}
	if !errors.Is(err, cause) {
		t.Fatal("reportedError does not wrap cause")
	}
}

func TestWriteVerifyFailureIsFriendly(t *testing.T) {
	var out bytes.Buffer
	info := &gce.InstanceInfo{
		Zone:          "us-central1-a",
		ProjectID:     "test-project",
		ProjectNumber: 123456789012,
		InstanceName:  "test-instance",
		InstanceID:    112233445566778899,
	}
	result := &gce.PZIDVerification{
		AttestedMROwnerHX: "0000",
		ExpectedMROwnerHX: "abcd",
		Payload:           `{"raw":"payload"}`,
	}

	writeVerifyFailure(&out, info, "abcdef1234567890abcdef1234567890", result, false)
	got := out.String()
	for _, want := range []string{
		"GCE TDX provenance verification: FAILED",
		"Name: test-instance",
		"Project: test-project (123456789012)",
		"Host registry document: found",
		"PZID binding: FAILED",
		"Quote MR_OWNER:    0000",
		"Expected MR_OWNER: abcd",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("failure output missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "payload") {
		t.Errorf("failure output included verbose payload without verbose:\n%s", got)
	}
}
