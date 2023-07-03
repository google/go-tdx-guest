// Package client (in testing) allows tests to get a fake or real tdx-guest device.
package client

import (
	"testing"

	"github.com/google/go-tdx-guest/client"
	test "github.com/google/go-tdx-guest/testing"
)

// GetTdxGuest is a testing helper function that retrieves the
// appropriate TDX-guest device from the flags passed into "go test".
//
// If using a test guest device, this will also produce a fake Device.
func GetTdxGuest(tcs []test.TestCase, tb testing.TB) client.Device {
	tb.Helper()
	if client.UseDefaultTdxGuestDevice() {
		tdxTestDevice, err := test.TcDevice(tcs)
		if err != nil {
			tb.Fatalf("failed to create test device: %v", err)
		}
		return tdxTestDevice
	}
	client, err := client.OpenDevice()
	if err != nil {
		tb.Fatalf("Failed to open TDX guest device: %v", err)
	}
	return client
}
