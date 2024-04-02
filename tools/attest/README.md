# `attest` CLI tool

This binary is a thin wrapper around the `client` library to gather attestation
reports in either binary or textproto formats.

The tool's input is the intended `REPORT_DATA` contents, which is 64 bytes of
user-provided data to include in the attestation report. This is typically a
nonce.

The tool's output is the report in any specified format to either standard out
or directly to a file.

*Note*: For Ubuntu images, the `tdx_guest` module was moved to linux-modules-extra
package in the 1016 and newer kernels. You should be able to install the module,
and either manually load the module or reboot.

To install the linux-modules-extra package, run:

```console
sudo apt-get install linux-modules-extra-gcp
```

To manually load the module, run:

```console
sudo modprobe tdx_guest
```

## Usage

```
./attest [options...]
```

### `-in`

This flag provides a string of 64 bytes `REPORT_DATA` content directly on the command line to include in the output attestation report.
REPORT_DATA can be either in base64 or hex format. If -inform=auto, first check with base64, hex and last with auto.

### `-inform`

The format that input takes. One of

*   `base64`: for a byte string in base64 encoding. Fewer bytes than expected
    will be zero-filled.
*   `hex`: for a byte string encoded as a hexadecimal string. Fewer bytes than
    expected will be zero-filled.
*   `auto`: first check with base64 and last with hex

Default value is `auto`.

### `-outform`

The format that output takes. This can be `bin` for Intel's specified structures
in binary or `textproto` for this module's protobuf message types in human readable text format.

Default value is `bin`.

### `-out`

Path to output file to write attestation report to.

Default is empty, interpreted as stdout.


### `verbose`

If set, then the logger can append INFO and WARNING logs to stdout as per the verbosity level. Default logger has verbosity set to `0`, so verbosity option should be set to appropriate value to append INFO and WARN logs at variable verbosity levels to stdout.

Default value is `false`.

### `verbosity`

Used to set the verbosity of logger, where higher number means more verbose output.

Default value is `0`.
