# `check` CLI tool

This binary is a thin wrapper around the `verify` library to
check Intel TDX quotes against expectations.

The tool's input is an Intel TDX quote.

The tool's output is an error or "Success".

## Usage

```
./check [options...]
```

### `-in`

This flag provides the path to the quote to check. Stdin is "-".

### `-inform`

The format that input takes. One of

*   `bin`: for a raw binary quote.
*   `proto`: A binary serialized `tdx.QuoteV4` message.
*   `textproto`: The `tdx.QuoteV4` message in textproto format.

Default value is `bin`.

### `-quiet`

If set, doesn't write exit errors to Stdout. All results are communicated through exit code.

### `-parse_ccel`

If true, parses a Confidential Computing event log and replays the parsed event log
against the RTMR banks extracted from the verified TD quote. 
The parsed results are then saved to a **result.textproto** file in the current directory.

Default `false`.

### `-verbosity`

Used to set the verbosity of logger, where higher number means more verbose output.

Default value is `0`.

### `-check_crl`

Checks if the PCK certificate and the intermediate certificate of the PCK
certificate chain has been revoked, and errors if so. Default `false`. Requires
`-get_collateral` to be true so that CRLs are downloaded from the network.

Note: For more details about PCK CRLs refer [Intel's PCK CRL specification](https://api.trustedservices.intel.com/documents/Intel_SGX_PCK_Certificate_CRL_Spec-1.5.pdf)

### `-get_collateral`

Uses the network to download "collateral" elements:

*   CRLs (if `-check_crl`)
*   The Intel quoting enclave (QE) Identity, and
*   TCB info from Intel's PCS.

Default `false`.

## Examples

The following example checks a binary quote, downloads collaterals, checks the
quote against collaterals, and checks certificate revocations.

```shell
$ ./check -in quote.dat -inform bin -get_collateral -check_crl
```

## Exit code meaning

*   0: Success
*   1: Failure due to tool misuse
*   2: Failure due to quote parsing errors, invalid signatures, certificates or
 collateral mismatch
*   3: Failure due to an issue with the network or Intel's PCS

