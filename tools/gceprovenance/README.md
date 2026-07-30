# `gceprovenance` CLI tool

`gceprovenance` verifies GCE TDX provenance by reusing the quote verification
library in this repository, then checking GCE-specific host and instance
bindings.

## Build

```bash
go build ./tools/gceprovenance
```

## Full Verification

Verify the local VM:

```bash
sudo ./gceprovenance verify
```

This:

1. Fetches a local TDX quote.
2. Verifies the quote.
3. Extracts PPID from the verified quote.
4. Fetches the host registry JSON from the configured bucket.
5. Reads GCE instance identity from the metadata server.
6. Checks the quote `MR_OWNER` against the expected PZID digest.
7. Writes `tdx_quote.bin` and `host_registry.json`.

Verify a supplied QuoteV4 or QuoteV5 against explicit GCE instance identity:

```bash
./gceprovenance verify \
  -quote /path/to/quote.bin \
  -instance projects/<project-number>/zones/<zone>/instances/<instance-id>
```

## Host Verification

```bash
sudo ./gceprovenance verify-host
```

This verifies a QuoteV4 or QuoteV5, extracts PPID, fetches the host registry
document, and writes the raw quote and host registry JSON.

## Instance Verification

```bash
sudo ./gceprovenance verify-instance
```

This verifies a QuoteV4 or QuoteV5, resolves GCE instance identity, and compares
the expected PZID digest with quote `MR_OWNER`.

Verify a supplied QuoteV4 or QuoteV5:

```bash
./gceprovenance verify-instance \
  -quote /path/to/quote.bin \
  -instance projects/<project-number>/zones/<zone>/instances/<instance-id>
```

## Challenge

`-challenge` accepts 64 bytes as 128 hex characters.

When fetching a local quote, the challenge is used as quote `REPORT_DATA`. For
both local and supplied quotes, the CLI verifies that the quote `REPORT_DATA`
matches the challenge after quote verification succeeds.

```bash
sudo ./gceprovenance verify -challenge <128-hex-character-challenge>
```

Without `-challenge`, quote verification still runs, but quote freshness is not
checked.

## Quote Verification Scope

Quote verification authenticates QuoteV4 and QuoteV5 using the Intel root
certificate embedded in this repository. It checks the quote structure, PCK
certificate chain and validity period, quote signature, QE report signature,
and the binding between the attestation key and QE report. When `-challenge` is
set, it also checks the authenticated quote `REPORT_DATA` against that value.

The command does not download Intel PCS collateral or evaluate TDX or QE TCB
status. It also does not check certificate revocation, workload measurements,
RTMRs, debug or migration attributes, or minimum SVN policy. Use `tools/check`
for customer-configurable TCB and TD evaluation policy.

## Output Files

By default, outputs are written under `-out-dir`:

```text
<out-dir>/tdx_quote.bin
<out-dir>/host_registry.json
```

Defaults:

```text
-out-dir .
-quote-out <out-dir>/tdx_quote.bin
-host-registry-out <out-dir>/host_registry.json
```

Use explicit output paths when needed:

```bash
sudo ./gceprovenance verify \
  -quote-out quote.bin \
  -host-registry-out host_registry.json
```

`-quote-out` writes the exact raw quote bytes used by the command.
`-host-registry-out` writes the exact fetched host registry JSON.

## Flags

- `-bucket`: public GCS bucket containing host registry documents. Defaults to `confidential-host-registry`.
- `-quote`: raw binary TDX QuoteV4 or QuoteV5. If unset, a local quote is fetched.
- `-instance`: GCE instance resource string in the form `projects/<project-number>/zones/<zone>/instances/<instance-id>`.
- `-MDS`: use the metadata server to collect GCE instance identity. This is the default when `-instance` is unset.
- `-challenge`: expected quote `REPORT_DATA` as 128 hex characters.
- `-out-dir`: directory for default output files.
- `-quote-out`: path for the raw quote output file.
- `-host-registry-out`: path for the host registry JSON output file.
- `-verbose`: enable verbose output.
