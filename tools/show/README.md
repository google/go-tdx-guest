# `show` CLI tool

This binary is a CLI tool for parsing and displaying Intel TDX quotes.

The tool's input is a quote.

The tool's output is the quote in any specified format to either standard out
or directly to a file.

## Usage

```
./show [options...]
```

### `-in`

This flag provides the path to the quote to show. Stdin is "-".

### `-inform`

The format that input takes. One of

*   `bin`: for a raw binary quote.
*   `proto`: A binary serialized `tdx.QuoteV4` message.
*   `textproto`: The `tdx.QuoteV4` message in textproto format.

Default value is `bin`.

### `-out`

Path to output file to write quote to.

Default is empty, interpreted as stdout.

### `-outform`

The format that output takes. Currently only `textproto` is supported.

Default value is `textproto`.

### `-verbosity`

Used to set the verbosity of logger, where higher number means more verbose output.

Default value is `0`.
