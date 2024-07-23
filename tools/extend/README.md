# `check` CLI tool

This binary is a thin wrapper around the `rtmr` library to
extend the measurement into RTMR registers.

The tool's input is the event log.

The tool's output is an error or "Success".

## Usage

```
./extend [options...]
```

### `-in`

This flag provides the path to the event log to measure. Stdin is "-".

### `quiet`

If set, doesn't write exit errors to Stdout. All results are communicated through exit code.

### `verbosity`

Used to set the verbosity of logger, where higher number means more verbose output.

Default value is `0`.

## Examples

The following example measures an eventlog and extends it measurement into the RTMR2
register.

```shell
$ ./extend -in log.in -rtmr 2
```

## Exit code meaning

*   0: Success
*   1: Failure due to tool misuse
