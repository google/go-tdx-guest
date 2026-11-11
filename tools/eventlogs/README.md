# `eventlogs` CLI tool

This binary is a thin wrapper around the `tcg` library to parse unverified CCEL logs for debugging purpose.

The tool takes a CCEL log file as input and outputs the parsed events in textproto format to either standard output or a specified file.

*Note*: The event logs parsed by this tool are NOT replayed against the RTMR values and are therefore unverified. The output includes the digest corresponding to the provided hash algorithm. If an event does not contain a digest for that hash, the field will be empty.


## Usage

```
./eventlogs [options...]
```

### `-in`

Specifies the path to the input CCEL log file.

Default: `/sys/firmware/acpi/tables/data/CCEL`

### `-out`

Path to output file in textproto format to write parsed logs to.

Default is empty, interpreted as stdout.


### `-verbose`

If set, then the logger can append INFO and WARNING logs to stdout as per the verbosity level. Default logger has verbosity set to `0`, so verbosity option should be set to appropriate value to append INFO and WARN logs at variable verbosity levels to stdout.

Default value is `false`.

### `-verbosity`

Used to set the verbosity of logger, where higher number means more verbose output.

Default value is `0`.


## Examples

The following example parses a specific CCEL file, and output to a new file.

```shell
$ ./eventlogs -in ccel.dat -out parsed_logs.textproto
```