# go-configfs-tsm

This library wraps the configfs/tsm Linux subsystem for Trusted Security Module operations.

Please note that this is a temporary library added for now. NOT FOR EXTERNAL USE.

## `report` library

This library wraps the configfs/tsm/report subsystem for safely generating
attestation reports.

The TSM `report` subsystem provides a vendor-agnostic interface for collecting a
signed document for the Trusted Execution Environment's (TEE) state for remote
verification. For simplicity, we call this document an "attestation report",
though other sources may sometimes refer to it as a "quote".

Signing keys are expected to be rooted back to the manufacturer. Certificates
may be present in the `auxblob` attribute or as part of the report in `outblob`.

The core functionality of attestation report interaction is nonce in, report
out. For testability, we abstract the file operations that are needed for
creating configfs report entries, reading and writing attributes, and final
reclaiming of resources.

```golang
func Get(client configfsi.Client, req *report.Request) (*report.Response, error)
```

Where

```golang
type Request struct {
	InBlob     []byte
	Privilege  *Privilege
	GetAuxBlob bool
}


type Response struct {
	Provider string
	OutBlob  []byte
	AuxBlob  []byte
}

type Privilege struct {
	Level int
}
```

The provider may not implement an `AuxBlob` delivery mechanism, so if
`GetAuxBlob` is true, then `AuxBlob` still must be checked for length 0.

### Errors

Since this is a file-based system, there's always a chance that an operation may
fail with a permission error. By default, the TSM system requires root access.

The host may also add rate limiting to requests, such that an outblob read fails
with `EBUSY`. The kernel may or may not try again on behalf of the user.

Finally, due to the fact that the TSM report system only requests an attestation
report when reading `outblob` or `auxblob`, there is a chance the input
attributes may have been changed to unexpected values from an interfering
process. This interference is a bug in user space that the kernel does not block
for simplicity. Interference is evident through the `generation` attribute. When
`generation` does not match the expectations that the `report` package tracks,
`report.Get` returns a `*report.GenerationErr` or an error that wraps
`*report.GenerationErr`.

Use `func GetGenerationErr(error) *GenerationErr` to extract a `*GenerationErr`
from an error if it is or contains a `*GenerationErr`. If present, the caller
should try to identify the source of interference and remove it. Meanwhile, the
caller may try again.

## `configfsi.Client` interface

Most users will only want to use the client from `linuxtsm.MakeClient`.

A client on real hardware is just the filesystem, since the configfs
interactions will interact with the hardware. In unit tests though, we can
emulate the behavior that has been proposed in v7 of the patch series

```golang
type Client interface {
	MkdirTemp(dir, pattern string) (string, error)
	ReadFile(name string) ([]byte, error)
	WriteFile(name string, contents []byte) error
	RemoveAll(path string) error
}
```

The `RemoveAll` function is the only oddly named method, since the real
interface would just `rmdir` the report directory
([`os.Remove`](https://pkg.go.dev/os#Remove) in Golang), even when there are
apparent files underneath. Non-empty directory removal is generally not allowed,
so the `RemoveAll` name is clearer with what it does.

## `linuxtsm` package

The `linuxtsm` package defines an implementation of `configfsi.Client` with

```golang
func MakeClient() (configfsi.Client, error)
```

For further convenience, `linuxtsm` provides an alias for `MakeClient` combined with `report.Get` as

```golang
func GetReport(req *report.Request) (*report.Response, error)
```

The usage is the same as for `report.Get`.

## `faketsm` package

The `faketsm.Client` implementation allows tests to provide custom behavior for subsystems by name:

```golang
type Client struct {
	Subsystems map[string]configfsi.Client
}
```

The `faketsm.ReportSubsystem` type implements a client that emulates the
concurrent behavior and `generation` attribute semantics. To test negative
behavior as well, the subsystem allows the user to override `Mkdir`, `ReadFile`,
existing entries' values, and the error behavior of `WriteFile`.

## Disclaimer

This is not an officially supported Google product.
