# TDX Guest


This project offers libraries for a simple wrapper around quote providing tools
such as the `go-configfs-tsm` library, or the `/dev/tdx_guest` device in Linux,
as well as a library for attestation verification of fundamental components of
an attestation quote.


This project is split into two complementary roles. The first role is producing
an attestation quote, and the second is checking an attestation quote. The
`client` library produces quote, the `verify` library verifies quote's
signatures and certificates.


## `client`


This library should be used within the confidential workload to collect an
attestation quote along with requisite certificates.


Your main interactions with it will be to first get the quote provider, or
open the device, then get an attestation quote with your provided 64 bytes of
user data (typically a nonce), and then close the device. For convenience, the
attestation with its associated certificates can be collected in a
wire-transmittable protocol buffer format.


### `func GetQuoteProvider() (*LinuxConfigFsQuoteProvider, error)`


This function creates an instance of a quote provider which uses the go-configfs-tsm
library to fetch attestation quotes via ConfigFS.


### `func OpenDevice() (*LinuxDevice, error)`


This function creates a file descriptor to the `/dev/tdx_guest` device and
returns an object that has methods encapsulating commands to the device. When
done, remember to `Close()` the device.
Note:- The Device interface is deprecated, and use of quote provider interface
is recommended for fetching attestation quote.


### `func GetQuote(quoteProvider any, reportData [64]byte) (any, error)`


This function takes an object implementing either the `QuoteProvider` interface
(e.g. `LinuxConfigFsQuoteProvider`), or the `Device` interface (e.g., a `LinuxDevice`)
along with report data which typically consists of a nonce value.
It returns the protocol buffer representation of the attestation quote.


You can use `GetRawQuote` to get the TDX Quote in byte array format.


### `func (d Device) Close() error`


Closes the device.

## `verify`

This library will check the signature, certificate chain and basic
well-formedness properties of an attestation quote. The requirements for quote
well-formedness come from the [Intel TDX specification](https://cdrdv2.intel.com/v1/dl/getContent/733568),
and the requirements for certificate well-formedness come from the
[Intel PCK Certificate specification](https://api.trustedservices.intel.com/documents/Intel_SGX_PCK_Certificate_CRL_Spec-1.5.pdf).

The presence of the PCK Certificate Chain within the input attestation quote is
expected.

### `func TdxQuote(quote *pb.QuoteV4, options *Options) error`

This function verifies that the attestation has a valid signature and
certificate chain. It provides an optional verification against the collateral
obtained from the Intel PCS API and also offers an optional check against
the certificate revocation list (CRL). By default, the option to verify against
collaterals and the certificate revocation list(CRL) is disabled. The
verification using collaterals is based on [Intel PCS API specification](https://api.portal.trustedservices.intel.com/provisioning-certification)
documentation.

Example expected invocation:

```
verify.TdxQuote(myAttestation, verify.Options())
```

#### `Options` type

This type contains five fields:

*   `GetCollateral bool`: if true, then `TdxQuote` will download the collateral
    from Intel PCS API service and check against collateral obtained.
    Must be `true` if `CheckRevocations` is true.
*   `CheckRevocations bool`: if true, then `TdxQuote` will download the
    certificate revocation list (CRL) from Intel PCS API service and check for
    revocations.
*   `Getter HTTPSGetter`: if `nil`, uses `DefaultHTTPSGetter()`.
    The `HTTPSGetter` interface consists of a single method `Get(url string)
    (map[string][]string, []byte, error)` that should return the headers and body
    of the HTTPS response.
*   `Now time.Time`: if `nil`, uses `time.Now()`. It is the time at which to verify
    the validity of certificates and collaterals.
*   `TrustedRoots *x509.CertPool`: if `nil`, uses the library's embedded
    certificate.
    Certificate chain verification is performed using trusted roots.


## License


go-tdx-guest is released under the Apache 2.0 license.


```
Copyright 2023 Google LLC


Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at


http://www.apache.org/licenses/LICENSE-2.0


Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```


## Links


* [Intel TDX specification](https://cdrdv2.intel.com/v1/dl/getContent/733568)
* [Intel PCK Certificate specification](https://api.trustedservices.intel.com/documents/Intel_SGX_PCK_Certificate_CRL_Spec-1.5.pdf)
* [Intel PCS API specification](https://api.portal.trustedservices.intel.com/provisioning-certification)


## Disclaimers


This is not an officially supported Google product.