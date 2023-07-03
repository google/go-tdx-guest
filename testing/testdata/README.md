# `testdata`
This folder contains embedded files that serve as sample API responses,
intended for testing purposes. These responses can be used to stimulate the
behavior of Intel PCS APIs without actually making network access.


## Files

### `pckcrl`

This file serves as sample for Intel PCS API response for PCK certificate
Revocation List. This response is specifically designed to check whether a PCK
certificate is revoked or not.
This sample API follows a structure similar to
`https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=platform&encoding=der`


###  `sample_tcbInfo_response`

This file serves as sample for Intel PCS API response to retrieve TDX TCB
information for given FMSPC. This response helps in determining the status of a
TDX TCB level for a given platform needs to be done using TDX TCB information
according to the following algorithm:

1. Retrieve FMSPC value from SGX PCK Certificate assigned to a given platform.

2. Retrieve TDX TCB Info matching the FMSPC value.

3. Go over the sorted collection of TCB Levels retrieved from TCB Info starting
   from the first item on the list:

   a. Compare all of the SGX TCB Comp SVNs retrieved from the SGX PCK Certificate
      (from 01 to 16) with the corresponding values of SVNs in sgxtcbcomponents
      array of TCB Level. If all SGX TCB Comp SVNs in the certificate are greater
      or equal to the corresponding values in TCB Level, go to 3.b, otherwise move
      to the next item on TCB Levels list.

   b. Compare PCESVN value retrieved from the SGX PCK certificate with the
      corresponding value in the TCB Level. If it is greater or equal to the
      value in TCB Level, go to 3.c, otherwise move to the next item on TCB
      Levels list.

   c. Compare all of the SVNs in TEE TCB SVN array retrieved from TD Report in
      Quote (from index 0 to 15) with the corresponding values of SVNs in
      tdxtcbcomponents array of TCB Level. If all TEE TCB SVNs in the TD Report
      are greater or equal to the corresponding values in TCB Level, read status
      assigned to this TCB level. Otherwise, move to the next item on TCB Levels
      list.

4. For the selected TCB level verify that SVN at index 1 in tdxtcbcomponents
   array matches the value of SVN at index 1 in TEE TCB SVNs array (from TD Report
   in Quote). In case of a mismatch the selected TCB level should be rejected as
   TCB Info that was used for the comparison is not supported for this platform
   configuration.
   
5. If no TCB level matches the SGX PCK Certificate and TD Report, then the TCB
   level is not supported.

This sample API follows a structure similar to
`https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=50806f000000`


### `sample_qeIdentity_response`

This file serves as sample for Intel PCS API response to retrieve QE identity
response. This response helps in determining if the identity of a SGX Enclave
(represented by SGX Enclave Report) matches a valid, up-to-date Enclave Identity
issued by Intel requires following steps:

1. Retrieve Enclave Identity(TDX QE) from PCS and verify that it is a valid
   structure issued by Intel.

2. Perform the following comparison of SGX Enclave Report against the retrieved
   Enclave Identity:

  a. Verify if MRSIGNER field retrieved from SGX Enclave Report is equal to the
     value of mrsigner field in Enclave Identity.

  b. Verify if ISVPRODID field retrieved from SGX Enclave Report is equal to the
     value of isvprodid field in Enclave Identity.

  c. Apply miscselectMask (binary mask) from Enclave Identity to MISCSELECT
     field retrieved from SGX Enclave Report. Verify if the outcome
     (miscselectMask & MISCSELECT) is equal to the value of miscselect field in
     Enclave Identity.

  d. Apply attributesMask (binary mask) from Enclave Identity to ATTRIBUTES
     field retrieved from SGX Enclave Report. Verify if the outcome (attributesMask
     & ATTRIBUTES) is equal to the value of attributes field in Enclave Identity.

3. If any of the checks above fail, the identity of the enclave does not match
   Enclave Identity published by Intel.

4. Determine a TCB status of the Enclave:

  a. Retrieve a collection of TCB Levels (sorted by ISVSVNs) from tcbLevels field
     in Enclave Identity structure.

  b. Go over the list of TCB Levels (descending order) and find the one that has
     ISVSVN that is lower or equal to the ISVSVN value from SGX Enclave Report.

  c. If a TCB level is found, read its status from tcbStatus field, otherwise
     the TCB Level is not supported.

This sample API follows a structure similar to
`https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity`


### `rootcrl.der`

This file serves as sample for Intel PCS API response for Root certificate
Revocation List. This response is specifically designed to check whether a Root
certificate is revoked or not.
This sample API follows a structure similar to
`https://certificates.trustedservices.intel.com/IntelSGXRootCA.der`
