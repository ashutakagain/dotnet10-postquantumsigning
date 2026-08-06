# PostQuantum.MlDsa

[![NuGet](https://img.shields.io/nuget/v/PostQuantum.MlDsa.svg)](https://www.nuget.org/packages/PostQuantum.MlDsa/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A small, dependency-free helper library for **ML-DSA** (Module-Lattice-Based Digital Signature
Algorithm, **NIST FIPS 204**) post-quantum signatures on **.NET 10**.

Classical RSA and ECC signatures will eventually fall to quantum computers. ML-DSA is NIST's
lattice-based, quantum-resistant replacement. This library wraps the native .NET 10
`System.Security.Cryptography.MLDsa` APIs behind a friendly, hard-to-misuse surface and adds a
path for **hardware (HSM) keys**.

## Features

- ✅ All three FIPS-204 parameter sets: **ML-DSA-44 / 65 / 87**
- 🔑 Key generation, and loading from **PEM**, **DER/PKCS#8**, and **X.509 certificates**
- ✍️ **Sign / verify** with a single API over two back-ends:
  - **Software** keys via managed `System.Security.Cryptography.MLDsa`
  - **Hardware** keys via CNG / NCrypt (non-exportable HSM keys - the private key never leaves the device; Windows only)
- 📏 Built-in FIPS-204 size and OID metadata (public/private/signature sizes, security level)
- 🧯 Rich `MlDsaException` with structured error codes and log-friendly messages
- 🧹 Implements `IDisposable` and zeroes private key material on dispose

## Install

```bash
dotnet add package PostQuantum.MlDsa
```

> **Requires .NET 10 or later.** ML-DSA ships as an experimental API in .NET 10; the library
> already opts in, so you do not need to suppress `SYSLIB5006` yourself.

## Quick start

### Generate a key, sign, and verify

```csharp
using PostQuantum.MlDsa;

using var key = MlDsaKey.Generate(MlDsaParameterSet.ML_DSA_87);

byte[] message = System.Text.Encoding.UTF8.GetBytes("hello post-quantum world");

byte[] signature = key.SignHash(message);
bool ok = key.VerifySignature(message, signature);

Console.WriteLine($"{key.AlgorithmName} | sig = {signature.Length} bytes | valid = {ok}");
// ML-DSA-87 | sig = 4627 bytes | valid = True
```

### Load a public key from a certificate and verify

```csharp
using var pub = MlDsaKey.FromCertificate("signer-mldsa87.cer");
bool ok = pub.VerifySignature(message, signature);
```

### Sign with a non-exportable hardware (HSM) key  — Windows only

```csharp
using System.Security.Cryptography;

// Open the key in your HSM's Key Storage Provider.
var cngKey = CngKey.Open("my-hsm-key-container",
    new CngProvider("Your HSM Key Storage Provider"));

using var hsmKey = new MlDsaKey(cngKey, MlDsaParameterSet.ML_DSA_87);
byte[] signature = hsmKey.SignHash(message); // signed inside the HSM via NCryptSignHash
```

## FIPS-204 parameter sets

| Parameter set | Security level | Public key | Private key | Signature |
|---|---|---|---|---|
| ML-DSA-44 | NIST Level 2 | 1312 B | 2560 B | 2420 B |
| ML-DSA-65 | NIST Level 3 | 1952 B | 4032 B | 3309 B |
| ML-DSA-87 | NIST Level 5 | 2592 B | 4896 B | 4627 B |

OIDs: ML-DSA-44 `2.16.840.1.101.3.4.3.17`, ML-DSA-65 `...18`, ML-DSA-87 `...19`.

## API surface

`MlDsaKey`
- Constructors: `(string filePath)`, `(byte[] keyBytes, MlDsaParameterSet, bool isPrivate)`, `(CngKey, MlDsaParameterSet)` *(Windows)*, `(X509Certificate2)`
- Static: `Generate(parameterSet)`, `FromCertificate(path)`, `IsMlDsaCertificate(cert)`, `GetAlgorithmOid(parameterSet)`
- Instance: `SignHash(data)`, `VerifySignature(data, signature)`, `ExportPublicKey()`, `ExportSubjectPublicKeyInfo()`, `ExportPkcs8PrivateKey()`
- Properties: `ParameterSet`, `HasPrivate`, `Id`, `PublicKeySize`, `PrivateKeySize`, `SignatureSize`, `SecurityLevel`, `AlgorithmName`, `AlgorithmOid`

`MlDsaException` / `MlDsaErrorCode` — structured, log-friendly error reporting.

`MlDsaParameterSet` — `ML_DSA_44`, `ML_DSA_65`, `ML_DSA_87`.

## Notes & caveats

- **Experimental base API.** ML-DSA is experimental in .NET 10 (`SYSLIB5006`) and its surface may change in later releases.
- **HSM signing is Windows-only** (uses `ncrypt.dll`). Software sign/verify is cross-platform.
- ML-DSA signs the **message directly** - there is no separate external pre-hash step.
- Not a security audit: review and test against your own threat model before production use.

## License

[MIT](LICENSE)

## Package metadata

The NuGet package includes repository provenance, SourceLink information, XML API
documentation, symbol packages, release notes, licensing, compatibility, and discovery
tags. See [PACKAGE_METADATA.md](PACKAGE_METADATA.md) for the complete metadata reference
and publishing details.
