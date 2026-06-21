# dotnet10-postquantumsigning

This repository documents an `MlDsaKey` implementation for post-quantum signing scenarios in .NET 10 using the native `System.Security.Cryptography.MLDsa` APIs.

## Summary

`MlDsaKey` is a wrapper around .NET 10's experimental ML-DSA support. It is designed to make post-quantum signing and verification easier for consumers that need:

- ML-DSA-44, ML-DSA-65, or ML-DSA-87 key support
- loading keys from PEM, DER, PKCS#8, SPKI, or X.509 certificates
- signing with exportable software keys or non-exportable CNG/HSM-backed keys
- verification with imported public keys or certificates
- placeholder signature generation for non-file signing workflows

In short, the class acts as a bridge between application code and the low-level .NET 10 post-quantum cryptography primitives.

## What the code does

### Main responsibilities

The `MlDsaKey` class is responsible for:

1. **Creating or importing ML-DSA keys**
   - from files
   - from raw public/private key bytes
   - from `X509Certificate2`
   - from `CngKey` for HSM-backed scenarios
   - by generating a fresh key pair

2. **Tracking key metadata**
   - whether the private key is available
   - which ML-DSA parameter set is in use
   - public key size, private key size, and signature size

3. **Signing and verifying**
   - signs message data with ML-DSA
   - verifies ML-DSA signatures
   - supports special placeholder-signing flows used by the surrounding signing pipeline

4. **Providing expression-friendly properties**
   - exposes values like algorithm name, key sizes, public key bytes, and security level

5. **Cleaning up sensitive material**
   - disposes cryptographic handles
   - clears private key material from memory where possible

## Key design notes

The implementation follows the native .NET 10 ML-DSA API model:

- `MLDsa` instances are created through static factory/import methods
- the algorithm is determined from imported/generated key material
- `SignData` and `VerifyData` operate directly on message bytes
- the code disables `SYSLIB5006` because ML-DSA is still experimental in .NET 10 preview

## Supported parameter sets

The implementation supports the FIPS 204 parameter sets below:

| Parameter set | Security level | Public key size | Private key size | Signature size |
| --- | --- | ---: | ---: | ---: |
| `ML_DSA_44` | NIST Level 2 | 1312 bytes | 2560 bytes | 2420 bytes |
| `ML_DSA_65` | NIST Level 3 | 1952 bytes | 4032 bytes | 3309 bytes |
| `ML_DSA_87` | NIST Level 5 | 2592 bytes | 4896 bytes | 4627 bytes |

The code also maps each parameter set to its ML-DSA object identifier (OID):

- `ML_DSA_44` → `2.16.840.1.101.3.4.3.17`
- `ML_DSA_65` → `2.16.840.1.101.3.4.3.18`
- `ML_DSA_87` → `2.16.840.1.101.3.4.3.19`

## Constructor and factory overview

### `MlDsaKey(string filePath)`
Loads a key from disk and selects the correct loader based on the file extension:

- `.pem`
- `.der`
- `.key`
- `.cer`
- `.crt`

### `MlDsaKey(byte[] keyBytes, MlDsaParameterSet parameterSet, bool isPrivate)`
Imports a raw private or public key, derives the actual algorithm from the imported material, and validates that it matches the caller-supplied parameter set.

### `MlDsaKey(CngKey cngKey, MlDsaParameterSet parameterSet)`
Wraps a non-exportable CNG key, which is useful for HSM scenarios where the private key never leaves the provider.

### `MlDsaKey(X509Certificate2 certificate)`
Builds a public-key-only instance from a certificate, using the certificate public key OID to determine which ML-DSA parameter set is present.

### `Generate(MlDsaParameterSet parameterSet)`
Creates a new software-backed ML-DSA key pair with the requested parameter set.

### `FromCertificate(string certPath)`
Convenience helper that loads a certificate file and returns an `MlDsaKey` instance.

## Signing and verification behavior

### Signing

`SignHash(byte[] hash, NodeContext context = null)` signs the provided byte array.

Important note: even though the method parameter is named `hash`, the implementation is documenting that ML-DSA signs the input bytes directly rather than assuming a pre-hashed digest.

The method has three paths:

1. **Placeholder mode**
   - used when the signing context requests placeholder output
   - creates a deterministic placeholder signature buffer
   - optionally writes a Base64 digest file to disk

2. **HSM / CNG mode**
   - used when the key is backed by a non-exportable `CngKey`
   - delegates signing to the provider through `CngHandleSigner`

3. **Normal software signing**
   - calls `mldsaAlgorithm.SignData(...)`

### Verification

`VerifySignature(byte[] hash, byte[] signature, NodeContext context = null)` verifies the signature against the provided input bytes.

- in placeholder mode, it recomputes the expected placeholder signature and compares it
- otherwise, it calls `mldsaAlgorithm.VerifyData(...)`
- invalid signature formats or cryptographic verification exceptions return `false`

## File and certificate loading

The code supports these loading patterns:

- **PEM files**
  - certificate PEMs
  - public key PEMs
  - private key PEMs
- **DER / binary files**
  - PKCS#8 private keys
  - SubjectPublicKeyInfo public keys
- **X.509 certificates**
  - public key extracted from the certificate
  - parameter set determined from the certificate OID

If the imported key material does not match a known ML-DSA algorithm name, the code throws an `MlDsaException`.

## Exposed properties

The class exposes:

- `HasPrivate`
- `ParameterSet`
- `Id`
- `PublicKeySize`
- `PrivateKeySize`
- `SignatureSize`

It also supports dynamic property access through `GetPropertyValue(...)`, including:

- `paramset`
- `publickey`
- `publickeysize`
- `privatekeysize`
- `signaturesize`
- `algorithm`
- `securitylevel`
- `spki`
- `hasprivate`

## Utility and lifecycle behavior

- `SanitizeFileName(...)` replaces invalid file-name characters with underscores for placeholder output files
- `ToString()` returns a readable key description including parameter set, security level, and whether the instance is public or private
- `Dispose()` releases the `MLDsa` instance and any `CngKey`, and clears private key bytes from memory

## Error handling

The implementation consistently throws `MlDsaException` for:

- unknown parameter sets
- invalid file formats
- unsupported certificate algorithms
- private-key-required operations attempted with a public key
- failed PEM/DER import scenarios

## Practical usage guidance

Use `MlDsaKey` when you want a single abstraction for:

- generating ML-DSA keys
- importing ML-DSA material from multiple formats
- signing in software or HSM-backed environments
- verifying signatures from public keys or certificates

This makes it a useful entry point for .NET 10 post-quantum signing integrations, especially in workflows that already use certificates, expression-based metadata, or external signing infrastructure.
