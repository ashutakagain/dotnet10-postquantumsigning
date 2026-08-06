# NuGet package metadata

This document describes the metadata shipped with `PostQuantum.MlDsa` and how each
field is used by NuGet.org, development tools, and package consumers.

## Package identity

| Field | Value | Purpose |
|---|---|---|
| Package ID | `PostQuantum.MlDsa` | Permanent, case-insensitive identifier used by NuGet clients. |
| Version | `1.0.0` | Initial stable release using semantic versioning. |
| Title | ML-DSA (FIPS 204) Post-Quantum Digital Signatures for .NET | Human-readable title displayed by NuGet clients. |
| Authors | `PostQuantum.MlDsa Contributors` | Neutral contributor identity displayed on NuGet.org. |
| Product | `PostQuantum.MlDsa` | Product name embedded in the built assembly. |

The package ID and version form the immutable release identity
`PostQuantum.MlDsa/1.0.0`. NuGet.org does not allow an existing version to be
overwritten. Every subsequent release must use a new semantic version.

## Description and discovery

The package description identifies the library as a dependency-free .NET 10 wrapper
for the NIST FIPS 204 ML-DSA algorithm. It documents support for ML-DSA-44,
ML-DSA-65, and ML-DSA-87, including software keys and Windows CNG/NCrypt HSM keys.

Search tags cover the standardized and commonly used terminology:

`ml-dsa`, `mldsa`, `post-quantum`, `pqc`, `fips204`, `cryptography`,
`digital-signature`, `dilithium`, `security`, and `dotnet`.

The package README is displayed directly on NuGet.org and provides installation,
usage, compatibility, API, and security guidance.

## Licensing and ownership

| Field | Value |
|---|---|
| License expression | `MIT` |
| License acceptance required | `false` |
| Copyright | `Copyright (c) 2026 PostQuantum.MlDsa contributors` |

The SPDX license expression links NuGet consumers to the standard MIT license text.
The repository also contains the complete `LICENSE` file.

## Repository and provenance

| Field | Value |
|---|---|
| Project URL | `https://github.com/ashutakagain/dotnet10-postquantumsigning` |
| Repository URL | `https://github.com/ashutakagain/dotnet10-postquantumsigning` |
| Repository type | `git` |

The package records the exact source commit used during packing. SourceLink maps
compiled source paths to that GitHub commit, allowing supported debuggers to retrieve
the matching source while stepping through the library.

`PublishRepositoryUrl`, `EmbedUntrackedSources`, and
`ContinuousIntegrationBuild` provide deterministic source provenance for local and
GitHub Actions builds.

## Framework compatibility

The package targets `net10.0` and therefore requires .NET 10 or later. ML-DSA is an
experimental .NET 10 cryptography API. The package opts into that API internally, so
consuming projects do not need to suppress `SYSLIB5006`.

The managed ML-DSA operations are cross-platform. The CNG/NCrypt HSM path is available
only on Windows.

## Documentation and debugging assets

The main package contains:

- `PostQuantum.MlDsa.dll`
- XML API documentation used by IDE IntelliSense
- `README.md`
- this metadata reference

Packing also creates `PostQuantum.MlDsa.1.0.0.snupkg`, which contains portable PDB
symbols and SourceLink data for NuGet.org's symbol server.

## Release notes

Version 1.0.0 is the initial release. It includes:

- ML-DSA-44, ML-DSA-65, and ML-DSA-87 key generation
- message signing and signature verification
- PEM, DER/PKCS#8, and X.509 certificate loading
- public and private key import/export
- Windows CNG/NCrypt support for non-exportable HSM keys
- structured ML-DSA error reporting

## Publication

The Release build creates the primary package and its matching symbol package:

```powershell
dotnet pack src\PostQuantum.MlDsa\PostQuantum.MlDsa.csproj `
  -c Release `
  -o artifacts
```

Publish the primary package to NuGet.org with an API key scoped to push new versions
of `PostQuantum.MlDsa`:

```powershell
dotnet nuget push artifacts\PostQuantum.MlDsa.1.0.0.nupkg `
  --api-key <NUGET_API_KEY> `
  --source https://api.nuget.org/v3/index.json `
  --skip-duplicate
```

NuGet.org discovers and uploads the adjacent `.snupkg` symbol package automatically.

Before each release:

1. Update the package version and release notes in the project file.
2. Build and pack the Release configuration.
3. Inspect the generated package metadata and contents.
4. Push the package to NuGet.org and confirm package validation completes.

NuGet.org package versions are immutable. If a release needs correction after it is
published, increment the patch version rather than rebuilding version `1.0.0`.
