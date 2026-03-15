# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Build
dotnet build

# Run all tests
dotnet test

# Run tests for a specific project
dotnet test src/UnitTests/UnitTests.csproj

# Run a single test class
dotnet test --filter "FullyQualifiedName~AesCbcTests"

# Pack NuGet package
dotnet pack
```

## Architecture

**Enigma.Cryptography** is a .NET cryptography library wrapping [BouncyCastle](https://www.bouncycastle.org/) with clean abstractions. It targets `netstandard2.0` and `net8.0`; tests run on `net10.0`.

### Consistent Pattern: Service + Factory

Every cryptographic feature follows this structure:

- `IXxxService` / `XxxService` — performs the operation (encrypt, decrypt, hash, sign, etc.)
- `IXxxServiceFactory` / `XxxServiceFactory` — creates service instances

For block ciphers there are additional internal factories:
- `IBlockCipherEngineFactory` — creates BouncyCastle cipher engines
- `IBlockCipherPaddingFactory` — creates padding instances
- `IBlockCipherParametersFactory` — creates cipher parameters

### Key Design Decisions

- Stream-based modules (BlockCiphers, StreamCiphers, Hash) are **async** (`Task`-based) and accept `Stream` inputs/outputs (enabling large-file processing). Byte[]-based modules (KDF, PublicKey, PQC, Padding, DataEncoding) are synchronous.
- Async stream-based modules support `IProgress<int>` for progress reporting (reports per-chunk byte deltas, not cumulative totals) and `CancellationToken` for cancellation
- Internal buffer pooling uses `ArrayPool<byte>.Shared` for memory efficiency
- All crypto delegates to **BouncyCastle.Cryptography v2.6.2**; this library is purely an abstraction layer

### Modules

| Namespace | Description |
|-----------|-------------|
| `BlockCiphers` | AES, DES, 3DES, Blowfish, Twofish, Serpent, Camellia, CAST-128, IDEA, SEED, ARIA, SM4 — CBC, ECB, SIC/CTR, GCM modes |
| `StreamCiphers` | ChaCha20 (including RFC 7539), Salsa20 |
| `Hash` | MD5, SHA-1, SHA-256, SHA-512, SHA-3 |
| `KDF` | PBKDF2, Argon2 |
| `PublicKey` | RSA encryption and signing |
| `PQC` | ML-DSA (CRYSTALS-Dilithium), ML-KEM (CRYSTALS-Kyber) |
| `Padding` | PKCS7, ISO 7816-4, X9.23 |
| `DataEncoding` | Base64, Hex |
| `Extensions` | `StreamExtensions` (read/write typed values), `EncodingExtensions` (UTF-8 helpers) |
| `Utils` | `PemUtils` (load/save PEM keys), `RandomUtils` (secure random bytes) |

### Tests

Tests use **xUnit v3** with `[Theory]` / `[MemberData]` driven by CSV test vectors. Each CSV file contains the expected input/output pairs for a given algorithm. CSV files and PEM key files are copied to the output directory at build time.

C# language version is **14** (latest); nullable reference types are enabled throughout.
