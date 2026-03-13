# Enigma.Cryptography v4.2.0 Release Notes

## Security Fixes

- **ThreadStatic SecureRandom in RandomUtils** — `SecureRandom` is now cached per-thread via `[ThreadStatic]`, eliminating repeated instantiation and ensuring thread safety.
- **Password bytes zeroed in Pbkdf2Service** — UTF-8 password bytes are now cleared in a `finally` block after key derivation to prevent sensitive data from lingering in memory.
- **PemPasswordFinder password clearing** — `PemPasswordFinder` now implements `IDisposable`; the internal `char[]` password is cleared on disposal. `GetPassword()` returns defensive copies.
- **Unbounded length guard in ReadLengthValue** — `ReadLengthValue` and `ReadLengthValueAsync` now accept a `maxLength` parameter (default 10 MB) and throw `InvalidOperationException` for negative or excessive lengths. This guard propagates through `ReadTagLengthValue`.
- **Argument validation on all public methods** — All public service methods now validate inputs with `ArgumentNullException` / `ArgumentException` guards, covering `BlockCipherService`, `StreamCipherService`, `HashService`, `Pbkdf2Service`, `Argon2Service`, `PublicKeyService`, `MLDsaService`, `MLKemService`, `PaddingService`, `NoPaddingService`, `Base64Service`, `HexService`, `PemUtils`, and `RandomUtils`.

## Correctness Fixes

- **Stream.Read loop for StreamExtensions** — All `ReadXxx` / `ReadXxxAsync` methods in `StreamExtensions` now use a read loop (`StreamReadHelpers.ReadExact` / `ReadExactAsync`) instead of a single `Stream.Read` call, correctly handling partial reads from network or buffered streams.
- **Explicit little-endian encoding** — Integer types (`Int16`, `Int32`, `Int64`, `UInt16`, `UInt32`, `UInt64`) now use manual little-endian byte construction for writes and reconstruction for reads, eliminating dependence on `BitConverter.IsLittleEndian`. `Bool`, `Float`, and `Double` use `BitConverter` with a conditional `Array.Reverse` for big-endian safety.
- **PemUtils leaveOpen: true** — `StreamWriter` / `StreamReader` in `SaveKey`, `SavePrivateKey`, `LoadKey`, and `LoadPrivateKey` now pass `leaveOpen: true`, preventing the underlying stream from being disposed after PEM operations.
- **PemUtils SavePrivateKey password clearing** — Password `char[]` is now captured in a local variable and cleared in a `finally` block.

## API Quality

- **KDF Service+Factory pattern** — `Pbkdf2Service` and `Argon2Service` now implement `IPbkdf2Service` / `IArgon2Service` interfaces. New factory interfaces (`IPbkdf2ServiceFactory`, `IArgon2ServiceFactory`) and implementations (`Pbkdf2ServiceFactory`, `Argon2ServiceFactory`) follow the established Service+Factory pattern.
- **Deterministic ML-DSA configuration** — `MLDsaService` now accepts a `bool deterministic` constructor parameter. `IMLDsaServiceFactory` methods (`CreateDsa44Service`, `CreateDsa65Service`, `CreateDsa87Service`) accept an optional `bool deterministic = false` parameter, allowing deterministic signing when needed.
- **CLAUDE.md documentation corrections** — Clarified that only stream-based modules (BlockCiphers, StreamCiphers, Hash) are async; byte[]-based modules (KDF, PublicKey, PQC, Padding, DataEncoding) are synchronous. Added note that `IProgress<int>` reports per-chunk byte deltas, not cumulative totals.

## Test Coverage

- **Block cipher round-trip tests for 8 additional engines** — Twofish, Serpent, Camellia, CAST5, IDEA, SEED, ARIA, SM4 in CBC mode.
- **RSA encrypt/decrypt + GenerateKeyPair tests** — Key generation, encrypt/decrypt round-trip, sign/verify round-trip with generated keypairs.
- **PQC sign + GenerateKeyPair tests** — ML-DSA sign/verify round-trip for all three security levels (44, 65, 87) plus deterministic signing test.
- **PQC encapsulate + GenerateKeyPair tests** — ML-KEM encapsulate/decapsulate round-trip for all three security levels (512, 768, 1024).
- **Base64 and Hex encoding tests** — Round-trip, known vectors, and empty input for both encoding services.
- **Argument validation tests** — `Assert.Throws<ArgumentNullException>` / `Assert.Throws<ArgumentException>` for all null guards and boundary checks across all services.
- **IProgress and CancellationToken tests** — Verifies progress callbacks during hash/encrypt and that pre-cancelled tokens throw `OperationCanceledException`.
- **PEM round-trip tests** — `SaveKey`/`LoadKey` and `SavePrivateKey`/`LoadPrivateKey` round-trips, plus stream-not-disposed regression tests for the `leaveOpen` fix.
- **Coverlet for code coverage** — Added `coverlet.collector` v6.0.4 to the test project for coverage collection.

## Version

- Bumped from `4.1.0` to `4.2.0`.
