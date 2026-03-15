# Enigma.Cryptography

A comprehensive .NET cryptography library built on top of [BouncyCastle.Cryptography](https://github.com/bcgit/bc-csharp), providing a clean and easy-to-use API for common cryptographic operations.

- [Bouncy Castle GitHub repository](https://github.com/bcgit/bc-csharp)
- [Bouncy Castle Official website](https://www.bouncycastle.org/download/bouncy-castle-c/)

## Features

- **Block Ciphers** — AES, DES, 3DES, Blowfish, Twofish, Serpent, Camellia, and more (CBC, ECB, GCM, SIC/CTR modes)
- **Stream Ciphers** — ChaCha20, ChaCha20-RFC7539, Salsa20
- **Public-Key Cryptography** — RSA encryption, signing, and PEM key management
- **Post-Quantum Cryptography** — ML-DSA (CRYSTALS-Dilithium) and ML-KEM (CRYSTALS-Kyber)
- **Hashing** — MD5, SHA-1, SHA-256, SHA-512, SHA-3
- **Key Derivation** — PBKDF2 and Argon2
- **Padding** — PKCS7, ISO 7816-4, X9.23
- **Data Encoding** — Base64 and hexadecimal encoding/decoding

## Async, progress reporting & cancellation

Stream-based modules (Block Ciphers, Stream Ciphers, Hashing) are fully async and accept optional `IProgress<int>` and `CancellationToken` parameters for progress reporting and cooperative cancellation:

```csharp
var cts = new CancellationTokenSource();
var progress = new Progress<int>(bytesProcessed =>
    Console.WriteLine($"Processed {bytesProcessed} bytes"));

await service.EncryptAsync(input, output, parameters, progress, cts.Token);
```

Progress reports per-chunk byte deltas (not cumulative totals), making it straightforward to build progress bars for large-file processing.

## Installation

```shell
dotnet add package Enigma.Cryptography
```

---

## Block ciphers

### Supported algorithms

| Cipher Name      | Block Size (bits) | Supported Key Size(s) (bits) | Notes                                                                     |
|------------------|-------------------|------------------------------|---------------------------------------------------------------------------|
| AES              | 128               | 128, 192, 256                | Current global standard. Recommended for new applications.                |
| DES              | 64                | 56 (effective)               | Insecure. Broken due to small key size. Do not use.                       |
| 3DES (TripleDES) | 64                | 112, 168 (effective)         | Slow, small block size. Largely superseded by AES. Use with caution.      |
| Blowfish         | 64                | 32 - 448 (variable)          | Older cipher, 64-bit block size can be problematic (Sweet32).             |
| Twofish          | 128               | 128, 192, 256                | AES finalist. Strong, but less widely adopted than AES.                   |
| Serpent          | 128               | 128, 192, 256                | AES finalist. Known for conservative security margin, slower in software. |
| Camellia         | 128               | 128, 192, 256                | ISO/NESSIE/CRYPTREC standard. Similar performance/security to AES.        |
| CAST-128 (CAST5) | 64                | 40 - 128 (variable)          | Used in older PGP/GPG. 64-bit block size limitation.                      |
| IDEA             | 64                | 128                          | Used in older PGP. Patented until ~2012. 64-bit block size limit.         |
| SEED             | 128               | 128                          | South Korean standard.                                                    |
| ARIA             | 128               | 128, 192, 256                | South Korean standard, successor to SEED.                                 |
| SM4              | 128               | 128                          | Chinese national standard.                                                |

### Classes

- `BlockCipherService` — Service for encryption/decryption with block ciphers
- `BlockCipherServiceFactory` — `IBlockCipherService` factory
- `BlockCipherEngineFactory` — `IBlockCipher` factory
- `BlockCipherPaddingFactory` — `IBlockCipherPadding` factory
- `BlockCipherParametersFactory` — `ICipherParameters` factory

### Usage

Create a block cipher service with an algorithm string:

```csharp
var service = new BlockCipherService("AES/CBC/PKCS7Padding");
// or without padding:
var service = new BlockCipherService("AES/CBC/NoPadding");
```

Create a block cipher service with factories:

```csharp
var engineFactory = new BlockCipherEngineFactory();
var paddingFactory = new BlockCipherPaddingFactory();

// With padding
var service = new BlockCipherServiceFactory().CreateCbcService(engineFactory.CreateAesEngine, paddingFactory.CreatePkcs7Padding);

// Without padding
var service = new BlockCipherServiceFactory().CreateCbcService(engineFactory.CreateAesEngine);
```

### AES-256 GCM example

```csharp
var service = new BlockCipherService("AES/GCM");

var key = RandomUtils.GenerateRandomBytes(32);
var nonce = RandomUtils.GenerateRandomBytes(12);
var parameters = new BlockCipherParametersFactory().CreateGcmParameters(key, nonce, "associated data".GetUtf8Bytes());

var data = "This is a secret message !".GetUtf8Bytes();

// Encrypt
using var inputEnc = new MemoryStream(data);
using var outputEnc = new MemoryStream();
await service.EncryptAsync(inputEnc, outputEnc, parameters);

var encrypted = outputEnc.ToArray();

// Decrypt
using var inputDec = new MemoryStream(encrypted);
using var outputDec = new MemoryStream();
await service.DecryptAsync(inputDec, outputDec, parameters);

var decrypted = outputDec.ToArray();
```

### AES-256 CBC example

```csharp
var service = new BlockCipherService("AES/CBC/PKCS7Padding");

var key = RandomUtils.GenerateRandomBytes(32);
var iv = RandomUtils.GenerateRandomBytes(16);
var parameters = new BlockCipherParametersFactory().CreateCbcParameters(key, iv);

var data = "This is a secret message !".GetUtf8Bytes();

// Encrypt
using var inputEnc = new MemoryStream(data);
using var outputEnc = new MemoryStream();
await service.EncryptAsync(inputEnc, outputEnc, parameters);

var encrypted = outputEnc.ToArray();

// Decrypt
using var inputDec = new MemoryStream(encrypted);
using var outputDec = new MemoryStream();
await service.DecryptAsync(inputDec, outputDec, parameters);

var decrypted = outputDec.ToArray();
```

---

## Stream ciphers

### Supported algorithms

| Cipher Name       | Key Size (bits) | Nonce Size (bits) | Notes                                           |
|-------------------|-----------------|-------------------|-------------------------------------------------|
| ChaCha20          | 256             | 64                | High-performance software cipher.               |
| ChaCha20-RFC7539  | 256             | 96                | IETF variant of ChaCha20 (RFC 7539 / RFC 8439). |
| Salsa20           | 128, 256        | 64                | Predecessor to ChaCha20.                        |

### Classes

- `StreamCipherService` — Service for encryption/decryption with stream ciphers
- `StreamCipherServiceFactory` — `IStreamCipherService` factory

### ChaCha20-RFC7539 example

```csharp
var service = new StreamCipherServiceFactory().CreateChaCha7539Service();

var key = RandomUtils.GenerateRandomBytes(32);
var nonce = RandomUtils.GenerateRandomBytes(12);

var data = "This is a secret message !".GetUtf8Bytes();

// Encrypt
using var inputEnc = new MemoryStream(data);
using var outputEnc = new MemoryStream();
await service.EncryptAsync(inputEnc, outputEnc, key, nonce);

var encrypted = outputEnc.ToArray();

// Decrypt
using var inputDec = new MemoryStream(encrypted);
using var outputDec = new MemoryStream();
await service.DecryptAsync(inputDec, outputDec, key, nonce);

var decrypted = outputDec.ToArray();
```

---

## Public-key cryptography

### Classes

- `PublicKeyService` — Service for public-key encryption/decryption and signing/verifying
- `PublicKeyServiceFactory` — `IPublicKeyService` factory

### RSA example

```csharp
var service = new PublicKeyServiceFactory().CreateRsaService();

// Generate a 4096-bit key pair
var keyPair = service.GenerateKeyPair(4096);

var data = "This is a secret message".GetUtf8Bytes();

// Encrypt/decrypt
var enc = service.Encrypt(data, keyPair.Public);
var dec = service.Decrypt(enc, keyPair.Private);

// Sign/verify
var signature = service.Sign(data, keyPair.Private);
var verified = service.Verify(data, signature, keyPair.Public);

// Save public key in PEM format
using var publicOutput = new MemoryStream();
PemUtils.SaveKey(keyPair.Public, publicOutput);

// Save and encrypt private key in PEM format
using var privateOutput = new MemoryStream();
PemUtils.SavePrivateKey(keyPair.Private, privateOutput, "yourpassword", algorithm: "AES-256-CBC");

// Load public key from PEM
using var publicInput = new MemoryStream(publicOutput.ToArray());
var publicKey = PemUtils.LoadKey(publicInput);

// Load and decrypt private key from PEM
using var privateInput = new MemoryStream(privateOutput.ToArray());
var privateKey = PemUtils.LoadPrivateKey(privateInput, "yourpassword");
```

---

## Post-Quantum Cryptography (PQC)

### Classes

- `MLDsaService` — Module-Lattice-Based digital signature algorithm (ML-DSA / CRYSTALS-Dilithium)
- `MLDsaServiceFactory` — `IMLDsaService` factory
- `MLKemService` — Module-Lattice-Based key-encapsulation mechanism (ML-KEM / CRYSTALS-Kyber)
- `MLKemServiceFactory` — `IMLKemService` factory

### ML-DSA example

```csharp
var service = new MLDsaServiceFactory().CreateDsa65Service(); // deterministic: false (default)

var keyPair = service.GenerateKeyPair();

var data = "Data to sign".GetUtf8Bytes();

// Sign/verify
var signature = service.Sign(data, keyPair.Private);
var verified = service.Verify(data, signature, keyPair.Public);

// Save public key in PEM format
using var publicOutput = new MemoryStream();
PemUtils.SaveKey(keyPair.Public, publicOutput);

// Save and encrypt private key in PEM format
using var privateOutput = new MemoryStream();
PemUtils.SavePrivateKey(keyPair.Private, privateOutput, "yourpassword", algorithm: "AES-256-CBC");

// Load public key from PEM
using var publicInput = new MemoryStream(publicOutput.ToArray());
var publicKey = PemUtils.LoadKey(publicInput);

// Load and decrypt private key from PEM
using var privateInput = new MemoryStream(privateOutput.ToArray());
var privateKey = PemUtils.LoadPrivateKey(privateInput, "yourpassword");
```

### ML-KEM example

```csharp
var service = new MLKemServiceFactory().CreateKem1024();

var keyPair = service.GenerateKeyPair();

// Encapsulate a shared secret
var (encapsulation, secret) = service.Encapsulate(keyPair.Public);

// Decapsulate the shared secret
var secretDec = service.Decapsulate(encapsulation, keyPair.Private);

// Save public key in PEM format
using var publicOutput = new MemoryStream();
PemUtils.SaveKey(keyPair.Public, publicOutput);

// Save and encrypt private key in PEM format
using var privateOutput = new MemoryStream();
PemUtils.SavePrivateKey(keyPair.Private, privateOutput, "yourpassword", algorithm: "AES-256-CBC");

// Load public key from PEM
using var publicInput = new MemoryStream(publicOutput.ToArray());
var publicKey = PemUtils.LoadKey(publicInput);

// Load and decrypt private key from PEM
using var privateInput = new MemoryStream(privateOutput.ToArray());
var privateKey = PemUtils.LoadPrivateKey(privateInput, "yourpassword");
```

---

## Hashing

### Supported algorithms

| Algorithm | Output Size (bits) | Notes                                         |
|-----------|--------------------|-----------------------------------------------|
| MD5       | 128                | Broken. For checksums only, not security use. |
| SHA-1     | 160                | Deprecated for security use.                  |
| SHA-256   | 256                | Widely used. Recommended for most use cases.  |
| SHA-512   | 512                | Stronger variant of SHA-2.                    |
| SHA-3     | 224, 256, 384, 512 | Latest NIST standard. Keccak-based.           |

### Classes

- `HashService` — Hash service
- `HashServiceFactory` — `IHashService` factory

### Usage

```csharp
var data = "Data to hash".GetUtf8Bytes();

var service = new HashServiceFactory().CreateSha3Service();

using var input = new MemoryStream(data);
var hash = await service.HashAsync(input);
```

---

## Key Derivation (KDF)

### Classes

- `Pbkdf2Service` — PBKDF2 key derivation service
- `Pbkdf2ServiceFactory` — `IPbkdf2Service` factory
- `Argon2Service` — Argon2 password-based key derivation service
- `Argon2ServiceFactory` — `IArgon2Service` factory

### PBKDF2 example

```csharp
var service = new Pbkdf2Service();

var salt = "5775ada0513d7d7d7316de8d72d1f4d2".FromHexString();

// Derive a 32-byte key from a password and salt
var key = service.GenerateKey(size: 32, password: "yourpassword", salt);
```

### Argon2 example

```csharp
var service = new Argon2Service();

var passwordData = "yourpassword".GetUtf8Bytes();
var salt = RandomUtils.GenerateRandomBytes(16);

// Derive a 32-byte key from a password and salt
var key = service.GenerateKey(32, passwordData, salt);
```

---

## Padding

### Supported schemes

| Scheme      | Standard          | Notes                                    |
|-------------|-------------------|------------------------------------------|
| PKCS7       | RFC 5652          | Most widely used padding scheme.         |
| ISO 7816-4  | ISO/IEC 7816-4    | Used in smart card applications.         |
| X9.23       | ANSI X9.23        | Also known as PKCS#5 zero-byte padding.  |

### Classes

- `NoPaddingService` — No-op padding service
- `PaddingService` — Padding service
- `PaddingServiceFactory` — `IPaddingService` factory

### Usage

```csharp
var data = "Data to pad".GetUtf8Bytes();

var service = new PaddingServiceFactory().CreatePkcs7Service();

// Pad/unpad with a 16-byte block size
var padded = service.Pad(data, blockSize: 16);
var unpadded = service.Unpad(padded, blockSize: 16);
```

---

## Data encoding

### Classes

- `Base64Service` — Base64 encoding/decoding service
- `HexService` — Hexadecimal encoding/decoding service

### Usage

```csharp
var data = "This is some data".GetUtf8Bytes();

// Hex encoding
var hex = new HexService();
var hexEncoded = hex.Encode(data);
var hexDecoded = hex.Decode(hexEncoded);

// Base64 encoding
var base64 = new Base64Service();
var base64Encoded = base64.Encode(data);
var base64Decoded = base64.Decode(base64Encoded);
```

With extension methods:

```csharp
var data = "This is some data".GetUtf8Bytes();

var hexEncoded = data.ToHexString();
var hexDecoded = hexEncoded.FromHexString();

var base64Encoded = data.ToBase64String();
var base64Decoded = base64Encoded.FromBase64String();
```

---

Copyright (c) 2026 Josué Clément
