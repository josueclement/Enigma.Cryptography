using System;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace Enigma.Cryptography.KDF;

/// <summary>
/// Service for password-based key derivation using the Argon2 algorithm family.
/// Argon2 is a memory-hard password hashing function designed to be resistant to
/// GPU, ASIC, and side-channel attacks.
/// </summary>
/// <remarks>
/// This implementation uses BouncyCastle's Argon2BytesGenerator which supports all
/// Argon2 variants (Argon2d, Argon2i, and Argon2id) configurable through parameters.
/// </remarks>
public class Argon2Service : IArgon2Service
{
    /// <inheritdoc />
    public byte[] GenerateKey(
        int size,
        byte[] passwordBytes,
        byte[] salt,
        int iterations = 10,
        int parallelism = 4,
        int memoryPowOfTwo = 16,
        int argon2Variant = 0x02,
        int argon2Version = 0x13)
    {
        if (size <= 0) throw new ArgumentException("Size must be greater than zero.", nameof(size));
        if (passwordBytes is null) throw new ArgumentNullException(nameof(passwordBytes));
        if (salt is null) throw new ArgumentNullException(nameof(salt));

        var argon2Params = new Argon2Parameters.Builder(argon2Variant)
            .WithVersion(argon2Version)
            .WithIterations(iterations)
            .WithMemoryPowOfTwo(memoryPowOfTwo)
            .WithParallelism(parallelism)
            .WithSalt(salt)
            .Build();

        var argon2Gen = new Argon2BytesGenerator();
        argon2Gen.Init(argon2Params);

        var derivedKey = new byte[size];

        argon2Gen.GenerateBytes(passwordBytes, derivedKey, 0, derivedKey.Length);

        return derivedKey;
    }
}
