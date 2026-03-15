using System;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using System.Text;

namespace Enigma.Cryptography.KDF;

/// <summary>
/// Provides functionality for generating cryptographic keys using PBKDF2 (Password-Based Key Derivation Function 2).
/// </summary>
/// <remarks>
/// PBKDF2 is a key derivation function that is part of RSA's PKCS #5 v2.0 standard.
/// It applies a pseudorandom function (such as HMAC-SHA1) to the input password along with a salt value,
/// and repeats the process multiple times to produce a derived key, which can then be used as a cryptographic key.
///
/// This implementation uses the BouncyCastle library's PKCS5S2ParametersGenerator internally with SHA-1 as the default digest.
/// </remarks>
public class Pbkdf2Service : IPbkdf2Service
{
    /// <inheritdoc />
    public byte[] GenerateKey(int size, string password, byte[] salt, int iterations = 600_000)
    {
        if (size <= 0) throw new ArgumentException("Size must be greater than zero.", nameof(size));
        if (password is null) throw new ArgumentNullException(nameof(password));
        if (salt is null) throw new ArgumentNullException(nameof(salt));
        if (iterations <= 0) throw new ArgumentException("Iterations must be greater than zero.", nameof(iterations));

        var passwordBytes = Encoding.UTF8.GetBytes(password);

        try
        {
            var generator = new Pkcs5S2ParametersGenerator();
            generator.Init(passwordBytes, salt, iterations);

            var keyParameter = (KeyParameter)generator.GenerateDerivedParameters("AES", size * 8);
            return keyParameter.GetKey();
        }
        finally
        {
            Array.Clear(passwordBytes, 0, passwordBytes.Length);
        }
    }
}