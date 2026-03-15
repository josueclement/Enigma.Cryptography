namespace Enigma.Cryptography.KDF;

/// <summary>
/// Defines the contract for Argon2 key derivation operations.
/// </summary>
public interface IArgon2Service
{
    /// <summary>
    /// Generates a cryptographic key using the Argon2 password-based key derivation function.
    /// </summary>
    /// <param name="size">The size of the derived key in bytes.</param>
    /// <param name="passwordBytes">The password bytes to derive the key from. The caller is responsible for clearing this array when no longer needed.</param>
    /// <param name="salt">The cryptographic salt to use.</param>
    /// <param name="iterations">The number of iterations (time cost). Default is 10.</param>
    /// <param name="parallelism">The degree of parallelism. Default is 4.</param>
    /// <param name="memoryPowOfTwo">The memory size as power of 2. Default is 16 (64 MiB).</param>
    /// <param name="argon2Variant">The Argon2 variant. Default is Argon2id (0x02).</param>
    /// <param name="argon2Version">The Argon2 version. Default is 1.3 (0x13).</param>
    /// <returns>The derived key as a byte array of the specified size.</returns>
    byte[] GenerateKey(
        int size,
        byte[] passwordBytes,
        byte[] salt,
        int iterations = 10,
        int parallelism = 4,
        int memoryPowOfTwo = 16,
        int argon2Variant = 0x02,
        int argon2Version = 0x13);
}
