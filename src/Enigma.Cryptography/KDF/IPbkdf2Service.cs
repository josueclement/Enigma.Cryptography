namespace Enigma.Cryptography.KDF;

/// <summary>
/// Defines the contract for PBKDF2 key derivation operations.
/// </summary>
public interface IPbkdf2Service
{
    /// <summary>
    /// Generates a cryptographic key using PBKDF2 with the specified parameters.
    /// </summary>
    /// <param name="size">The desired key size in bytes.</param>
    /// <param name="password">The password from which to derive the key.</param>
    /// <param name="salt">The salt value to use in the derivation.</param>
    /// <param name="iterations">The number of iterations to perform. Default is 600,000 (OWASP 2023 recommendation).</param>
    /// <returns>The derived key as a byte array of the requested size.</returns>
    byte[] GenerateKey(int size, string password, byte[] salt, int iterations = 600_000);
}
