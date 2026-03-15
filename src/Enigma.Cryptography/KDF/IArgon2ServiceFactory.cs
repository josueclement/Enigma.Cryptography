namespace Enigma.Cryptography.KDF;

/// <summary>
/// Factory interface for creating Argon2 key derivation services.
/// </summary>
public interface IArgon2ServiceFactory
{
    /// <summary>
    /// Creates an Argon2 service instance.
    /// </summary>
    /// <returns>An implementation of <see cref="IArgon2Service"/>.</returns>
    IArgon2Service CreateArgon2Service();
}
