namespace Enigma.Cryptography.KDF;

/// <summary>
/// Factory interface for creating PBKDF2 key derivation services.
/// </summary>
public interface IPbkdf2ServiceFactory
{
    /// <summary>
    /// Creates a PBKDF2 service instance.
    /// </summary>
    /// <returns>An implementation of <see cref="IPbkdf2Service"/>.</returns>
    IPbkdf2Service CreatePbkdf2Service();
}
