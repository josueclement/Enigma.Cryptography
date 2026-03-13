namespace Enigma.Cryptography.KDF;

/// <summary>
/// Factory for creating PBKDF2 key derivation services.
/// </summary>
public class Pbkdf2ServiceFactory : IPbkdf2ServiceFactory
{
    /// <inheritdoc />
    public IPbkdf2Service CreatePbkdf2Service()
        => new Pbkdf2Service();
}
