namespace Enigma.Cryptography.KDF;

/// <summary>
/// Factory for creating Argon2 key derivation services.
/// </summary>
public class Argon2ServiceFactory : IArgon2ServiceFactory
{
    /// <inheritdoc />
    public IArgon2Service CreateArgon2Service()
        => new Argon2Service();
}
